from __future__ import annotations

import math
import struct
from dataclasses import dataclass

import numpy as np

DTMF_FREQUENCIES = {
    "1": (697, 1209),
    "2": (697, 1336),
    "3": (697, 1477),
    "A": (697, 1633),
    "4": (770, 1209),
    "5": (770, 1336),
    "6": (770, 1477),
    "B": (770, 1633),
    "7": (852, 1209),
    "8": (852, 1336),
    "9": (852, 1477),
    "C": (852, 1633),
    "*": (941, 1209),
    "0": (941, 1336),
    "#": (941, 1477),
    "D": (941, 1633),
}

ROW_FREQS = [697, 770, 852, 941]
COL_FREQS = [1209, 1336, 1477, 1633]


@dataclass
class DtmfResult:
    digit: str
    start_time: float
    end_time: float
    confidence: float


def _parse_wav_header(data: bytes) -> tuple[bytes, int, int, int]:
    if len(data) < 44 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        raise ValueError("Not a valid WAV file")

    fmt_pos = data.find(b"fmt ")
    if fmt_pos < 0:
        raise ValueError("No fmt chunk")

    num_channels = struct.unpack_from("<H", data, fmt_pos + 10)[0]
    sample_rate = struct.unpack_from("<I", data, fmt_pos + 12)[0]
    bits_per_sample = struct.unpack_from("<H", data, fmt_pos + 22)[0]

    data_pos = data.find(b"data")
    if data_pos < 0:
        raise ValueError("No data chunk")

    data_size = struct.unpack_from("<I", data, data_pos + 4)[0]
    audio_start = data_pos + 8
    sample_data = data[audio_start:audio_start + data_size]

    return sample_data, sample_rate, num_channels, bits_per_sample


def _goertzel_magnitude(samples: np.ndarray, target_freq: float, sample_rate: int) -> float:
    n = len(samples)
    k = int(0.5 + n * target_freq / sample_rate)
    w = 2.0 * math.pi * k / n
    coeff = 2.0 * math.cos(w)

    s0 = 0.0
    s1 = 0.0
    s2 = 0.0
    for sample in samples:
        s0 = sample + coeff * s1 - s2
        s2 = s1
        s1 = s0

    magnitude = math.sqrt(s1 * s1 + s2 * s2 - coeff * s1 * s2)
    return magnitude / n if n > 0 else 0.0


def _detect_dtmf_in_frame(frame: np.ndarray, sample_rate: int) -> tuple[str | None, float]:
    row_mags = [(freq, _goertzel_magnitude(frame, freq, sample_rate)) for freq in ROW_FREQS]
    col_mags = [(freq, _goertzel_magnitude(frame, freq, sample_rate)) for freq in COL_FREQS]

    best_row = max(row_mags, key=lambda x: x[1])
    best_col = max(col_mags, key=lambda x: x[1])

    row_total = sum(m for _, m in row_mags)
    col_total = sum(m for _, m in col_mags)

    if row_total == 0 or col_total == 0:
        return None, 0.0

    row_ratio = best_row[1] / row_total
    col_ratio = best_col[1] / col_total

    confidence = (row_ratio + col_ratio) / 2.0

    if confidence < 0.4:
        return None, 0.0

    for digit, (rf, cf) in DTMF_FREQUENCIES.items():
        if rf == best_row[0] and cf == best_col[0]:
            return digit, confidence

    return None, 0.0


def detect_dtmf(data: bytes) -> list[DtmfResult]:
    try:
        sample_data, sample_rate, num_channels, bits_per_sample = _parse_wav_header(data)
    except Exception:
        return []

    if bits_per_sample == 16:
        fmt = "<h"
        max_val = 32768.0
    elif bits_per_sample == 8:
        fmt = "<B"
        max_val = 128.0
    else:
        return []

    bytes_per_sample = bits_per_sample // 8
    if bytes_per_sample == 0:
        bytes_per_sample = 1

    bytes_per_frame = bytes_per_sample * num_channels
    if bytes_per_frame == 0:
        return []

    num_frames = len(sample_data) // bytes_per_frame
    mono_samples = []

    for i in range(num_frames):
        frame_start = i * bytes_per_frame
        total = 0.0
        for ch in range(num_channels):
            offset = frame_start + ch * bytes_per_sample
            if offset + bytes_per_sample <= len(sample_data):
                val = struct.unpack_from(fmt, sample_data, offset)[0]
                if bits_per_sample == 8:
                    val = val - 128
                total += val
        mono_samples.append(total / num_channels)

    if not mono_samples:
        return []

    samples = np.array(mono_samples, dtype=np.float64)
    if max_val > 0:
        samples = samples / max_val

    frame_size = int(sample_rate * 0.04)
    hop_size = int(sample_rate * 0.02)

    if frame_size > len(samples):
        return []

    results: list[DtmfResult] = []
    active_digit: str | None = None
    active_start = 0.0

    for start in range(0, len(samples) - frame_size, hop_size):
        frame = samples[start:start + frame_size]
        time_s = start / sample_rate

        digit, confidence = _detect_dtmf_in_frame(frame, sample_rate)

        if digit and confidence > 0.4:
            if active_digit == digit:
                continue
            elif active_digit is not None:
                results.append(DtmfResult(
                    digit=active_digit,
                    start_time=active_start,
                    end_time=time_s,
                    confidence=confidence,
                ))
                active_digit = digit
                active_start = time_s
            else:
                active_digit = digit
                active_start = time_s
        else:
            if active_digit is not None:
                results.append(DtmfResult(
                    digit=active_digit,
                    start_time=active_start,
                    end_time=time_s,
                    confidence=confidence,
                ))
                active_digit = None

    if active_digit is not None:
        end_time = len(samples) / sample_rate
        results.append(DtmfResult(
            digit=active_digit,
            start_time=active_start,
            end_time=end_time,
            confidence=0.0,
        ))

    return results


def dtmf_to_string(results: list[DtmfResult]) -> str:
    return "".join(r.digit for r in results)
