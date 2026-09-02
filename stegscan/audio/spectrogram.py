from __future__ import annotations

import os
import struct
import tempfile
from typing import Any

from stegscan.flagfinder.detector import Detector


def _parse_wav_samples(data: bytes) -> tuple[bytes, int, int, int]:
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


def generate_spectrogram(data: bytes, output_path: str | None = None) -> str | None:
    try:
        import numpy as np
    except ImportError:
        return None

    try:
        sample_data, sample_rate, num_channels, bits_per_sample = _parse_wav_samples(data)
    except Exception:
        return None

    if bits_per_sample == 16:
        fmt = "<h"
        max_val = 32768.0
    elif bits_per_sample == 8:
        fmt = "<B"
        max_val = 128.0
        sample_data = bytes(b - 128 for b in sample_data)
    else:
        fmt = "<h"
        max_val = 32768.0

    bytes_per_sample = bits_per_sample // 8
    if bytes_per_sample == 0:
        bytes_per_sample = 1

    bytes_per_frame = bytes_per_sample * num_channels
    if bytes_per_frame == 0:
        return None

    num_samples = len(sample_data) // bytes_per_frame
    if num_channels > 1:
        mono_samples = []
        for i in range(num_samples):
            frame_start = i * bytes_per_frame
            total = 0
            for ch in range(num_channels):
                offset = frame_start + ch * bytes_per_sample
                if offset + bytes_per_sample <= len(sample_data):
                    val = struct.unpack_from(fmt, sample_data, offset)[0]
                    total += val
            mono_samples.append(total // num_channels)
    else:
        mono_samples = []
        for i in range(num_samples):
            offset = i * bytes_per_frame
            if offset + bytes_per_sample <= len(sample_data):
                val = struct.unpack_from(fmt, sample_data, offset)[0]
                mono_samples.append(val)

    if not mono_samples:
        return None

    samples = np.array(mono_samples, dtype=np.float64)
    if max_val > 0:
        samples = samples / max_val

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return None

    if output_path is None:
        output_path = os.path.join(tempfile.gettempdir(), "stegscan_spectrogram.png")

    import warnings
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="divide by zero")
        fig, ax = plt.subplots(1, 1, figsize=(10, 4))
        ax.specgram(samples, Fs=sample_rate, NFFT=1024, noverlap=512)
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Frequency (Hz)")
        ax.set_title("Spectrogram")
        fig.savefig(output_path, dpi=100, bbox_inches="tight")
        plt.close(fig)

    return output_path


def analyze_spectrogram(data: bytes) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []

    spec_path = generate_spectrogram(data)
    if spec_path is None:
        results.append({
            "type": "spectrogram",
            "detections": [],
            "detail": "Failed to generate spectrogram (missing dependencies)",
        })
        return results

    try:
        from PIL import Image
        img = Image.open(spec_path)

        detector = Detector()

        try:
            from pyzbar import pyzbar
            qr_results = pyzbar.decode(img)
            for qr in qr_results:
                qr_text = qr.data.decode("utf-8", errors="replace")
                detections = detector.scan_bytes(qr_text.encode("utf-8"))
                results.append({
                    "type": "spectrogram_qr",
                    "detections": detections,
                    "detail": f"QR code found in spectrogram: {qr_text[:200]}",
                })
        except Exception:
            pass

        img_gray = img.convert("L")
        pixels = list(img_gray.getdata())
        width, height = img.size
        printable_count = sum(1 for p in pixels if 32 <= p <= 126)
        total = len(pixels)
        if total > 0 and printable_count / total > 0.7:
            ascii_data = bytes(pixels[:total])
            detections = detector.scan_bytes(ascii_data)
            results.append({
                "type": "spectrogram_text",
                "detections": detections,
                "detail": "High printable ASCII ratio in spectrogram pixels",
            })

    except Exception as e:
        results.append({
            "type": "spectrogram",
            "detections": [],
            "detail": f"Error analyzing spectrogram: {e}",
        })

    try:
        os.unlink(spec_path)
    except Exception:
        pass

    if not results:
        results.append({
            "type": "spectrogram",
            "detections": [],
            "detail": "No hidden content detected in spectrogram",
        })

    return results
