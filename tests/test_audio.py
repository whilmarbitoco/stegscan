from __future__ import annotations

import struct
import wave

from stegscan.audio.dtmf import DtmfResult, detect_dtmf, dtmf_to_string
from stegscan.audio.lsb import extract_audio_lsb, extract_raw_lsb


def _make_wav(path: str, samples: list[int]) -> None:
    with wave.open(path, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(44100)
        data = bytearray()
        for s in samples:
            data += struct.pack("<h", s)
        wf.writeframes(bytes(data))


def test_extract_audio_lsb(tmp_path) -> None:
    flag = b"CTF{audio_test}"
    samples = [0x1000] * 1000
    flat = bytearray()
    for s in samples:
        flat += struct.pack("<h", s)
    bits = []
    for byte in flag:
        for i in range(8):
            bits.append((byte >> i) & 1)
    for i, b in enumerate(bits):
        flat[i * 2] = (flat[i * 2] & 0xFE) | b
    path = str(tmp_path / "audio.wav")
    with wave.open(path, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(44100)
        wf.writeframes(bytes(flat))
    with open(path, "rb") as f:
        data = f.read()
    extracted = extract_audio_lsb(data)
    assert extracted.startswith(b"CTF{audio_test}")


def test_extract_raw_lsb() -> None:
    samples = b"\x01\x02\x03"
    out = extract_raw_lsb(samples, bits_per_sample=1, channels=1, sample_width=1)
    assert isinstance(out, bytes)


def test_dtmf_detection(tmp_path) -> None:
    import math
    rate = 44100
    duration = 0.1  # 100ms tone
    n = int(rate * duration)
    # DTMF '5' = 770 Hz + 1336 Hz
    freq_row = 770
    freq_col = 1336
    samples = []
    for i in range(n):
        v = 0.4 * math.sin(2 * math.pi * freq_row * i / rate) + \
            0.4 * math.sin(2 * math.pi * freq_col * i / rate)
        v = int(v * 32767)
        samples.append(v)
    # pad with silence before and after
    silence = [0] * int(rate * 0.05)
    full = silence + samples + silence
    path = str(tmp_path / "dtmf.wav")
    _make_wav(path, full)
    with open(path, "rb") as f:
        data = f.read()
    results = detect_dtmf(data)
    assert len(results) >= 1
    assert results[0].digit == "5"
    s = dtmf_to_string(results)
    assert "5" in s


def test_dtmf_to_string() -> None:
    results = [
        DtmfResult(digit="1", start_time=0.0, end_time=0.1, confidence=0.9),
        DtmfResult(digit="2", start_time=0.1, end_time=0.2, confidence=0.9),
    ]
    assert dtmf_to_string(results) == "12"
