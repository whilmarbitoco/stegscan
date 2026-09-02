from __future__ import annotations

import math
import os
import struct
import wave

from stegscan.audio.spectrogram import analyze_spectrogram, generate_spectrogram


def _write_tone_wav(path: str, freq: float = 440.0, rate: int = 8000, secs: float = 1.0) -> None:
    n = int(rate * secs)
    with wave.open(path, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(rate)
        data = bytearray()
        for i in range(n):
            v = int(0.4 * 32767 * math.sin(2 * math.pi * freq * i / rate))
            data += struct.pack("<h", v)
        wf.writeframes(bytes(data))


def test_generate_spectrogram(tmp_path) -> None:
    path = str(tmp_path / "tone.wav")
    _write_tone_wav(path)
    with open(path, "rb") as f:
        data = f.read()
    out_path = generate_spectrogram(data)
    assert out_path is not None
    assert os.path.exists(out_path)
    os.unlink(out_path)


def test_generate_spectrogram_custom_output(tmp_path) -> None:
    import tempfile
    path = str(tmp_path / "tone2.wav")
    _write_tone_wav(path)
    with open(path, "rb") as f:
        data = f.read()
    out = os.path.join(tempfile.gettempdir(), "custom_spec.png")
    result = generate_spectrogram(data, out)
    assert result == out
    assert os.path.exists(out)
    os.unlink(out)


def test_analyze_spectrogram(tmp_path) -> None:
    path = str(tmp_path / "tone3.wav")
    _write_tone_wav(path)
    with open(path, "rb") as f:
        data = f.read()
    results = analyze_spectrogram(data)
    assert len(results) >= 1
    assert results[0]["type"] == "spectrogram"


def test_invalid_wav_returns_none() -> None:
    assert generate_spectrogram(b"not a wav file") is None
