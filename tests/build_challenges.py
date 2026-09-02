# ruff: noqa: E402
from __future__ import annotations

"""Builds 5 synthetic CTF-style stego challenges and verifies stegscan solves them."""

import base64
import os
import struct
import sys
import wave
import zlib

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import numpy as np
from PIL import Image, PngImagePlugin

from stegscan.auto_scan import scan

CHALLENGES_DIR = os.path.join(os.path.dirname(__file__), "challenges")


def _ensure_dir() -> None:
    os.makedirs(CHALLENGES_DIR, exist_ok=True)


# Challenge 1: LSB in PNG blue channel
def build_lsb_png() -> str:
    flag = b"CTF{challenge1_lsb_blue}" + b"\x00" * 60
    arr = np.full((120, 120, 3), (70, 80, 90), dtype=np.uint8)
    flat = arr.reshape(-1, 3)
    bits = np.unpackbits(np.frombuffer(flag, dtype=np.uint8))
    for i, b in enumerate(bits):
        if i < len(flat):
            flat[i][2] = (flat[i][2] & 0xFE) | int(b)
    path = os.path.join(CHALLENGES_DIR, "challenge1_lsb.png")
    Image.fromarray(flat.reshape(120, 120, 3)).save(path)
    return path


# Challenge 2: base64-encoded flag in PNG tEXt chunk
def build_b64_txt_png() -> str:
    flag_b64 = base64.b64encode(b"CTF{challenge2_base64_comment}").decode()
    img = Image.new("RGB", (80, 80), (200, 150, 100))
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Description", flag_b64)
    path = os.path.join(CHALLENGES_DIR, "challenge2_b64comment.png")
    img.save(path, pnginfo=meta)
    return path


# Challenge 3: flag in JPEG COM marker
def build_jpeg_com() -> str:
    img = Image.new("RGB", (100, 100), (120, 200, 60))
    base = os.path.join(CHALLENGES_DIR, "challenge3_com.jpg")
    img.save(base, quality=95)
    with open(base, "rb") as f:
        data = f.read()
    msg = b"CTF{challenge3_jpeg_comment}"
    com = b"\xff\xfe" + (len(msg) + 2).to_bytes(2, "big") + msg
    path = os.path.join(CHALLENGES_DIR, "challenge3_comment.jpg")
    with open(path, "wb") as f:
        f.write(data[:2] + com + data[2:])
    os.remove(base)
    return path


# Challenge 4: custom PNG chunk with plaintext flag
def build_custom_chunk() -> str:
    img = Image.new("RGB", (60, 60), (30, 40, 50))
    base = os.path.join(CHALLENGES_DIR, "challenge4_base.png")
    img.save(base)
    with open(base, "rb") as f:
        data = f.read()
    custom_type = b"steG"
    custom_data = b"CTF{challenge4_custom_chunk}"
    length = len(custom_data)
    crc = zlib.crc32(custom_type + custom_data) & 0xFFFFFFFF
    chunk = struct.pack(">I", length) + custom_type + custom_data + struct.pack(">I", crc)
    iend_pos = data.rfind(b"IEND")
    new_data = data[:iend_pos - 4] + chunk + data[iend_pos - 4:]
    path = os.path.join(CHALLENGES_DIR, "challenge4_chunk.png")
    with open(path, "wb") as f:
        f.write(new_data)
    os.remove(base)
    return path


# Challenge 5: flag in audio WAV LSB
def build_audio_wav() -> str:
    flag = b"CTF{challenge5_audio_lsb}"
    samples = [0x2000] * 2000
    flat = bytearray()
    for s in samples:
        flat += struct.pack("<h", s)
    bits = []
    for byte in flag:
        for i in range(8):
            bits.append((byte >> i) & 1)
    for i, b in enumerate(bits):
        flat[i * 2] = (flat[i * 2] & 0xFE) | b
    path = os.path.join(CHALLENGES_DIR, "challenge5_audio.wav")
    with wave.open(path, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(44100)
        wf.writeframes(bytes(flat))
    return path


def main() -> None:
    _ensure_dir()
    builders = [
        ("challenge1_lsb", build_lsb_png, "CTF{challenge1_lsb_blue}"),
        ("challenge2_b64", build_b64_txt_png, "CTF{challenge2_base64_comment}"),
        ("challenge3_jpeg", build_jpeg_com, "CTF{challenge3_jpeg_comment}"),
        ("challenge4_chunk", build_custom_chunk, "CTF{challenge4_custom_chunk}"),
        ("challenge5_audio", build_audio_wav, "CTF{challenge5_audio_lsb}"),
    ]

    print("=== Building and solving synthetic CTF challenges ===\n")
    total = 0
    solved = 0
    for name, builder, expected_flag in builders:
        total += 1
        path = builder()
        result = scan(path, quiet=True)
        found = [f.flag for f in result.flags_found]
        ok = expected_flag in found
        if ok:
            solved += 1
            status = "SOLVED"
        else:
            status = "FAILED"
        print(f"[{status}] {name}: expected={expected_flag!r} found={found}")
    print(f"\nSolved {solved}/{total} challenges")
    if solved != total:
        raise SystemExit(2)
    print("ALL CHALLENGES PASSED")


if __name__ == "__main__":
    main()
