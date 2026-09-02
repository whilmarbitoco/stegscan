from __future__ import annotations

import os
import struct
import zlib

from PIL import Image, PngImagePlugin

from stegscan.core.carving import carve_png_chunks
from stegscan.core.metadata import all_metadata
from stegscan.core.polyglot import detect_polyglot
from stegscan.image.diff import detect_lsb_anomaly
from stegscan.image.jpeg import analyze_jpeg
from stegscan.image.lsb import (
    lsb_extract_rgb,
    modulo_mask,
    near_black_mask,
    near_white_mask,
    region_mask,
)
from stegscan.image.png import analyze_png


def _make_png(path: str, size: int = 50, color: tuple[int, int, int] = (10, 20, 30)) -> None:
    img = Image.new("RGB", (size, size), color)
    img.save(path)


def test_png_chunk_parsing() -> None:
    _make_png("test_parse.png")
    with open("test_parse.png", "rb") as f:
        data = f.read()
    chunks = carve_png_chunks(data)
    types = [c.chunk_type for c in chunks]
    assert b"IHDR" in types
    assert b"IEND" in types
    assert all(c.crc_valid is not None for c in chunks)
    os.remove("test_parse.png")


def test_png_custom_chunk() -> None:
    _make_png("test_custom.png")
    with open("test_custom.png", "rb") as f:
        data = f.read()
    # insert a custom chunk before IEND
    custom_type = b"CTFx"
    custom_data = b"FLAG{custom_png_chunk}"
    length = len(custom_data)
    crc = zlib.crc32(custom_type + custom_data) & 0xFFFFFFFF
    custom_chunk = struct.pack(">I", length) + custom_type + custom_data + struct.pack(">I", crc)
    iend_pos = data.rfind(b"IEND")
    new_data = data[:iend_pos - 4] + custom_chunk + data[iend_pos - 4:]
    with open("test_custom.png", "wb") as f:
        f.write(new_data)
    results = analyze_png("test_custom.png", None, True)
    flags = []
    for r in results:
        for d in r.get("detections", []):
            flags.append(d.flag)
    assert "FLAG{custom_png_chunk}" in flags
    os.remove("test_custom.png")


def test_lsb_extraction_roundtrip() -> None:
    pixels = [(128, 100, 50)] * 100
    out = lsb_extract_rgb(pixels)
    assert len(out) > 0
    assert isinstance(out, bytes)


def test_lsb_masks() -> None:
    black_px = [(0, 0, 0)] * 10
    white_px = [(255, 255, 255)] * 10
    mixed = black_px + [(10, 20, 30)] * 10 + white_px
    nb = near_black_mask(mixed)
    nw = near_white_mask(mixed)
    assert len(nb) == 10
    assert len(nw) == 10
    r = region_mask(mixed, 10, (0, 0, 5, 2))
    assert len(r) == 10
    m = modulo_mask(mixed)
    assert len(m) == 20


def test_png_analyzer_finds_txt_flag(tmp_path) -> None:
    img = Image.new("RGB", (40, 40), (5, 10, 15))
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Comment", "plain CTF{png_txt_detected}")
    path = str(tmp_path / "txtflag.png")
    img.save(path, pnginfo=meta)
    results = analyze_png(path, None, True)
    flags = {d.flag for r in results for d in r.get("detections", [])}
    assert "CTF{png_txt_detected}" in flags


def test_png_analyzer_finds_lsb_flag(tmp_path) -> None:
    import numpy as np
    flag = b"CTF{lsb_unit_test}" + b"\x00" * 50
    img_arr = np.full((60, 60, 3), (40, 50, 60), dtype=np.uint8)
    flat = img_arr.reshape(-1, 3)
    bits = np.unpackbits(np.frombuffer(flag, dtype=np.uint8))
    for i, b in enumerate(bits):
        if i < len(flat):
            flat[i][2] = (flat[i][2] & 0xFE) | int(b)
    path = str(tmp_path / "lsbflag.png")
    Image.fromarray(flat.reshape(60, 60, 3)).save(path)
    results = analyze_png(path, None, True)
    flags = {d.flag for r in results for d in r.get("detections", [])}
    assert "CTF{lsb_unit_test}" in flags


def test_jpeg_com_marker_flag(tmp_path) -> None:
    img = Image.new("RGB", (30, 30), (200, 100, 50))
    path = str(tmp_path / "jpegcom.jpg")
    img.save(path, quality=92)
    with open(path, "rb") as f:
        base = f.read()
    msg = b"CTF{jpeg_com_flag}"
    com = b"\xff\xfe" + (len(msg) + 2).to_bytes(2, "big") + msg
    new_data = base[:2] + com + base[2:]
    path2 = str(tmp_path / "jpegcom2.jpg")
    with open(path2, "wb") as f:
        f.write(new_data)
    results = analyze_jpeg(path2, None, True)
    flags = {d.flag for r in results for d in r.get("detections", [])}
    assert "CTF{jpeg_com_flag}" in flags


def test_metadata_extraction() -> None:
    _make_png("test_meta.png")
    meta = all_metadata("test_meta.png")
    assert "exif" in meta
    assert "xmp" in meta
    os.remove("test_meta.png")


def test_polyglot_detection(tmp_path) -> None:
    png = Image.new("RGB", (20, 20), (1, 2, 3))
    path = str(tmp_path / "poly.png")
    png.save(path)
    with open(path, "rb") as f:
        png_data = f.read()
    # append a ZIP signature early in the file (within PNG)
    zip_sig = b"PK\x03\x04"
    combined = png_data[:16] + zip_sig + png_data[16:]
    matches = detect_polyglot(combined)
    assert len(matches) >= 1


def test_detect_lsb_anomaly_runs() -> None:
    img = Image.new("RGB", (30, 30), (100, 100, 100))
    stats = detect_lsb_anomaly(img)
    assert "anomaly_score" in stats
    assert "lsb_distribution" in stats
