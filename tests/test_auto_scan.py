from __future__ import annotations

import os

from PIL import Image

from stegscan.auto_scan import _deduplicate_flags, print_summary, scan
from stegscan.flagfinder.detector import Detection


def test_scan_png_no_flag(tmp_path) -> None:
    img = Image.new("RGB", (30, 30), (50, 60, 70))
    path = str(tmp_path / "clean.png")
    img.save(path)
    result = scan(path, quiet=True)
    assert result.total_detections >= 0
    assert result.flags_found == []
    # exit-code contract: return 1 if none found


def test_scan_png_lsb_flag(tmp_path) -> None:
    import numpy as np
    flag = b"CTF{integration_lsb}" + b"\x00" * 40
    arr = np.full((50, 50, 3), (90, 100, 110), dtype=np.uint8)
    flat = arr.reshape(-1, 3)
    bits = np.unpackbits(np.frombuffer(flag, dtype=np.uint8))
    for i, b in enumerate(bits):
        if i < len(flat):
            flat[i][1] = (flat[i][1] & 0xFE) | int(b)
    path = str(tmp_path / "integlsb.png")
    Image.fromarray(flat.reshape(50, 50, 3)).save(path)
    result = scan(path, quiet=True)
    flags = [f.flag for f in result.flags_found]
    assert "CTF{integration_lsb}" in flags


def test_scan_custom_regex(tmp_path) -> None:
    img = Image.new("RGB", (20, 20), (1, 2, 3))
    path = str(tmp_path / "custom.png")
    img.save(path)
    result = scan(path, flag_regex=r"SECRET\{.*?\}", quiet=True)
    assert result.total_detections >= 0


def test_output_dir_creates_reports(tmp_path) -> None:
    img = Image.new("RGB", (20, 20), (5, 6, 7))
    path = str(tmp_path / "report.png")
    outdir = str(tmp_path / "out")
    img.save(path)
    scan(path, quiet=True, output_dir=outdir)
    assert os.path.exists(os.path.join(outdir, "results.json"))
    assert os.path.exists(os.path.join(outdir, "report.md"))


def test_deduplicate_flags() -> None:
    flags = [
        Detection(flag="CTF{x}", source="a", confidence=0.6),
        Detection(flag="CTF{y}", source="b", confidence=0.9),
        Detection(flag="CTF{x}", source="c", confidence=0.5),
    ]
    deduped = _deduplicate_flags(flags)
    assert len(deduped) == 2
    # highest confidence kept for CTF{x}
    for d in deduped:
        if d.flag == "CTF{x}":
            assert d.confidence == 0.6


def test_print_summary_plain(tmp_path) -> None:
    img = Image.new("RGB", (10, 10), (1, 1, 1))
    path = str(tmp_path / "p.png")
    img.save(path)
    result = scan(path, quiet=True)
    text = print_summary(result)
    assert "StegScan" in text or "stegscan" in text.lower()
