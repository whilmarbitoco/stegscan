from __future__ import annotations

import os

from PIL import Image, PngImagePlugin

from stegscan.cli import main
from stegscan.document.pdf import analyze_pdf
from stegscan.image.diff import DiffResult, diff_images, diff_stats
from stegscan.triage import triage


class TestPdf:
    def test_pdf_plaintext_flag(self, tmp_path) -> None:
        pdf = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 60 >>
stream
BT /F1 12 Tf 72 700 Td (CTF{pdf_test_flag}) Tj ET
endstream
endobj
trailer
<< /Root 1 0 R /Info 5 0 R >>
%%EOF
"""
        path = str(tmp_path / "flag.pdf")
        with open(path, "wb") as f:
            f.write(pdf)
        results = analyze_pdf(path, None, True)
        flags = {d.flag for r in results for d in r.get("detections", [])}
        assert "CTF{pdf_test_flag}" in flags

    def test_pdf_flate_decompression(self, tmp_path) -> None:
        import zlib
        text = "CTF{pdf_flate_flag}"
        stream_data = f"BT (/{text}) Tj ET".encode("latin-1")
        compressed = zlib.compress(stream_data)
        length = len(compressed)
        pdf = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Contents 4 0 R >>\nendobj\n"
            b"4 0 obj\n<< /Filter /FlateDecode /Length " + str(length).encode() + b" >>\n"
            b"stream\n" + compressed + b"\nendstream\nendobj\n"
            b"trailer\n<< /Root 1 0 R >>\n%%EOF\n"
        )
        path = str(tmp_path / "flate.pdf")
        with open(path, "wb") as f:
            f.write(pdf)
        results = analyze_pdf(path, None, True)
        flags = {d.flag for r in results for d in r.get("detections", [])}
        assert "CTF{pdf_flate_flag}" in flags


class TestTriage:
    def test_triage_png_routes_to_png_analyzer(self, tmp_path) -> None:
        img = Image.new("RGB", (30, 30), (70, 100, 130))
        meta = PngImagePlugin.PngInfo()
        meta.add_text("Title", "CTF{triage_routing_ok}")
        path = str(tmp_path / "tri.png")
        img.save(path, pnginfo=meta)
        results = triage(path, None, True)
        modules = {r.get("module") for r in results}
        assert "image.png" in modules
        flags = {d.flag for r in results for d in r.get("detections", [])}
        assert "CTF{triage_routing_ok}" in flags

    def test_triage_unicode_flag(self, tmp_path) -> None:
        img = Image.new("RGB", (10, 10), (5, 5, 5))
        path = str(tmp_path / "uni.png")
        img.save(path)
        with open(path, "ab") as f:
            f.write("CTF{utf16flag}".encode("utf-16-le"))
        results = triage(path, None, True)
        flags = {d.flag for r in results for d in r.get("detections", [])}
        assert "CTF{utf16flag}" in flags


class TestDiff:
    def test_diff_images_same(self) -> None:
        img1 = Image.new("RGB", (20, 20), (100, 100, 100))
        img2 = Image.new("RGB", (20, 20), (100, 100, 100))
        diffs = diff_images(img1, img2)
        assert diffs == []

    def test_diff_images_different(self) -> None:
        img1 = Image.new("RGB", (20, 20), (100, 100, 100))
        img2 = Image.new("RGB", (20, 20), (200, 100, 100))
        diffs = diff_images(img1, img2)
        assert len(diffs) > 0
        assert all(isinstance(d, DiffResult) for d in diffs)

    def test_diff_stats(self) -> None:
        img = Image.new("RGB", (25, 25), (50, 60, 70))
        stats = diff_stats(img)
        assert "lsb_distribution" in stats
        assert "correlations" in stats


class TestCli:
    def test_cli_version(self, capsys) -> None:
        import pytest
        with pytest.raises(SystemExit) as excinfo:
            main(["--version"])
        assert excinfo.value.code == 0
        out = capsys.readouterr().out
        assert "stegscan" in out.lower()

    def test_cli_missing_file(self, capsys) -> None:
        code = main(["nonexistent_file_xyz.png"])
        assert code == 2

    def test_cli_unknown_technique(self, tmp_path) -> None:
        img = Image.new("RGB", (10, 10), (1, 2, 3))
        path = str(tmp_path / "cli_tmp.png")
        img.save(path)
        try:
            code = main([path, "-t", "not_a_real_tech"])
            assert code == 2
        finally:
            os.remove(path)

    def test_cli_png_flag_found(self, tmp_path) -> None:
        img = Image.new("RGB", (40, 40), (10, 20, 30))
        meta = PngImagePlugin.PngInfo()
        meta.add_text("Comment", "CTF{cli_e2e}")
        path = str(tmp_path / "cli.png")
        img.save(path, pnginfo=meta)
        code = main([path, "-q"])
        assert code == 0
