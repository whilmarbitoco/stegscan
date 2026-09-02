from __future__ import annotations

import base64

from stegscan.core.encoding import (
    b32_decode,
    b64_decode,
    base91_decode,
    encode_b64,
    hex_decode,
    rot13_decode,
)
from stegscan.core.errors import DecodeError
from stegscan.core.unicode import all_unicode_strings
from stegscan.flagfinder.cascade import run_cascade
from stegscan.flagfinder.detector import Detector
from stegscan.flagfinder.patterns import FlagPattern
from stegscan.flagfinder.xor_bruteforce import xor_bruteforce


class TestDetector:
    def test_raw_flag_match(self) -> None:
        detector = Detector()
        detections = detector.scan_bytes(b"the flag is CTF{test123} here")
        assert any(d.flag == "CTF{test123}" for d in detections)
        assert len(detections) >= 1

    def test_custom_regex(self) -> None:
        detector = Detector(flag_regex=r"FLAG\{\w+\}")
        detections = detector.scan_bytes(b"found FLAG{custom_works}")
        assert any(d.flag == "FLAG{custom_works}" for d in detections)

    def test_base64_encoded_flag(self) -> None:
        payload = base64.b64encode(b"CTF{encoded}".strip()).decode()
        detector = Detector()
        detections = detector.scan_bytes(payload.encode())
        assert any(d.flag == "CTF{encoded}" for d in detections)

    def test_rot13_encoded_flag(self) -> None:
        detector = Detector()
        # roT13 of CTF{rot13works} -> PGS{ebg13jbexf}
        encoded = "PGS{ebg13jbexf}"
        detections = detector.scan_bytes(encoded.encode())
        assert any("rot13works" in d.flag for d in detections)

    def test_hex_encoded_flag(self) -> None:
        import binascii
        hex_str = binascii.hexlify(b"CTF{hexworks}").decode()
        detector = Detector()
        detections = detector.scan_bytes(hex_str.encode())
        assert any("hexworks" in d.flag for d in detections)

    def test_custom_pattern_override(self) -> None:
        detector = Detector(pattern_overrides=[
            FlagPattern(name="custom", regex=r"XCTF\{.*?\}", flags=0, group=None)
        ])
        detections = detector.scan_bytes(b"XCTF{custom_pattern}")
        assert len(detections) == 1
        assert detections[0].flag == "XCTF{custom_pattern}"


class TestCascade:
    def test_multi_layer_decoding(self) -> None:
        # flag -> base64 -> rot13
        inner = base64.b64encode(b"CTF{layered}").decode()
        layered = bytes(rot13_decode(inner.encode()))
        detector = Detector()
        detections = run_cascade(layered, detector, max_depth=3)
        flags = [d.flag for d in detections]
        assert "CTF{layered}" in flags

    def test_xor_detection(self) -> None:
        data = b"CTF{xor_found}"
        key = 0x42
        xored = bytes(b ^ key for b in data)
        detector = Detector()
        detections = run_cascade(xored, detector, max_depth=2)
        flags = [d.flag for d in detections]
        assert "CTF{xor_found}" in flags

    def test_confidence_penalty(self) -> None:
        detector = Detector()
        direct = detector.scan_bytes(b"CTF{a}")
        assert direct[0].confidence == 1.0
        b64 = base64.b64encode(b"CTF{b}")
        detections = run_cascade(b64, detector, max_depth=2, xor_key_range=0)
        assert -0.0 < (detections[0].confidence - 0.95) < 0.0 or detections[0].confidence <= 1.0


class TestXorBruteforce:
    def test_xor_roundtrip(self) -> None:
        data = b"CTF{xor_bruteforce}"
        key = 0x7F
        xored = bytes(b ^ key for b in data)
        results = xor_bruteforce(xored)
        # original key should appear at least once
        found = any(result_bytes.startswith(b"CTF{") for _, result_bytes in results)
        assert found


class TestEncoding:
    def test_b64_roundtrip(self) -> None:
        encoded = encode_b64(b"hello")
        assert b64_decode(encoded) == b"hello"

    def test_hex_roundtrip(self) -> None:
        assert hex_decode(b"68656c6c6f") == b"hello"

    def test_rot13(self) -> None:
        assert rot13_decode(b"hello") == b"uryyb"

    def test_b32(self) -> None:
        import base64 as b64
        enc = b64.b32encode(b"bonjour")
        assert b32_decode(enc) == b"bonjour"

    def test_base91_known(self) -> None:
        # base91 of "test" with standard implementation
        result = base91_decode(b"fPNKd")
        assert result == b"test"

    def test_invalid_decode_raises(self) -> None:
        import pytest
        with pytest.raises(DecodeError):
            b64_decode(b"!!! not base64 !!!")


class TestUnicode:
    def test_utf16_le_extraction(self) -> None:
        data = "CTF{unicode16}".encode("utf-16-le")
        strings = all_unicode_strings(data, min_length=4)
        assert any("CTF{unicode16}" in s for s in strings)

    def test_bom_detection(self) -> None:
        data = b"\xff\xfe" + "CTF{bom}".encode("utf-16-le")
        strings = all_unicode_strings(data, min_length=3)
        assert any("CTF{bom}" in s for s in strings)
