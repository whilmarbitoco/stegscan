from __future__ import annotations

import base64
import codecs
import re
from collections.abc import Callable

from stegscan.flagfinder.detector import Detection, Detector
from stegscan.flagfinder.xor_bruteforce import xor_bruteforce


def _try_b64(data: bytes) -> bytes | None:
    try:
        return base64.b64decode(data, validate=True)
    except Exception:
        return None


def _try_b32(data: bytes) -> bytes | None:
    try:
        return base64.b32decode(data, casefold=True)
    except Exception:
        return None


def _try_hex(data: bytes) -> bytes | None:
    try:
        cleaned = re.sub(r"\s+", "", data.decode(errors="ignore"))
        return bytes.fromhex(cleaned)
    except Exception:
        return None


def _try_rot13(data: bytes) -> bytes | None:
    try:
        return codecs.decode(data.decode(errors="ignore"), "rot_13").encode(
            errors="ignore"
        )
    except Exception:
        return None


DECODE_FUNCS: list[tuple[str, Callable[[bytes], bytes | None]]] = [
    ("base64", _try_b64),
    ("hex", _try_hex),
    ("rot13", _try_rot13),
    ("base32", _try_b32),
]


def run_cascade(
    data: bytes,
    detector: Detector,
    max_depth: int = 4,
    xor_key_range: int = 256,
    max_heavy_bytes: int = 262144,
) -> list[Detection]:
    all_detections: list[Detection] = []
    seen: dict[str, Detection] = {}

    def _add(detections: list[Detection]) -> None:
        for d in detections:
            if d.flag not in seen or d.confidence > seen[d.flag].confidence:
                seen[d.flag] = d
                all_detections.append(d)

    direct = detector.scan_bytes(data)
    _add(direct)

    # The recursive decode cascade and full XOR sweep are expensive and only
    # make sense on small/high-signal payloads (embedded chunks, extracted LSB
    # data, etc.). On large opaque files they spend minutes XOR-ing every byte
    # of noise; direct detection above already catches plaintext/encoded flags.
    if len(data) > max_heavy_bytes:
        return sorted(all_detections, key=lambda d: d.confidence, reverse=True)

    def _explore(current: bytes, depth: int, path: list[str]) -> None:
        if depth >= max_depth:
            return
        for name, fn in DECODE_FUNCS:
            decoded = fn(current)
            if decoded is None:
                continue
            new_path = path + [name]
            detections = detector.scan_bytes(decoded)
            for d in detections:
                d.confidence *= 0.95 ** len(new_path)
                d.decode_path = new_path + d.decode_path
            _add(detections)
            _explore(decoded, depth + 1, new_path)

    _explore(data, 1, [])

    for key_val, xored_data in xor_bruteforce(data, xor_key_range):
        detections = detector.scan_bytes(xored_data)
        for d in detections:
            d.confidence *= 0.95
            d.decode_path = [f"xor:0x{key_val:02x}"] + d.decode_path
        _add(detections)

    return sorted(all_detections, key=lambda d: d.confidence, reverse=True)
