from __future__ import annotations

from dataclasses import dataclass, field

from PIL import Image

from stegscan.flagfinder.detector import Detection, Detector


@dataclass
class BitplaneResult:
    plane: int
    channel: str
    detections: list[Detection] = field(default_factory=list)
    qr_result: str | None = None
    has_file_signature: bool = False
    text_snippet: str | None = None


FILE_SIGNATURES = [
    b"\x89PNG",
    b"\xff\xd8\xff",
    b"GIF8",
    b"PK\x03\x04",
    b"BM",
    b"\x7fELF",
    b"MZ",
    b"Rar!",
    b"\x1f\x8b",
    b"SQLite",
    b"<!DOCTYPE",
    b"<html",
    b"{",
    b"[",
    b"flag{",
    b"FLAG{",
    b"CTF{",
]


def _extract_bitplane(channel_data: list[int], plane: int) -> list[int]:
    return [(v >> plane) & 1 for v in channel_data]


def _bits_to_bytes(bits: list[int]) -> bytes:
    result = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte |= bits[i + j] << (7 - j)
        result.append(byte)
    return bytes(result)


def _check_file_signatures(data: bytes) -> bool:
    for sig in FILE_SIGNATURES:
        if data[:len(sig)] == sig:
            return True
    return False


def _detect_text(data: bytes, threshold: float = 0.7) -> str | None:
    if len(data) == 0:
        return None
    printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
    ratio = printable / len(data)
    if ratio > threshold:
        decoded = data.decode("ascii", errors="replace")
        snippet = decoded[:200].strip()
        return snippet if snippet else None
    return None


def _try_qr_decode(plane_bytes: bytes) -> str | None:
    try:

        from PIL import Image as PILImage
        from pyzbar import pyzbar

        width = 1
        height = len(plane_bytes)
        if height > 1000:
            side = int(height ** 0.5)
            height = side
            width = side
            plane_bytes_trimmed = plane_bytes[: width * height]
        else:
            plane_bytes_trimmed = plane_bytes

        img = PILImage.new("L", (width, height))
        pixels = list(plane_bytes_trimmed)
        while len(pixels) < width * height:
            pixels.append(0)
        img.putdata(pixels)
        results = pyzbar.decode(img)
        if results:
            return results[0].data.decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


def analyze_bitplanes(img: Image.Image, detector: Detector, flag_regex: str | None = None) -> list[BitplaneResult]:
    if img.mode not in ("RGB", "RGBA", "L"):
        img = img.convert("RGBA")

    channels: dict[str, list[int]] = {}
    if img.mode == "L":
        channels["L"] = list(img.getdata())
    elif img.mode == "RGB":
        r, g, b = img.split()
        channels["R"] = list(r.getdata())
        channels["G"] = list(g.getdata())
        channels["B"] = list(b.getdata())
    elif img.mode == "RGBA":
        r, g, b, a = img.split()
        channels["R"] = list(r.getdata())
        channels["G"] = list(g.getdata())
        channels["B"] = list(b.getdata())
        channels["A"] = list(a.getdata())

    results: list[BitplaneResult] = []

    for channel_name, channel_data in channels.items():
        for plane in range(8):
            bits = _extract_bitplane(channel_data, plane)
            plane_bytes = _bits_to_bytes(bits)

            result = BitplaneResult(plane=plane, channel=channel_name)

            qr_text = _try_qr_decode(plane_bytes)
            result.qr_result = qr_text

            result.has_file_signature = _check_file_signatures(plane_bytes)

            text = _detect_text(plane_bytes)
            result.text_snippet = text

            detections = detector.scan_bytes(plane_bytes)
            result.detections = detections

            if result.detections or result.qr_result or result.has_file_signature or result.text_snippet:
                results.append(result)

    return results
