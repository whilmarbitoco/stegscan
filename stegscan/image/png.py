from __future__ import annotations

import zlib
from typing import Any

from PIL import Image

from stegscan.core.carving import carve_png_chunks
from stegscan.flagfinder.detector import Detector
from stegscan.image.bitplane import analyze_bitplanes
from stegscan.image.channel import analyze_channel_differences
from stegscan.image.diff import detect_lsb_anomaly
from stegscan.image.lsb import (
    lsb_extract_rgb,
    modulo_mask,
    near_black_mask,
    near_white_mask,
    region_mask,
)


def _extract_text_chunks(data: bytes) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    offset = 8
    while offset + 8 <= len(data):
        length = int.from_bytes(data[offset:offset + 4], "big")
        chunk_type = data[offset + 4:offset + 8].decode("ascii", errors="replace")
        chunk_data = data[offset + 8:offset + 8 + length]

        if chunk_type == "tEXt":
            sep = chunk_data.find(b"\x00")
            if sep >= 0:
                key = chunk_data[:sep].decode("latin-1")
                val = chunk_data[sep + 1:].decode("latin-1", errors="replace")
                results.append({"type": "tEXt", "key": key, "value": val})

        elif chunk_type == "zTXt":
            sep = chunk_data.find(b"\x00")
            if sep >= 0:
                key = chunk_data[:sep].decode("latin-1")
                compressed = chunk_data[sep + 1:]
                if compressed and compressed[0] == 0:
                    compressed = compressed[1:]
                try:
                    decompressed = zlib.decompress(compressed)
                    val = decompressed.decode("latin-1", errors="replace")
                    results.append({"type": "zTXt", "key": key, "value": val})
                except Exception:
                    pass

        elif chunk_type == "iTXt":
            sep = chunk_data.find(b"\x00")
            if sep >= 0:
                key = chunk_data[:sep].decode("latin-1")
                rest = chunk_data[sep + 1:]
                if rest and rest[0:1] == b"\x00":
                    sep2 = rest.find(b"\x00", 1)
                    if sep2 >= 0:
                        text = rest[sep2 + 1:].decode("utf-8", errors="replace")
                    else:
                        text = rest[1:].decode("utf-8", errors="replace")
                else:
                    text = rest.decode("utf-8", errors="replace")
                results.append({"type": "iTXt", "key": key, "value": text})

        offset += 12 + length
        if chunk_type == "IEND":
            break

    return results


def _check_custom_chunks(data: bytes) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    offset = 8
    standard_types = {
        "IHDR", "PLTE", "IDAT", "IEND", "tEXt", "zTXt", "iTXt",
        "gAMA", "cHRM", "sRGB", "iCCP", "sBIT", "tRNS", "bKGD",
        "hIST", "pHYs", "sPLT", "tIME",
    }
    while offset + 8 <= len(data):
        length = int.from_bytes(data[offset:offset + 4], "big")
        chunk_type = data[offset + 4:offset + 8].decode("ascii", errors="replace")
        chunk_data = data[offset + 8:offset + 8 + length]

        if chunk_type not in standard_types and len(chunk_type) == 4 and all(32 <= ord(c) <= 126 for c in chunk_type):
            results.append({
                "type": "custom_chunk",
                "key": chunk_type,
                "value": chunk_data.hex()[:200],
                "detail": f"Unusual chunk type: {chunk_type}, length: {length}",
            })

        offset += 12 + length
        if chunk_type == "IEND":
            break

    return results


def _lsb_masks(pixels: list[tuple[int, int, int]], width: int) -> list[tuple[str, bytes]]:
    results: list[tuple[str, bytes]] = []
    masked = near_black_mask(pixels)
    if masked:
        results.append(("near_black", lsb_extract_rgb(masked)))
    masked = near_white_mask(pixels)
    if masked:
        results.append(("near_white", lsb_extract_rgb(masked)))
    masked = region_mask(pixels, width, (0, 0, min(width, 100), min(len(pixels) // width + 1, 100)))
    if masked:
        results.append(("region", lsb_extract_rgb(masked)))
    masked = modulo_mask(pixels, 2)
    if masked:
        results.append(("modulo", lsb_extract_rgb(masked)))
    return results


def analyze_png(filepath: str, flag_regex: str | None = None, quiet: bool = False) -> list[dict[str, Any]]:
    with open(filepath, "rb") as f:
        raw_data = f.read()

    detector = Detector(flag_regex=flag_regex)
    results: list[dict[str, Any]] = []

    text_chunks = _extract_text_chunks(raw_data)
    if text_chunks:
        for tc in text_chunks:
            text_bytes = tc["value"].encode("utf-8", errors="replace")
            detections = detector.scan_bytes(text_bytes)
            results.append({
                "type": "text_chunk",
                "detections": detections,
                "detail": f"{tc['type']} key={tc['key']}: {tc['value'][:200]}",
            })

    custom_chunks = _check_custom_chunks(raw_data)
    for cc in custom_chunks:
        chunk_bytes = bytes.fromhex(cc["value"])
        detections = detector.scan_bytes(chunk_bytes)
        results.append({
            "type": "custom_chunk",
            "detections": detections,
            "detail": cc["detail"],
        })

    try:
        img = Image.open(filepath)
    except Exception:
        return results

    bitplane_results = analyze_bitplanes(img, detector, flag_regex)
    for bp in bitplane_results:
        results.append({
            "type": "bitplane",
            "detections": bp.detections,
            "detail": (
                f"Plane {bp.plane} channel={bp.channel} "
                f"qr={bp.qr_result} sig={bp.has_file_signature} "
                f"text={bp.text_snippet is not None}"
            ),
        })

    try:
        if img.mode != "RGB":
            rgb_img = img.convert("RGB")
        else:
            rgb_img = img
        pixels = list(rgb_img.getdata())
        width = rgb_img.size[0]
        for mask_name, mask_data in _lsb_masks(pixels, width):
            detections = detector.scan_bytes(mask_data)
            if detections:
                results.append({
                    "type": "lsb_mask",
                    "detections": detections,
                    "detail": f"LSB mask={mask_name}",
                })
    except Exception:
        pass

    channel_results = analyze_channel_differences(img, detector)
    for cr in channel_results:
        results.append({
            "type": "channel_diff",
            "detections": cr.detections,
            "detail": f"Channels: {cr.channels}",
        })

    try:
        if img.mode == "P":
            palette = img.getpalette()
            if palette:
                pal_data = bytes(palette)
                detections = detector.scan_bytes(pal_data)
                if detections:
                    results.append({
                        "type": "palette",
                        "detections": detections,
                        "detail": "Palette entries contain suspicious data",
                    })
    except Exception:
        pass

    try:
        lsb_result = detect_lsb_anomaly(img)
        score = lsb_result.get("anomaly_score", 0.0)
        if score > 0.05:
            results.append({
                "type": "lsb_anomaly",
                "detections": [],
                "detail": f"LSB anomaly score: {score:.4f}",
            })
    except Exception:
        pass

    chunks = carve_png_chunks(raw_data)
    for chunk in chunks:
        chunk_type_bytes = chunk.chunk_type
        if chunk_type_bytes:
            detections = detector.scan_bytes(chunk_type_bytes)
            if detections:
                results.append({
                    "type": "chunk_name",
                    "detections": detections,
                    "detail": "Chunk type name contains flag pattern",
                })

    return results
