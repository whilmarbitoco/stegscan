from __future__ import annotations

from typing import Any

from PIL import Image

from stegscan.core.carving import carve_jpeg_markers
from stegscan.flagfinder.detector import Detection, Detector
from stegscan.image.bitplane import analyze_bitplanes
from stegscan.image.channel import analyze_channel_differences
from stegscan.image.diff import detect_lsb_anomaly
from stegscan.image.lsb import lsb_extract_rgb


def _parse_exif(data: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    offset = 2
    while offset + 4 <= len(data):
        marker = data[offset:offset + 2]
        if marker[0] != 0xFF:
            break
        if marker[1] in (0xD8, 0xD9):
            offset += 2
            if marker[1] == 0xD9:
                break
            continue
        length = int.from_bytes(data[offset + 2:offset + 4], "big")
        segment_data = data[offset + 4:offset + 2 + length]

        if marker[1] == 0xE1:
            try:
                text = segment_data.decode("utf-8", errors="replace")
                result["APP1"] = text[:2000]
            except Exception:
                result["APP1"] = segment_data.hex()[:500]
        elif marker == b"\xff\xfe":
            try:
                text = segment_data.decode("utf-8", errors="replace")
                result["COM"] = text[:2000]
            except Exception:
                result["COM"] = segment_data.hex()[:500]
        elif marker[1] in range(0xE0, 0xEF):
            key = f"APP{marker[1] - 0xE0}"
            result[key] = segment_data.hex()[:500]

        offset += 2 + length

    return result


def _find_trailing_data(data: bytes) -> bytes | None:
    eoi_pos = data.rfind(b"\xff\xd9")
    if eoi_pos >= 0 and eoi_pos + 2 < len(data):
        trailing = data[eoi_pos + 2:]
        if len(trailing) > 0:
            return trailing
    return None


def _try_steghide(filepath: str) -> list[Detection]:
    try:
        from stegscan.core.utils import require_tool
        require_tool("steghide")
        import subprocess
        result = subprocess.run(
            ["steghide", "extract", "-sf", filepath, "-p", "", "-f", "-xf", "/dev/null"],
            capture_output=True,
            timeout=10,
            text=True,
        )
        if result.returncode == 0:
            return [Detection(
                flag="steghide_empty_password_extracted",
                source="steghide",
                confidence=0.9,
                decode_path=["steghide", "extract"],
            )]
    except Exception:
        pass
    return []


def analyze_jpeg(filepath: str, flag_regex: str | None = None, quiet: bool = False) -> list[dict[str, Any]]:
    with open(filepath, "rb") as f:
        raw_data = f.read()

    detector = Detector(flag_regex=flag_regex)
    results: list[dict[str, Any]] = []

    markers = carve_jpeg_markers(raw_data)
    for marker in markers:
        if hasattr(marker, "data") and marker.data:
            detections = detector.scan_bytes(marker.data)
            if detections:
                results.append({
                    "type": "marker",
                    "detections": detections,
                    "detail": f"Marker 0x{marker.marker:04X} ({marker.name})",
                })

    exif_data = _parse_exif(raw_data)
    for key, val in exif_data.items():
        val_bytes = val.encode("utf-8", errors="replace")
        detections = detector.scan_bytes(val_bytes)
        if detections:
            results.append({
                "type": "exif",
                "detections": detections,
                "detail": f"{key}: {str(val)[:200]}",
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
            "detail": f"Plane {bp.plane} channel={bp.channel} qr={bp.qr_result} sig={bp.has_file_signature}",
        })

    try:
        if img.mode != "RGB":
            rgb_img = img.convert("RGB")
        else:
            rgb_img = img
        pixels = list(rgb_img.getdata())
        lsb_data = lsb_extract_rgb(pixels)
        detections = detector.scan_bytes(lsb_data)
        if detections:
            results.append({
                "type": "lsb",
                "detections": detections,
                "detail": "LSB extraction from RGB",
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

    trailing = _find_trailing_data(raw_data)
    if trailing:
        detections = detector.scan_bytes(trailing)
        results.append({
            "type": "trailing_data",
            "detections": detections,
            "detail": f"Trailing data after EOI: {len(trailing)} bytes",
        })

    steghide_results = _try_steghide(filepath)
    if steghide_results:
        results.append({
            "type": "steghide",
            "detections": steghide_results,
            "detail": "Steghide extracted data with empty password",
        })

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

    return results
