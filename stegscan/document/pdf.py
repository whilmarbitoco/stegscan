from __future__ import annotations

import re
import zlib
from typing import Any


def _find_objects(data: bytes) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    pattern = re.compile(rb"(\d+)\s+(\d+)\s+obj")
    for match in pattern.finditer(data):
        obj_num = int(match.group(1))
        gen_num = int(match.group(2))
        start = match.end()
        endobj = data.find(b"endobj", start)
        if endobj < 0:
            endobj = len(data)
        stream_start = data.find(b"stream", start)
        stream_end = data.find(b"endstream", start)
        has_stream = stream_start >= 0 and stream_start < endobj and stream_end >= 0 and stream_end < endobj
        stream_data = b""
        if has_stream:
            ss = data.find(b"\n", stream_start)
            if ss < 0:
                ss = stream_start + 6
            else:
                ss += 1
            if data[ss:ss + 1] == b"\r":
                ss += 1
            stream_data = data[ss:stream_end]
        obj_content = data[start:endobj]
        objects.append({
            "obj_num": obj_num,
            "gen_num": gen_num,
            "content": obj_content,
            "stream": stream_data,
            "has_stream": has_stream,
        })
    return objects


def _extract_text_from_stream(stream_data: bytes) -> str:
    text_parts: list[str] = []
    tj_pattern = re.compile(rb"\(([^)]*)\)\s*Tj")
    TJ_pattern = re.compile(rb"\[([^\]]*)\]\s*TJ")
    for match in tj_pattern.finditer(stream_data):
        raw = match.group(1)
        try:
            text_parts.append(raw.decode("latin-1"))
        except Exception:
            pass
    for match in TJ_pattern.finditer(stream_data):
        raw = match.group(1)
        hex_pattern = re.compile(rb"<([0-9A-Fa-f]+)>")
        for hex_match in hex_pattern.finditer(raw):
            try:
                decoded = bytes.fromhex(hex_match.group(1).decode("ascii"))
                text_parts.append(decoded.decode("latin-1", errors="replace"))
            except Exception:
                pass
    return "".join(text_parts)


def _decompress_flatedecode(obj_content: bytes, stream_data: bytes) -> bytes:
    filter_match = re.search(rb"/Filter\s*/FlateDecode", obj_content)
    if not filter_match:
        return stream_data
    try:
        return zlib.decompress(stream_data)
    except zlib.error:
        try:
            return zlib.decompress(stream_data, -15)
        except zlib.error:
            return stream_data


def _check_hidden_text(obj_content: bytes) -> list[str]:
    issues: list[str] = []
    color_pattern = re.compile(rb"(\d+\.?\d*)\s+(\d+\.?\d*)\s+(\d+\.?\d*)\s+rg")
    rgb_matches = list(color_pattern.finditer(obj_content))
    for i, match in enumerate(rgb_matches):
        r = float(match.group(1))
        g = float(match.group(2))
        b = float(match.group(3))
        if r > 0.95 and g > 0.95 and b > 0.95:
            issues.append(f"White-on-white text detected (RGB {r:.2f},{g:.2f},{b:.2f}) at offset {match.start()}")
    return issues


def _check_offpage_text(obj_content: bytes) -> list[str]:
    issues: list[str] = []
    position_pattern = re.compile(rb"(-?\d+\.?\d*)\s+(-?\d+\.?\d*)\s+Td")
    for match in position_pattern.finditer(obj_content):
        x = float(match.group(1))
        y = float(match.group(2))
        if abs(x) > 2000 or abs(y) > 2000 or x < -1000 or y < -1000:
            issues.append(f"Off-page text position ({x:.1f}, {y:.1f}) at offset {match.start()}")
    return issues


def _check_annotations(obj_content: bytes) -> list[str]:
    issues: list[str] = []
    annot_match = re.search(rb"/Annots", obj_content)
    if annot_match:
        issues.append(f"Annotations found at offset {annot_match.start()}")
    return issues


def _check_javascript(obj_content: bytes) -> list[str]:
    issues: list[str] = []
    js_patterns = [b"/JavaScript", b"/JS", b"eval(", b"eval("]
    for pattern in js_patterns:
        pos = obj_content.find(pattern)
        if pos >= 0:
            issues.append(f"JavaScript reference found: {pattern.decode('ascii', errors='replace')} at offset {pos}")
    return issues


def _check_embedded_files(obj_content: bytes) -> list[str]:
    issues: list[str] = []
    ef_patterns = [b"/EmbeddedFile", b"/EF", b"/Filespec", b"/Launch"]
    for pattern in ef_patterns:
        pos = obj_content.find(pattern)
        if pos >= 0:
            issues.append(
                f"Embedded file/launch reference found: "
                f"{pattern.decode('ascii', errors='replace')} at offset {pos}"
            )
    return issues


def _extract_metadata(data: bytes) -> dict[str, str]:
    meta_map: dict[str, str] = {}
    patterns = {
        "Author": rb"/Author\s*\(([^)]*)\)",
        "Creator": rb"/Creator\s*\(([^)]*)\)",
        "Producer": rb"/Producer\s*\(([^)]*)\)",
        "Title": rb"/Title\s*\(([^)]*)\)",
        "Subject": rb"/Subject\s*\(([^)]*)\)",
        "Keywords": rb"/Keywords\s*\(([^)]*)\)",
        "CreationDate": rb"/CreationDate\s*\(([^)]*)\)",
        "ModDate": rb"/ModDate\s*\(([^)]*)\)",
    }
    for key, pattern in patterns.items():
        match = re.search(pattern, data)
        if match:
            meta_map[key] = match.group(1).decode("latin-1", errors="replace")
    xmp_start = data.find(b"<x:xmpmeta")
    xmp_end = data.find(b"</x:xmpmeta>")
    if xmp_start >= 0 and xmp_end >= 0:
        xmp_data = data[xmp_start:xmp_end + 12].decode("utf-8", errors="replace")
        title_match = re.search(r"<dc:title>(.*?)</dc:title>", xmp_data)
        if title_match:
            meta_map["XMP_Title"] = title_match.group(1)
        creator_match = re.search(r"<dc:creator>(.*?)</dc:creator>", xmp_data, re.DOTALL)
        if creator_match:
            meta_map["XMP_Creator"] = creator_match.group(1)
    return meta_map


def _scan_object_text(obj: dict[str, Any], detector: Any) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    stream_data = obj["stream"]
    if obj["has_stream"]:
        decompressed = _decompress_flatedecode(obj["content"], stream_data)
        text = _extract_text_from_stream(decompressed)
        if text.strip():
            detections = detector.scan_bytes(text.encode("utf-8", errors="replace"))
            if detections:
                results.append({
                    "type": "stream_text",
                    "detections": detections,
                    "detail": f"Object {obj['obj_num']}: {text[:300]}",
                    "confidence": max((d.confidence for d in detections), default=0.0),
                })
        hidden = _check_hidden_text(decompressed)
        for issue in hidden:
            results.append({
                "type": "anomaly",
                "detections": [],
                "detail": f"Object {obj['obj_num']}: {issue}",
                "confidence": 0.6,
            })
        offpage = _check_offpage_text(decompressed)
        for issue in offpage:
            results.append({
                "type": "anomaly",
                "detections": [],
                "detail": f"Object {obj['obj_num']}: {issue}",
                "confidence": 0.5,
            })
    raw_text = _extract_text_from_stream(obj["content"])
    if raw_text.strip():
        detections = detector.scan_bytes(raw_text.encode("utf-8", errors="replace"))
        if detections:
            results.append({
                "type": "obj_text",
                "detections": detections,
                "detail": f"Object {obj['obj_num']}: {raw_text[:300]}",
                "confidence": max((d.confidence for d in detections), default=0.0),
            })
    annots = _check_annotations(obj["content"])
    for issue in annots:
        results.append({
            "type": "metadata",
            "detections": [],
            "detail": f"Object {obj['obj_num']}: {issue}",
            "confidence": 0.4,
        })
    js_issues = _check_javascript(obj["content"])
    for issue in js_issues:
        results.append({
            "type": "anomaly",
            "detections": [],
            "detail": f"Object {obj['obj_num']}: {issue}",
            "confidence": 0.8,
        })
    ef_issues = _check_embedded_files(obj["content"])
    for issue in ef_issues:
        results.append({
            "type": "embedded",
            "detections": [],
            "detail": f"Object {obj['obj_num']}: {issue}",
            "confidence": 0.7,
        })
    return results


def analyze_pdf(
    filepath: str,
    flag_regex: str | None = None,
    quiet: bool = False,
) -> list[dict[str, Any]]:
    from stegscan.flagfinder.detector import Detector

    with open(filepath, "rb") as f:
        data = f.read()

    if not data.startswith(b"%PDF"):
        return []

    detector = Detector(flag_regex=flag_regex)
    results: list[dict[str, Any]] = []

    meta = _extract_metadata(data)
    if meta:
        results.append({
            "module": "document.pdf",
            "type": "metadata",
            "detections": [],
            "detail": f"PDF metadata: {meta}",
            "confidence": 0.5,
        })

    objects = _find_objects(data)
    for obj in objects:
        obj_results = _scan_object_text(obj, detector)
        for r in obj_results:
            r["module"] = "document.pdf"
        results.extend(obj_results)

    trailer_match = re.search(rb"trailer\s*<<(.*?)>>", data, re.DOTALL)
    if trailer_match:
        trailer_match.group(1).decode("latin-1", errors="replace")
        meta_match = re.search(rb"/Info\s+(\d+)\s+\d+\s+R", trailer_match.group(1))
        if meta_match:
            info_obj_num = int(meta_match.group(1))
            for obj in objects:
                if obj["obj_num"] == info_obj_num:
                    info_text = obj["content"].decode("latin-1", errors="replace")
                    detections = detector.scan_bytes(info_text.encode("utf-8", errors="replace"))
                    if detections:
                        results.append({
                            "module": "document.pdf",
                            "type": "flag",
                            "detections": detections,
                            "detail": f"Info object {info_obj_num}: {info_text[:300]}",
                            "confidence": max((d.confidence for d in detections), default=0.0),
                        })

    return results
