from __future__ import annotations

import json
import os
import re
import struct
import tempfile
from dataclasses import dataclass
from typing import Any

from stegscan.core.utils import safe_tool, which


@dataclass
class FrameInfo:
    index: int
    path: str
    timestamp: float


def _extract_frames_ffmpeg(filepath: str, output_dir: str) -> list[FrameInfo]:
    pattern = os.path.join(output_dir, "frame_%04d.png")
    result = safe_tool(
        "ffmpeg",
        ["-i", filepath, "-vsync", "0", "-q:v", "1", pattern],
        timeout=120,
    )
    if result is None:
        return []
    frames: list[FrameInfo] = []
    for fname in sorted(os.listdir(output_dir)):
        if fname.startswith("frame_") and fname.endswith(".png"):
            match = re.search(r"frame_(\d+)", fname)
            if match:
                idx = int(match.group(1)) - 1
                frames.append(FrameInfo(
                    index=idx,
                    path=os.path.join(output_dir, fname),
                    timestamp=float(idx) * (1.0 / 30.0),
                ))
    return frames


def _extract_frames_pil(filepath: str, output_dir: str) -> list[FrameInfo]:
    try:
        from PIL import Image
    except ImportError:
        return []
    frames: list[FrameInfo] = []
    try:
        img = Image.open(filepath)
        idx = 0
        while True:
            frame = img.copy()
            out_path = os.path.join(output_dir, f"frame_{idx:04d}.png")
            frame.save(out_path, "PNG")
            frames.append(FrameInfo(index=idx, path=out_path, timestamp=float(idx)))
            idx += 1
            img.seek(idx)
    except EOFError:
        pass
    except Exception:
        pass
    return frames


def extract_frames(filepath: str, output_dir: str | None = None) -> list[FrameInfo]:
    if output_dir is None:
        output_dir = tempfile.mkdtemp(prefix="stegscan_frames_")
    else:
        os.makedirs(output_dir, exist_ok=True)
    if which("ffmpeg") is not None:
        return _extract_frames_ffmpeg(filepath, output_dir)
    return _extract_frames_pil(filepath, output_dir)


def _extract_audio_stream(filepath: str) -> bytes | None:
    result = safe_tool(
        "ffmpeg",
        ["-i", filepath, "-map", "0:a", "-f", "wav", "pipe:1"],
        timeout=60,
    )
    if result is None or result.returncode != 0:
        return None
    return result.stdout.encode("latin-1") if isinstance(result.stdout, str) else result.stdout


def _extract_video_metadata(filepath: str) -> dict[str, object]:
    result = safe_tool(
        "ffprobe",
        ["-print_format", "json", "-show_format", "-show_streams", filepath],
        timeout=30,
    )
    if result is None or result.returncode != 0:
        return {}
    try:
        return json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        return {}


def _detect_audio_lsb_wav(audio_data: bytes) -> list[dict[str, Any]]:
    if len(audio_data) < 44:
        return []
    riff_pos = audio_data.find(b"RIFF")
    if riff_pos < 0:
        return []
    offset = riff_pos + 12
    channels = 0
    bits_per_sample = 0
    data_size = 0
    while offset + 8 <= len(audio_data):
        chunk_id = audio_data[offset:offset + 4]
        chunk_size = struct.unpack("<I", audio_data[offset + 4:offset + 8])[0]
        if chunk_id == b"fmt ":
            if offset + 24 <= len(audio_data):
                channels = struct.unpack("<H", audio_data[offset + 10:offset + 12])[0]
                struct.unpack("<I", audio_data[offset + 14:offset + 18])[0]
                bits_per_sample = struct.unpack("<H", audio_data[offset + 22:offset + 24])[0]
        elif chunk_id == b"data":
            data_size = chunk_size
            break
        offset += 8 + chunk_size
        if chunk_size % 2 != 0:
            offset += 1
    if channels == 0 or bits_per_sample == 0:
        return []
    data_start = audio_data.find(b"data")
    if data_start < 0:
        return []
    data_start += 8
    audio_bytes = audio_data[data_start:data_start + data_size]
    if bits_per_sample == 16 and len(audio_bytes) >= 2:
        samples = struct.unpack(f"<{len(audio_bytes) // 2}h", audio_bytes)
        lsb_bits = [(s & 1) for s in samples]
    elif bits_per_sample == 8 and len(audio_bytes) >= 1:
        lsb_bits = [(b & 1) for b in audio_bytes]
    else:
        return []
    result_bytes = bytearray()
    for i in range(0, len(lsb_bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte |= lsb_bits[i + j] << j
        result_bytes.append(byte)
    if len(result_bytes) == 0:
        return []
    printable_count = sum(1 for b in result_bytes if 32 <= b < 127 or b in (9, 10, 13))
    ratio = printable_count / len(result_bytes)
    if ratio > 0.3:
        try:
            text = bytes(result_bytes).decode("ascii", errors="replace").strip()
        except Exception:
            text = ""
        if text:
            return [{
                "type": "audio_lsb",
                "detail": f"Audio LSB extraction: {text[:500]}",
                "confidence": min(ratio, 1.0),
            }]
    return []


def _scan_audio_metadata(audio_data: bytes) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    id3_pos = audio_data.find(b"ID3")
    if id3_pos >= 0 and id3_pos + 10 <= len(audio_data):
        version = audio_data[id3_pos + 3:id3_pos + 5]
        text = audio_data[id3_pos + 10:id3_pos + 1000].decode("latin-1", errors="replace")
        results.append({
            "type": "metadata",
            "detail": f"ID3 tag v{version[0]}.{version[1]}: {text[:300]}",
            "confidence": 0.5,
        })
    return results


def analyze_video_frames(
    filepath: str,
    flag_regex: str | None = None,
    quiet: bool = False,
) -> list[dict[str, Any]]:
    from stegscan.flagfinder.cascade import run_cascade
    from stegscan.flagfinder.detector import Detector

    results: list[dict[str, Any]] = []
    detector = Detector(flag_regex=flag_regex)

    metadata = _extract_video_metadata(filepath)
    if metadata:
        metadata_str = json.dumps(metadata)
        detections = run_cascade(metadata_str.encode(), detector)
        results.append({
            "module": "video.frames",
            "type": "metadata",
            "detections": detections,
            "detail": f"Video metadata: {metadata_str[:500]}",
            "confidence": max((d.confidence for d in detections), default=0.5),
        })

    frames = extract_frames(filepath)
    for frame in frames:
        try:
            with open(frame.path, "rb") as f:
                frame_data = f.read()
        except Exception:
            continue
        detections = run_cascade(frame_data, detector)
        if detections:
            results.append({
                "module": "video.frames",
                "type": "flag",
                "detections": detections,
                "detail": f"Frame {frame.index} ({frame.timestamp:.2f}s)",
                "confidence": max(d.confidence for d in detections),
            })

    audio_data = _extract_audio_stream(filepath)
    if audio_data:
        audio_lsb_results = _detect_audio_lsb_wav(audio_data)
        for r in audio_lsb_results:
            results.append({
                "module": "video.frames",
                "type": r["type"],
                "detections": [],
                "detail": str(r["detail"]),
                "confidence": float(r["confidence"]),
            })
        audio_meta = _scan_audio_metadata(audio_data)
        for r in audio_meta:
            results.append({
                "module": "video.frames",
                "type": r["type"],
                "detections": [],
                "detail": str(r["detail"]),
                "confidence": float(r["confidence"]),
            })

    return results
