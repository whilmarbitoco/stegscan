from __future__ import annotations

from pathlib import Path
from typing import Any


def extract_exif(filepath: str) -> dict[str, Any]:
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS

        img = Image.open(filepath)
        raw_exif = img.getexif()
        if raw_exif is None:
            return {}
        result: dict[str, Any] = {}
        for tag_id, value in raw_exif.items():
            tag_name: str = TAGS.get(tag_id, str(tag_id))
            if isinstance(value, bytes):
                try:
                    value = value.decode("utf-8", errors="replace")
                except Exception:
                    pass
            result[tag_name] = value
        return result
    except Exception:
        return {}


def extract_iptc(filepath: str) -> dict[str, Any]:
    try:
        from iptcinfo3 import IPTCInfo

        info = IPTCInfo(filepath)
        if info is None:
            return {}
        return {str(k): v for k, v in info.items()}
    except Exception:
        return {}


def extract_xmp(filepath: str) -> str | None:
    try:
        data: bytes = Path(filepath).read_bytes()
        begin: bytes = b"<?xpacket begin="
        end: bytes = b"<?xpacket end="
        start: int = data.find(begin)
        if start == -1:
            return None
        end_offset: int = data.find(end, start)
        if end_offset == -1:
            return None
        eol: int = data.find(b"?>", end_offset)
        if eol != -1:
            end_offset = eol + 2
        chunk: bytes = data[start:end_offset]
        try:
            return chunk.decode("utf-8")
        except Exception:
            return chunk.decode("latin-1")
    except Exception:
        return None


def all_metadata(filepath: str) -> dict[str, Any]:
    return {
        "exif": extract_exif(filepath),
        "iptc": extract_iptc(filepath),
        "xmp": extract_xmp(filepath),
    }
