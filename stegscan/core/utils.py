from __future__ import annotations

import shutil
import subprocess
from collections.abc import Sequence

from stegscan.core.errors import ToolNotFoundError

MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"RIFF", "audio/wav"),
    (b"ID3", "audio/mpeg"),
    (b"\x1a\x45\xdf\xa3", "video/webm"),
    (b"\x00\x00\x00\x1c\x66\x74\x79\x70", "video/mp4"),
    (b"%PDF", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
    (b"\x1f\x8b\x08", "application/gzip"),
    (b"BZ", "application/x-bzip2"),
    (b"\xfd7zXZ", "application/x-xz"),
]


def which(name: str) -> str | None:
    return shutil.which(name)


def require_tool(name: str) -> str:
    path = which(name)
    if path is None:
        raise ToolNotFoundError(f"Required tool not found: {name}")
    return path


def try_tool(
    name: str, args: Sequence[str], timeout: int = 30
) -> subprocess.CompletedProcess[str]:
    path = require_tool(name)
    return subprocess.run(
        [path, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def safe_tool(
    name: str, args: Sequence[str], timeout: int = 30
) -> subprocess.CompletedProcess[str] | None:
    path = which(name)
    if path is None:
        return None
    try:
        return subprocess.run(
            [path, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except Exception:
        return None


def detect_magic(data: bytes) -> str:
    for sig, mime in MAGIC_SIGNATURES:
        if data[: len(sig)] == sig:
            return mime
    return "application/octet-stream"


def hexdump_line(offset: int, chunk: bytes, width: int = 16) -> str:
    hex_part = " ".join(f"{b:02x}" for b in chunk)
    ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
    return f"{offset:08x}  {hex_part:<{width * 3}}  |{ascii_part}|"


def hexdump(data: bytes, length: int = 256) -> str:
    lines: list[str] = []
    for offset in range(0, min(len(data), length), 16):
        lines.append(hexdump_line(offset, data[offset : offset + 16]))
    return "\n".join(lines)


def chunked(data: bytes, size: int) -> list[bytes]:
    return [data[i : i + size] for i in range(0, len(data), size)]
