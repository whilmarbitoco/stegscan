from __future__ import annotations

from pathlib import Path

from stegscan.core.errors import FileFormatError
from stegscan.core.utils import detect_magic


class FileInfo:
    """Holds raw bytes and detected format for a scanned file."""

    __slots__ = ("data", "mime", "path", "size")

    def __init__(self, path: Path, data: bytes) -> None:
        self.path = path
        self.data = data
        self.mime = detect_magic(data)
        self.size = len(data)

    @classmethod
    def from_path(cls, path: str | Path) -> FileInfo:
        p = Path(path)
        if not p.is_file():
            raise FileFormatError(f"Not a regular file: {p}")
        data = p.read_bytes()
        if not data:
            raise FileFormatError(f"Empty file: {p}")
        return cls(p, data)

    def slice(self, offset: int, length: int) -> bytes:
        return self.data[offset : offset + length]

    def find(self, needle: bytes, start: int = 0) -> int:
        return self.data.find(needle, start)

    def rfind(self, needle: bytes) -> int:
        return self.data.rfind(needle)

    def contains(self, needle: bytes) -> bool:
        return needle in self.data
