from __future__ import annotations

from dataclasses import dataclass

from stegscan.core.utils import MAGIC_SIGNATURES

MAX_CARVE_SIZE: int = 10 * 1024 * 1024


@dataclass
class CarvedFile:
    name: str
    offset: int
    mime_type: str
    data: bytes


def carve_embedded_files(data: bytes) -> list[CarvedFile]:
    found: list[CarvedFile] = []
    for sig, mime in MAGIC_SIGNATURES:
        offset: int = 0
        while offset < len(data):
            idx: int = data.find(sig, offset)
            if idx == -1:
                break
            end: int = len(data)
            for other_sig, _ in MAGIC_SIGNATURES:
                other_idx: int = data.find(other_sig, idx + len(sig))
                if other_idx != -1 and other_idx < end:
                    end = other_idx
            end = min(end, idx + MAX_CARVE_SIZE)
            carved: bytes = data[idx:end]
            name: str = f"embedded_{mime.replace('/', '_')}_{idx:#x}"
            found.append(
                CarvedFile(name=name, offset=idx, mime_type=mime, data=carved)
            )
            offset = idx + len(sig)
    return found


def carve_from_end(data: bytes) -> list[CarvedFile]:
    found: list[CarvedFile] = []
    primary_sig: bytes = data[:8] if len(data) >= 8 else data
    for sig, mime in MAGIC_SIGNATURES:
        if sig == primary_sig[: len(sig)]:
            continue
        idx: int = data.rfind(sig)
        if idx > 0:
            carved: bytes = data[idx:]
            name: str = f"appended_{mime.replace('/', '_')}_{idx:#x}"
            found.append(
                CarvedFile(name=name, offset=idx, mime_type=mime, data=carved)
            )
    return found
