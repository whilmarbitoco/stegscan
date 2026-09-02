from __future__ import annotations

from dataclasses import dataclass


@dataclass
class PolyglotMatch:
    primary_format: str
    secondary_format: str
    offset: int
    description: str


ZIP_MAGIC: bytes = b"PK\x03\x04"
PNG_MAGIC: bytes = b"\x89PNG\r\n\x1a\n"
JPEG_MAGIC: bytes = b"\xff\xd8\xff"
PDF_MAGIC: bytes = b"%PDF"
GIF87_MAGIC: bytes = b"GIF87a"
GIF89_MAGIC: bytes = b"GIF89a"


def _find_all(data: bytes, needle: bytes) -> list[int]:
    positions: list[int] = []
    start: int = 0
    while start < len(data):
        idx: int = data.find(needle, start)
        if idx == -1:
            break
        positions.append(idx)
        start = idx + 1
    return positions


def detect_polyglot(data: bytes) -> list[PolyglotMatch]:
    matches: list[PolyglotMatch] = []

    primary_magics: list[tuple[str, bytes, str]] = [
        ("png", PNG_MAGIC, "ZIP signature found at offset {offset} inside PNG"),
        ("jpeg", JPEG_MAGIC, "ZIP signature found at offset {offset} inside JPEG"),
        ("pdf", PDF_MAGIC, "ZIP signature found at offset {offset} inside PDF"),
        ("gif", GIF87_MAGIC, "ZIP signature found at offset {offset} inside GIF"),
        ("gif", GIF89_MAGIC, "ZIP signature found at offset {offset} inside GIF"),
    ]

    for primary_name, primary_magic, desc_template in primary_magics:
        if not data.startswith(primary_magic):
            continue
        zip_positions: list[int] = _find_all(data, ZIP_MAGIC)
        for pos in zip_positions:
            if pos > 0:
                matches.append(
                    PolyglotMatch(
                        primary_format=primary_name,
                        secondary_format="zip",
                        offset=pos,
                        description=desc_template.format(offset=pos),
                    )
                )

    if data.startswith(PNG_MAGIC):
        zip_pos: int = data.find(ZIP_MAGIC)
        if zip_pos > len(PNG_MAGIC):
            matches.append(
                PolyglotMatch(
                    primary_format="png",
                    secondary_format="zip",
                    offset=zip_pos,
                    description=f"PNG+ZIP polyglot: embedded ZIP at offset {zip_pos}",
                )
            )

    if data.startswith(JPEG_MAGIC):
        zip_pos = data.find(ZIP_MAGIC)
        if zip_pos > len(JPEG_MAGIC):
            matches.append(
                PolyglotMatch(
                    primary_format="jpeg",
                    secondary_format="zip",
                    offset=zip_pos,
                    description=f"JPEG+ZIP polyglot: embedded ZIP at offset {zip_pos}",
                )
            )

    if data.startswith(PDF_MAGIC):
        zip_pos = data.find(ZIP_MAGIC)
        if zip_pos > len(PDF_MAGIC):
            matches.append(
                PolyglotMatch(
                    primary_format="pdf",
                    secondary_format="zip",
                    offset=zip_pos,
                    description=f"PDF+ZIP polyglot: embedded ZIP at offset {zip_pos}",
                )
            )

    all_signatures: list[tuple[bytes, str]] = [
        (PNG_MAGIC, "png"),
        (JPEG_MAGIC, "jpeg"),
        (PDF_MAGIC, "pdf"),
        (GIF87_MAGIC, "gif"),
        (GIF89_MAGIC, "gif"),
        (ZIP_MAGIC, "zip"),
    ]

    for sig, name in all_signatures:
        positions: list[int] = _find_all(data, sig)
        if len(positions) > 1:
            for pos in positions[1:]:
                matches.append(
                    PolyglotMatch(
                        primary_format="unknown",
                        secondary_format=name,
                        offset=pos,
                        description=f"Duplicate {name} signature at offset {pos}",
                    )
                )

    seen: set[tuple[str, str, int]] = set()
    unique: list[PolyglotMatch] = []
    for m in matches:
        key: tuple[str, str, int] = (m.primary_format, m.secondary_format, m.offset)
        if key not in seen:
            seen.add(key)
            unique.append(m)
    return unique
