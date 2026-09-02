from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass


@dataclass
class PngChunk:
    chunk_type: bytes
    offset: int
    data: bytes
    crc_valid: bool


@dataclass
class JpegMarker:
    marker: int
    name: str
    offset: int
    data: bytes


PNG_SIGNATURE: bytes = b"\x89PNG\r\n\x1a\n"

JPEG_MARKER_NAMES: dict[int, str] = {
    0xD8: "SOI",
    0xD9: "EOI",
    0xDA: "SOS",
    0xDB: "DQT",
    0xDC: "DNL",
    0xDD: "DRI",
    0xDE: "DHP",
    0xDF: "EXP",
    0xE0: "APP0",
    0xE1: "APP1",
    0xE2: "APP2",
    0xE3: "APP3",
    0xE4: "APP4",
    0xE5: "APP5",
    0xE6: "APP6",
    0xE7: "APP7",
    0xE8: "APP8",
    0xE9: "APP9",
    0xEA: "APP10",
    0xEB: "APP11",
    0xEC: "APP12",
    0xED: "APP13",
    0xEE: "APP14",
    0xEF: "APP15",
    0xFE: "COM",
    0xC0: "SOF0",
    0xC1: "SOF1",
    0xC2: "SOF2",
    0xC3: "SOF3",
    0xC5: "SOF5",
    0xC6: "SOF6",
    0xC7: "SOF7",
    0xC9: "SOF9",
    0xCA: "SOF10",
    0xCB: "SOF11",
    0xCD: "SOF13",
    0xCE: "SOF14",
    0xCF: "SOF15",
    0xC4: "DHT",
    0xC8: "JPG",
    0xCC: "DAC",
}

HIDDEN_CHUNK_TYPES: set[bytes] = {
    b"tEXt",
    b"zTXt",
    b"iTXt",
    b"sPLT",
    b"hIST",
}


def _png_crc(chunk_type: bytes, chunk_data: bytes) -> int:
    return zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF


def carve_png_chunks(data: bytes) -> list[PngChunk]:
    chunks: list[PngChunk] = []
    if not data.startswith(PNG_SIGNATURE):
        return chunks
    offset: int = len(PNG_SIGNATURE)
    while offset + 8 <= len(data):
        if offset + 12 > len(data):
            break
        length: int = struct.unpack(">I", data[offset : offset + 4])[0]
        chunk_type: bytes = data[offset + 4 : offset + 8]
        if offset + 12 + length > len(data):
            break
        chunk_data: bytes = data[offset + 8 : offset + 8 + length]
        stored_crc: int = struct.unpack(
            ">I", data[offset + 8 + length : offset + 12 + length]
        )[0]
        computed_crc: int = _png_crc(chunk_type, chunk_data)
        chunks.append(
            PngChunk(
                chunk_type=chunk_type,
                offset=offset,
                data=chunk_data,
                crc_valid=stored_crc == computed_crc,
            )
        )
        offset += 12 + length
        if chunk_type == b"IEND":
            break
    return chunks


def carve_jpeg_markers(data: bytes) -> list[JpegMarker]:
    markers: list[JpegMarker] = []
    if len(data) < 2 or data[0] != 0xFF or data[1] != 0xD8:
        return markers
    markers.append(JpegMarker(marker=0xD8, name="SOI", offset=0, data=b""))
    i: int = 2
    while i < len(data) - 1:
        if data[i] != 0xFF:
            i += 1
            continue
        while i < len(data) - 1 and data[i + 1] == 0xFF:
            i += 1
        marker_byte: int = data[i + 1]
        if marker_byte == 0x00:
            i += 2
            continue
        if marker_byte == 0xD9:
            markers.append(JpegMarker(marker=0xD9, name="EOI", offset=i, data=b""))
            break
        if marker_byte == 0xD8:
            i += 2
            continue
        if i + 3 >= len(data):
            break
        length: int = struct.unpack(">H", data[i + 2 : i + 4])[0]
        marker_data: bytes = data[i + 4 : i + 2 + length]
        name: str = JPEG_MARKER_NAMES.get(marker_byte, f"0xFF{marker_byte:02X}")
        markers.append(
            JpegMarker(marker=marker_byte, name=name, offset=i, data=marker_data)
        )
        i += 2 + length
    return markers
