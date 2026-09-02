from __future__ import annotations

from collections.abc import Sequence


def lsb_extract(data: bytes, bit_depth: int = 1) -> bytes:
    mask = (1 << bit_depth) - 1
    bits: list[int] = []
    for byte in data:
        bits.append(byte & mask)
    total_bits = len(bits) * bit_depth
    total_bytes = (total_bits + 7) // 8
    if total_bytes == 0:
        return b""
    result = bytearray(total_bytes)
    for i in range(total_bits):
        bit = (bits[i // bit_depth] >> (i % bit_depth)) & 1
        result[i // 8] |= bit << (i % 8)
    return bytes(result)


def lsb_extract_rgb(pixels: list[tuple[int, int, int]], bit_depth: int = 1) -> bytes:
    raw = bytearray()
    for r, g, b in pixels:
        raw.append(r)
        raw.append(g)
        raw.append(b)
    return lsb_extract(bytes(raw), bit_depth)


def lsb_extract_rgba(pixels: list[tuple[int, int, int, int]], bit_depth: int = 1) -> bytes:
    raw = bytearray()
    for r, g, b, a in pixels:
        raw.append(r)
        raw.append(g)
        raw.append(b)
        raw.append(a)
    return lsb_extract(bytes(raw), bit_depth)


def near_black_mask(pixels: Sequence[tuple[int, int, int]], threshold: int = 10) -> list[tuple[int, int, int]]:
    return [p for p in pixels if p[0] <= threshold and p[1] <= threshold and p[2] <= threshold]


def near_white_mask(pixels: Sequence[tuple[int, int, int]], threshold: int = 10) -> list[tuple[int, int, int]]:
    return [p for p in pixels if p[0] >= 255 - threshold and p[1] >= 255 - threshold and p[2] >= 255 - threshold]


def region_mask(
    pixels: Sequence[tuple[int, int, int]],
    width: int,
    bbox: tuple[int, int, int, int],
) -> list[tuple[int, int, int]]:
    x1, y1, x2, y2 = bbox
    result: list[tuple[int, int, int]] = []
    for y in range(y1, y2):
        for x in range(x1, x2):
            idx = y * width + x
            if idx < len(pixels):
                result.append(pixels[idx])
    return result


def modulo_mask(pixels: Sequence[tuple[int, int, int]], modulus: int = 2) -> list[tuple[int, int, int]]:
    return [p for p in pixels if sum(p) % modulus == 0]
