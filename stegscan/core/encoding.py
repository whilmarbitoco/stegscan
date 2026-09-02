from __future__ import annotations

import base64
import codecs

from stegscan.core.errors import DecodeError

ALPHABET_B91: str = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
)


def b64_decode(data: bytes) -> bytes:
    try:
        return base64.b64decode(data)
    except Exception:
        pass
    try:
        padding = 4 - len(data) % 4
        if padding != 4:
            return base64.b64decode(data + b"=" * padding)
        return base64.b64decode(data)
    except Exception:
        raise DecodeError("Base64 decode failed")


def b32_decode(data: bytes) -> bytes:
    try:
        return base64.b32decode(data, casefold=True)
    except Exception:
        raise DecodeError("Base32 decode failed")


def hex_decode(data: bytes) -> bytes:
    try:
        cleaned = data.decode(errors="ignore")
        cleaned = "".join(
            c for c in cleaned if c in "0123456789abcdefABCDEF \t\n\r"
        )
        return bytes.fromhex(cleaned)
    except Exception:
        raise DecodeError("Hex decode failed")


def rot13_decode(data: bytes) -> bytes:
    try:
        text = data.decode(errors="ignore")
        decoded = codecs.decode(text, "rot_13")
        return decoded.encode(errors="ignore")
    except Exception:
        raise DecodeError("ROT13 decode failed")


def base91_decode(data: bytes) -> bytes:
    dtable: dict[str, int] = {c: i for i, c in enumerate(ALPHABET_B91)}
    text = data.decode("ascii", errors="ignore")
    v: int = -1
    b: int = 0
    n: int = 0
    out: bytearray = bytearray()
    for c in text:
        if c not in dtable:
            continue
        if v < 0:
            v = dtable[c]
        else:
            v += dtable[c] * 91
            b |= v << n
            n += 13 if (v & 8191) > 88 else 14
            while n > 7:
                out.append(b & 255)
                b >>= 8
                n -= 8
            v = -1
    if v >= 0:
        out.append((b | v << n) & 255)
    return bytes(out)


def encode_b64(data: bytes) -> bytes:
    return base64.b64encode(data)
