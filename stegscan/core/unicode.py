from __future__ import annotations


def extract_unicode16_le(data: bytes) -> list[str]:
    strings: list[str] = []
    i: int = 0
    n: int = len(data)
    while i < n - 1:
        if 0x20 <= data[i] < 0x7F and data[i + 1] == 0x00:
            start: int = i
            while i < n - 1 and 0x20 <= data[i] < 0x80 and data[i + 1] == 0x00:
                i += 2
            chunk: bytes = data[start:i]
            if len(chunk) >= 8:
                try:
                    text: str = chunk.decode("utf-16-le")
                    if len(text) >= 4:
                        strings.append(text.rstrip("\x00"))
                except Exception:
                    pass
        else:
            i += 1
    return strings


def extract_unicode16_be(data: bytes) -> list[str]:
    strings: list[str] = []
    i: int = 0
    n: int = len(data)
    while i < n - 1:
        if data[i] == 0x00 and 0x20 <= data[i + 1] < 0x7F:
            start: int = i
            while i < n - 1 and data[i] == 0x00 and 0x20 <= data[i + 1] < 0x80:
                i += 2
            chunk: bytes = data[start:i]
            if len(chunk) >= 8:
                try:
                    text: str = chunk.decode("utf-16-be")
                    if len(text) >= 4:
                        strings.append(text.rstrip("\x00"))
                except Exception:
                    pass
        else:
            i += 1
    return strings


def extract_with_bom(data: bytes) -> list[str]:
    strings: list[str] = []
    if data[:3] == b"\xef\xbb\xbf":
        try:
            strings.append(data[3:].decode("utf-8"))
        except Exception:
            pass
    elif data[:2] == b"\xff\xfe":
        try:
            strings.append(data[2:].decode("utf-16-le"))
        except Exception:
            pass
    elif data[:2] == b"\xfe\xff":
        try:
            strings.append(data[2:].decode("utf-16-be"))
        except Exception:
            pass
    return strings


def all_unicode_strings(data: bytes, min_length: int = 4) -> list[str]:
    all_strings: list[str] = []
    all_strings.extend(extract_unicode16_le(data))
    all_strings.extend(extract_unicode16_be(data))
    all_strings.extend(extract_with_bom(data))
    try:
        text: str = data.decode("utf-8", errors="ignore")
        current: list[str] = []
        for c in text:
            if c.isprintable():
                current.append(c)
            else:
                if len(current) >= min_length:
                    all_strings.append("".join(current))
                current = []
        if len(current) >= min_length:
            all_strings.append("".join(current))
    except Exception:
        pass
    seen: set[str] = set()
    unique: list[str] = []
    for s in all_strings:
        if s not in seen and len(s) >= min_length:
            seen.add(s)
            unique.append(s)
    return unique
