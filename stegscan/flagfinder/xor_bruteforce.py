from __future__ import annotations


def xor_bruteforce(data: bytes, key_range: int = 256) -> list[tuple[int, bytes]]:
    results: list[tuple[int, bytes]] = []
    if not data:
        return results
    for key in range(min(key_range, 256)):
        xored = bytes(b ^ key for b in data)
        printable_count = sum(1 for b in xored if 32 <= b < 127 or b in (9, 10, 13))
        if printable_count / len(data) > 0.5:
            results.append((key, xored))
    return results
