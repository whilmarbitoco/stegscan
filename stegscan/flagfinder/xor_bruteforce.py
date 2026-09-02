from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import numpy as np


def _xor_bruteforce_numpy(data: bytes, key_range: int = 256) -> list[tuple[int, bytes]]:
    import numpy as np

    arr = np.frombuffer(data, dtype=np.uint8)
    n = len(arr)
    results: list[tuple[int, bytes]] = []
    upper = min(key_range, 256)
    for key in range(upper):
        xored = arr ^ key
        printable = (xored >= 32) & (xored < 127)
        printable = printable | (xored == 9) | (xored == 10) | (xored == 13)
        if np.count_nonzero(printable) / n > 0.5:
            results.append((key, xored.tobytes()))
    return results


def xor_bruteforce(data: bytes, key_range: int = 256) -> list[tuple[int, bytes]]:
    results: list[tuple[int, bytes]] = []
    if not data:
        return results
    try:
        return _xor_bruteforce_numpy(data, key_range)
    except ImportError:
        pass

    for key in range(min(key_range, 256)):
        xored = bytes(b ^ key for b in data)
        printable_count = sum(1 for b in xored if 32 <= b < 127 or b in (9, 10, 13))
        if printable_count / len(data) > 0.5:
            results.append((key, xored))
    return results
