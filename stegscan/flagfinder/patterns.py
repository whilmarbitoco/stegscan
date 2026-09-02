from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class FlagPattern:
    name: str
    regex: str
    flags: int = 0
    group: int | None = None


@dataclass(frozen=True)
class FlagMatch:
    pattern: FlagPattern
    value: str
    start: int
    end: int


DEFAULT_PATTERNS: list[FlagPattern] = [
    FlagPattern(name="flag", regex=r"\bflag\{[A-Za-z0-9_\-]+\}", flags=re.IGNORECASE),
    FlagPattern(name="ctf", regex=r"\bCTF\{[A-Za-z0-9_\-]+\}"),
    FlagPattern(name="generic_braced", regex=r"\b[A-Za-z][A-Za-z0-9_\-]{2,19}\{[A-Za-z0-9_\-]+\}"),
    FlagPattern(name="key", regex=r"\bkey\{.*?\}", flags=re.IGNORECASE),
    FlagPattern(name="SK", regex=r"SK-.*?"),
    FlagPattern(name="flag_assign", regex=r"flag\s*=\s*[A-Za-z0-9_\-]+"),
    FlagPattern(name="key_assign", regex=r"key\s*=\s*[A-Za-z0-9_\-]+"),
    FlagPattern(name="secret_assign", regex=r"secret\s*=\s*[A-Za-z0-9_\-]+"),
]


def compile_patterns(
    patterns: list[FlagPattern],
) -> list[tuple[FlagPattern, re.Pattern[str]]]:
    result: list[tuple[FlagPattern, re.Pattern[str]]] = []
    for p in patterns:
        compiled = re.compile(p.regex, p.flags | re.DOTALL)
        result.append((p, compiled))
    return result


def get_default_compiled() -> list[tuple[FlagPattern, re.Pattern[str]]]:
    return compile_patterns(DEFAULT_PATTERNS)


def match_all(
    text: str | bytes,
    compiled: list[tuple[FlagPattern, re.Pattern[str]]],
) -> list[FlagMatch]:
    if isinstance(text, bytes):
        text = text.decode(errors="ignore")
    matches: list[FlagMatch] = []
    for pattern, regex in compiled:
        for m in regex.finditer(text):
            value = m.group(pattern.group) if pattern.group is not None else m.group(0)
            matches.append(
                FlagMatch(pattern=pattern, value=value, start=m.start(), end=m.end())
            )
    return matches
