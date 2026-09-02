from __future__ import annotations

import base64
import codecs
import re
from dataclasses import dataclass, field

from stegscan.flagfinder.patterns import (
    FlagPattern,
    compile_patterns,
    get_default_compiled,
)


@dataclass
class Detection:
    flag: str
    source: str
    confidence: float
    decode_path: list[str] = field(default_factory=list)


class Detector:
    def __init__(
        self,
        flag_regex: str | None = None,
        pattern_overrides: list[FlagPattern] | None = None,
    ) -> None:
        self._custom_regex: re.Pattern[str] | None = None
        if flag_regex is not None:
            self._custom_regex = re.compile(flag_regex, re.DOTALL)
        if pattern_overrides is not None:
            self._compiled = compile_patterns(pattern_overrides)
        else:
            self._compiled = get_default_compiled()

    def _match(
        self,
        text: str,
        source: str,
        confidence: float,
        decode_path: list[str],
    ) -> list[Detection]:
        results: list[Detection] = []
        for pattern, regex in self._compiled:
            for m in regex.finditer(text):
                value = m.group(pattern.group) if pattern.group is not None else m.group(0)
                results.append(
                    Detection(
                        flag=value,
                        source=source,
                        confidence=confidence,
                        decode_path=list(decode_path),
                    )
                )
        if self._custom_regex is not None:
            for m in self._custom_regex.finditer(text):
                results.append(
                    Detection(
                        flag=m.group(0),
                        source=source,
                        confidence=confidence,
                        decode_path=list(decode_path),
                    )
                )
        return results

    def scan_bytes(self, data: bytes) -> list[Detection]:
        all_detections: list[Detection] = []
        text = data.decode(errors="ignore")
        all_detections.extend(self._match(text, "raw", 1.0, []))

        try:
            b64_text = base64.b64decode(data, validate=False)
            all_detections.extend(
                self._match(b64_text.decode(errors="ignore"), "base64", 0.95, ["base64"])
            )
        except Exception:
            pass

        try:
            rot13_text = codecs.decode(text, "rot_13")
            all_detections.extend(self._match(rot13_text, "rot13", 0.95, ["rot13"]))
        except Exception:
            pass

        try:
            cleaned = re.sub(r"\s+", "", text)
            hex_bytes = bytes.fromhex(cleaned)
            all_detections.extend(
                self._match(hex_bytes.decode(errors="ignore"), "hex", 0.95, ["hex"])
            )
        except Exception:
            pass

        try:
            utf16_text = data.decode("utf-16")
            all_detections.extend(self._match(utf16_text, "utf16", 0.95, ["utf16"]))
        except Exception:
            pass

        seen: dict[str, Detection] = {}
        for d in all_detections:
            if d.flag not in seen or d.confidence > seen[d.flag].confidence:
                seen[d.flag] = d
        return list(seen.values())
