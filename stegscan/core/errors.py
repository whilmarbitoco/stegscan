from __future__ import annotations


class StegScanError(Exception):
    """Base exception for stegscan."""


class FileFormatError(StegScanError):
    """File format could not be detected or is unsupported."""


class DecodeError(StegScanError):
    """A decode step failed."""


class CRCError(StegScanError):
    """CRC check failed."""


class ToolNotFoundError(StegScanError):
    """An external tool probe failed to find the binary."""


class FlagFound(StegScanError):
    """Raised to short-circuit when a flag is discovered."""

    def __init__(self, flag: str, source: str, confidence: float) -> None:
        super().__init__(flag)
        self.flag = flag
        self.source = source
        self.confidence = confidence
