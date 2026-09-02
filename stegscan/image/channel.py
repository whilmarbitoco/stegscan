from __future__ import annotations

from dataclasses import dataclass, field

from PIL import Image

from stegscan.flagfinder.detector import Detection, Detector


@dataclass
class ChannelResult:
    channels: str
    detections: list[Detection] = field(default_factory=list)


def extract_channels(img: Image.Image) -> dict[str, list[int]]:
    if img.mode not in ("RGB", "RGBA", "L"):
        img = img.convert("RGBA")

    result: dict[str, list[int]] = {}

    if img.mode == "L":
        result["L"] = list(img.getdata())
    elif img.mode == "RGB":
        r, g, b = img.split()
        result["R"] = list(r.getdata())
        result["G"] = list(g.getdata())
        result["B"] = list(b.getdata())
    elif img.mode == "RGBA":
        r, g, b, a = img.split()
        result["R"] = list(r.getdata())
        result["G"] = list(g.getdata())
        result["B"] = list(b.getdata())
        result["A"] = list(a.getdata())

    return result


def _xor_channels(a: list[int], b: list[int]) -> bytes:
    length = min(len(a), len(b))
    return bytes(a[i] ^ b[i] for i in range(length))


def analyze_channel_differences(img: Image.Image, detector: Detector) -> list[ChannelResult]:
    channels = extract_channels(img)
    results: list[ChannelResult] = []

    pairs = [("R", "G"), ("R", "B"), ("G", "B")]
    for ch_a, ch_b in pairs:
        if ch_a in channels and ch_b in channels:
            xor_data = _xor_channels(channels[ch_a], channels[ch_b])
            detections = detector.scan_bytes(xor_data)
            if detections:
                results.append(ChannelResult(
                    channels=f"{ch_a}^{ch_b}",
                    detections=detections,
                ))

    if "A" in channels:
        alpha_data = bytes(channels["A"])
        detections = detector.scan_bytes(alpha_data)
        if detections:
            results.append(ChannelResult(
                channels="A",
                detections=detections,
            ))

    return results
