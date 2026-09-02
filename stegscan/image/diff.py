from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

from PIL import Image


@dataclass
class DiffResult:
    pixel_offset: int
    channel: str
    values: tuple[int, int]
    significance: float


def diff_images(img1: Image.Image, img2: Image.Image) -> list[DiffResult]:
    if img1.size != img2.size:
        raise ValueError("Images must have the same dimensions")

    if img1.mode not in ("RGB", "RGBA"):
        img1 = img1.convert("RGBA")
    if img2.mode not in ("RGB", "RGBA"):
        img2 = img2.convert("RGBA")

    pixels1 = list(img1.getdata())
    pixels2 = list(img2.getdata())

    channel_names = ["R", "G", "B"]
    if img1.mode == "RGBA" and img2.mode == "RGBA":
        channel_names.append("A")

    results: list[DiffResult] = []

    for idx, (p1, p2) in enumerate(zip(pixels1, pixels2)):
        for ci, ch in enumerate(channel_names):
            v1 = p1[ci]
            v2 = p2[ci]
            if v1 != v2:
                significance = abs(v1 - v2) / 255.0
                results.append(DiffResult(
                    pixel_offset=idx,
                    channel=ch,
                    values=(v1, v2),
                    significance=significance,
                ))

    return results


def diff_stats(img: Image.Image) -> dict:
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGBA")

    channels_data: dict[str, list[int]] = {}
    if img.mode == "RGB":
        r, g, b = img.split()
        channels_data["R"] = list(r.getdata())
        channels_data["G"] = list(g.getdata())
        channels_data["B"] = list(b.getdata())
    elif img.mode == "RGBA":
        r, g, b, a = img.split()
        channels_data["R"] = list(r.getdata())
        channels_data["G"] = list(g.getdata())
        channels_data["B"] = list(b.getdata())
        channels_data["A"] = list(a.getdata())

    lsb_dist: dict[str, dict[int, int]] = {}
    entropy: dict[str, float] = {}
    correlations: dict[str, float] = {}

    for ch_name, ch_data in channels_data.items():
        lsb_counts: Counter[int] = Counter()
        for v in ch_data:
            lsb_counts[v & 1] += 1
        lsb_dist[ch_name] = dict(lsb_counts)

        total = len(ch_data)
        freq: Counter[int] = Counter(ch_data)
        ent = 0.0
        for count in freq.values():
            if count > 0:
                p = count / total
                ent -= p * math.log2(p)
        entropy[ch_name] = ent

    ch_list = list(channels_data.keys())
    for i in range(len(ch_list)):
        for j in range(i + 1, len(ch_list)):
            ch_a = ch_list[i]
            ch_b = ch_list[j]
            data_a = channels_data[ch_a]
            data_b = channels_data[ch_b]
            n = min(len(data_a), len(data_b))
            if n == 0:
                continue
            mean_a = sum(data_a[:n]) / n
            mean_b = sum(data_b[:n]) / n
            cov = sum((data_a[k] - mean_a) * (data_b[k] - mean_b) for k in range(n)) / n
            std_a = math.sqrt(sum((v - mean_a) ** 2 for v in data_a[:n]) / n)
            std_b = math.sqrt(sum((v - mean_b) ** 2 for v in data_b[:n]) / n)
            if std_a > 0 and std_b > 0:
                corr = cov / (std_a * std_b)
            else:
                corr = 0.0
            correlations[f"{ch_a}_{ch_b}"] = corr

    return {
        "lsb_distribution": lsb_dist,
        "entropy": entropy,
        "correlations": correlations,
    }


def detect_lsb_anomaly(img: Image.Image) -> dict:
    stats = diff_stats(img)
    lsb_dist = stats.get("lsb_distribution", {})

    total_pixels = img.size[0] * img.size[1]

    anomaly_score = 0.0
    channel_scores: dict[str, float] = {}

    for ch_name, dist in lsb_dist.items():
        count_0 = dist.get(0, 0)
        count_1 = dist.get(1, 0)
        if total_pixels > 0:
            ratio = abs(count_0 - count_1) / total_pixels
        else:
            ratio = 0.0
        channel_scores[ch_name] = ratio
        anomaly_score += ratio

    num_channels = max(len(lsb_dist), 1)
    anomaly_score /= num_channels

    uniform = anomaly_score < 0.01

    return {
        "lsb_distribution": lsb_dist,
        "anomaly_score": anomaly_score,
        "uniform_distribution_expected": uniform,
    }
