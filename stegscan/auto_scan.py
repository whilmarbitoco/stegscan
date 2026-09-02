from __future__ import annotations

import io
import json
import os
import time
from dataclasses import dataclass, field

from stegscan.flagfinder.detector import Detection
from stegscan.triage import triage


@dataclass
class ScanResult:
    filepath: str
    results: list[dict]
    flags_found: list[Detection]
    total_detections: int
    elapsed_seconds: float
    errors: list[str] = field(default_factory=list)


def _deduplicate_flags(flags: list[Detection]) -> list[Detection]:
    best: dict[str, Detection] = {}
    for flag in flags:
        key = flag.flag
        if key not in best or flag.confidence > best[key].confidence:
            best[key] = flag
    return sorted(best.values(), key=lambda d: d.confidence, reverse=True)


def _write_results_json(output_dir: str, result: ScanResult) -> None:
    data = {
        "filepath": result.filepath,
        "elapsed_seconds": result.elapsed_seconds,
        "total_detections": result.total_detections,
        "flags_found": [
            {
                "flag": f.flag,
                "source": f.source,
                "confidence": f.confidence,
                "decode_path": f.decode_path,
            }
            for f in result.flags_found
        ],
        "results": [
            {
                "module": r.get("module", "unknown"),
                "type": r.get("type", "unknown"),
                "detail": r.get("detail", ""),
                "confidence": r.get("confidence", 0.0),
                "detection_count": len(r.get("detections", [])),
            }
            for r in result.results
        ],
        "errors": result.errors,
    }
    path = os.path.join(output_dir, "results.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def _write_report_md(output_dir: str, result: ScanResult) -> None:
    lines: list[str] = []
    lines.append("# StegScan Report")
    lines.append("")
    lines.append(f"**File:** `{result.filepath}`")
    lines.append(f"**Scan time:** {result.elapsed_seconds:.2f}s")
    lines.append(f"**Total detections:** {result.total_detections}")
    lines.append("")
    if result.flags_found:
        lines.append("## Flags Found")
        lines.append("")
        for flag in result.flags_found:
            lines.append(f"- `{flag.flag}` (confidence: {flag.confidence:.2f}, source: {flag.source})")
        lines.append("")
    lines.append("## All Results")
    lines.append("")
    for r in result.results:
        module = r.get("module", "unknown")
        rtype = r.get("type", "unknown")
        detail = r.get("detail", "")
        conf = r.get("confidence", 0.0)
        det_count = len(r.get("detections", []))
        lines.append(f"### [{module}] {rtype} (confidence: {conf:.2f}, detections: {det_count})")
        lines.append("")
        lines.append(f"{detail}")
        lines.append("")
    if result.errors:
        lines.append("## Errors")
        lines.append("")
        for err in result.errors:
            lines.append(f"- {err}")
        lines.append("")
    path = os.path.join(output_dir, "report.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def scan(
    filepath: str,
    flag_regex: str | None = None,
    quiet: bool = True,
    output_dir: str | None = None,
    max_depth: int = 4,
) -> ScanResult:
    start = time.monotonic()
    errors: list[str] = []
    results: list[dict] = []

    try:
        results = triage(filepath, flag_regex, quiet)
    except Exception as exc:
        errors.append(f"Triage error: {exc}")

    all_flags: list[Detection] = []
    for r in results:
        detections = r.get("detections", [])
        if detections:
            all_flags.extend(detections)

    deduped_flags = _deduplicate_flags(all_flags)
    total_detections = sum(len(r.get("detections", [])) for r in results)
    elapsed = time.monotonic() - start

    scan_result = ScanResult(
        filepath=filepath,
        results=results,
        flags_found=deduped_flags,
        total_detections=total_detections,
        elapsed_seconds=elapsed,
        errors=errors,
    )

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        try:
            _write_results_json(output_dir, scan_result)
        except Exception as exc:
            errors.append(f"Failed to write results.json: {exc}")
        try:
            _write_report_md(output_dir, scan_result)
        except Exception as exc:
            errors.append(f"Failed to write report.md: {exc}")

    return scan_result


def print_summary(result: ScanResult) -> str:
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.text import Text

        console = Console(file=io.StringIO(), record=True, width=100)
        table = Table(title="StegScan Results", show_header=True, header_style="bold cyan")
        table.add_column("Category", style="dim")
        table.add_column("Value")

        table.add_row("File", result.filepath)
        table.add_row("Scan time", f"{result.elapsed_seconds:.2f}s")
        table.add_row("Total detections", str(result.total_detections))
        table.add_row("Techniques applied", str(len(result.results)))

        if result.flags_found:
            for flag in result.flags_found:
                text = Text(flag.flag, style="bold red")
                table.add_row("FLAG", text)
        else:
            table.add_row("Flags", Text("None found", style="yellow"))

        type_counts: dict[str, int] = {}
        for r in result.results:
            rtype = r.get("type", "unknown")
            type_counts[rtype] = type_counts.get(rtype, 0) + 1
        for rtype, count in sorted(type_counts.items()):
            table.add_row(f"  {rtype}", str(count))

        console.print(table)
        return console.export_text()
    except ImportError:
        lines: list[str] = []
        lines.append("=" * 60)
        lines.append("StegScan Results")
        lines.append("=" * 60)
        lines.append(f"File:           {result.filepath}")
        lines.append(f"Scan time:      {result.elapsed_seconds:.2f}s")
        lines.append(f"Total detects:  {result.total_detections}")
        lines.append(f"Techniques:     {len(result.results)}")
        lines.append("-" * 60)
        if result.flags_found:
            for flag in result.flags_found:
                lines.append(f"  *** FLAG: {flag.flag} (conf={flag.confidence:.2f}) ***")
        else:
            lines.append("  No flags found.")
        lines.append("-" * 60)
        type_counts2: dict[str, int] = {}
        for r in result.results:
            rtype = r.get("type", "unknown")
            type_counts2[rtype] = type_counts2.get(rtype, 0) + 1
        for rtype, count in sorted(type_counts2.items()):
            lines.append(f"  {rtype}: {count}")
        lines.append("=" * 60)
        return "\n".join(lines)
