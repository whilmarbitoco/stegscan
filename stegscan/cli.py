from __future__ import annotations

import argparse
import sys
from pathlib import Path

__version__ = "0.1.0"

TECHNIQUE_MAP: dict[str, str] = {
    "lsb": "image.lsb",
    "bitplane": "image.bitplane",
    "channels": "image.channel",
    "metadata": "core.metadata",
    "unicode": "core.unicode",
    "carving": "core.carving",
    "audio-lsb": "audio.lsb",
    "spectrogram": "audio.spectrogram",
    "dtmf": "audio.dtmf",
    "pdf": "document.pdf",
    "video": "video.frames",
}


def _run_technique(filepath: str, technique: str, flag_regex: str | None, quiet: bool) -> list[dict]:
    from stegscan.core.io import FileInfo

    fi = FileInfo.from_path(filepath)
    data = fi.data

    if technique == "lsb":
        from stegscan.flagfinder.cascade import run_cascade
        from stegscan.flagfinder.detector import Detector
        from stegscan.image.lsb import lsb_extract_rgb

        try:
            from PIL import Image as PILImage
            img: PILImage.Image = PILImage.open(filepath)
            if img.mode != "RGB":
                img = img.convert("RGB")
            pixels = list(img.getdata())
            extracted = lsb_extract_rgb(pixels)
            detector = Detector(flag_regex=flag_regex)
            detections = run_cascade(extracted, detector)
            return [{
                "module": "image.lsb",
                "type": "flag",
                "detections": detections,
                "detail": "LSB extraction from RGB channels",
                "confidence": max((d.confidence for d in detections), default=0.0),
            }]
        except ImportError:
            return [{
                    "module": "image.lsb", "type": "anomaly",
                    "detections": [], "detail": "PIL not available",
                    "confidence": 0.0,
                }]

    if technique == "bitplane":
        from stegscan.flagfinder.detector import Detector
        from stegscan.image.bitplane import analyze_bitplanes

        try:
            from PIL import Image
            detector = Detector(flag_regex=flag_regex)
            img = Image.open(filepath)
            bp_results = analyze_bitplanes(img, detector, flag_regex)
            return [{
                "module": "image.bitplane",
                "type": "bitplane",
                "detections": bp.detections,
                "detail": f"Plane {bp.plane} ch={bp.channel}",
                "confidence": max((d.confidence for d in bp.detections), default=0.0),
            } for bp in bp_results]
        except ImportError:
            return [{
                    "module": "image.bitplane", "type": "anomaly",
                    "detections": [], "detail": "PIL not available",
                    "confidence": 0.0,
                }]

    if technique == "channels":
        from stegscan.flagfinder.detector import Detector
        from stegscan.image.channel import analyze_channel_differences

        try:
            from PIL import Image
            detector = Detector(flag_regex=flag_regex)
            img = Image.open(filepath)
            ch_results = analyze_channel_differences(img, detector)
            return [{
                "module": "image.channel",
                "type": "channel_diff",
                "detections": cr.detections,
                "detail": f"Channels: {cr.channels}",
                "confidence": max((d.confidence for d in cr.detections), default=0.0),
            } for cr in ch_results]
        except ImportError:
            return [{
                    "module": "image.channel", "type": "anomaly",
                    "detections": [], "detail": "PIL not available",
                    "confidence": 0.0,
                }]

    if technique == "metadata":
        from stegscan.core.metadata import all_metadata
        from stegscan.flagfinder.detector import Detector

        meta = all_metadata(str(fi.path))
        detector = Detector(flag_regex=flag_regex)
        if meta:
            meta_bytes = str(meta).encode("utf-8", errors="replace")
            detections = detector.scan_bytes(meta_bytes)
            return [{
                "module": "core.metadata",
                "type": "metadata",
                "detections": detections,
                "detail": str(meta)[:500],
                "confidence": max((d.confidence for d in detections), default=0.3),
            }]
        return []

    if technique == "unicode":
        from stegscan.core.unicode import all_unicode_strings
        from stegscan.flagfinder.detector import Detector

        detector = Detector(flag_regex=flag_regex)
        unicode_strs = all_unicode_strings(data)
        results: list[dict] = []
        for ustr in unicode_strs:
            detections = detector.scan_bytes(ustr.encode("utf-8", errors="replace"))
            if detections:
                results.append({
                    "module": "core.unicode",
                    "type": "text",
                    "detections": detections,
                    "detail": ustr[:200],
                    "confidence": max(d.confidence for d in detections),
                })
        return results

    if technique == "carving":
        from stegscan.core.file import carve_embedded_files
        from stegscan.flagfinder.cascade import run_cascade
        from stegscan.flagfinder.detector import Detector

        detector = Detector(flag_regex=flag_regex)
        results2: list[dict] = []
        try:
            embedded = carve_embedded_files(data)
            for emb in embedded:
                emb_data = getattr(emb, "data", b"")
                detections = run_cascade(emb_data, detector) if emb_data else []
                results2.append({
                    "module": "core.carving",
                    "type": "embedded",
                    "detections": detections,
                    "detail": f"Embedded {getattr(emb, 'name', 'file')}",
                    "confidence": max((d.confidence for d in detections), default=0.6),
                })
        except Exception:
            pass
        return results2

    if technique == "audio-lsb":
        from stegscan.audio.lsb import extract_audio_lsb
        from stegscan.flagfinder.cascade import run_cascade
        from stegscan.flagfinder.detector import Detector

        detector = Detector(flag_regex=flag_regex)
        audio_raw = extract_audio_lsb(data)
        if audio_raw:
            audio_flags = run_cascade(audio_raw, detector)
            return [{
                "module": "audio.lsb",
                "type": "flag",
                "detections": audio_flags,
                "detail": "Audio LSB extraction",
                "confidence": max((d.confidence for d in audio_flags), default=0.0),
            }]
        return []

    if technique == "spectrogram":
        from stegscan.audio.spectrogram import analyze_spectrogram

        spec_results = analyze_spectrogram(data)
        return spec_results or []

    if technique == "dtmf":
        from stegscan.audio.dtmf import detect_dtmf

        dtmf_results = detect_dtmf(data)
        return [
            {
                "module": "audio.dtmf",
                "type": "dtmf",
                "detections": [],
                "detail": f"DTMF digit {r.digit} at {r.start_time:.2f}s-{r.end_time:.2f}s",
                "confidence": r.confidence,
            }
            for r in dtmf_results
        ]

    if technique == "pdf":
        from stegscan.document.pdf import analyze_pdf

        return analyze_pdf(filepath, flag_regex, quiet)

    if technique == "video":
        from stegscan.video.frames import analyze_video_frames

        return analyze_video_frames(filepath, flag_regex, quiet)

    return []


def _enable_ansi() -> None:
    """Enable ANSI/VT escape-sequence processing on Windows consoles."""
    import ctypes
    if getattr(sys, "platform", "").startswith(("win", "cygwin")):
        try:
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    _enable_ansi()
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8")
            except Exception:
                pass
    parser = argparse.ArgumentParser(
        prog="stegscan",
        description=(
            "Steganography analysis tool for CTF challenges.\n"
            "Automatically detects the file type and tries many common "
            "steganography 'hiding' techniques, then reports any flag-like "
            "text it finds."
        ),
        epilog=(
            "EXAMPLES\n"
            "  stegscan image.png             Scan a file using all techniques\n"
            "  stegscan file.png -v          Scan with live progress messages\n"
            "  stegscan file.png -r 'FLAG{.*?}'   Only look for FLAG{...} text\n"
            "  stegscan file.png -t lsb       Only check the least-significant-bit trick\n"
            "  stegscan file.png -o out/      Save report.md and results.json to out/\n"
            "  stegscan file.png -d 2         Try at most 2 decode layers (faster)\n"
            "  stegscan file.wav -t spectrogram   Render a WAV as an image (waterfall)\n\n"
            "TECHNIQUES (-t)\n"
            "  lsb          Data hidden in the lowest bits of image pixels\n"
            "  bitplane     Data hidden in a single color-bit plane of an image\n"
            "  channels     Compare the red/green/blue channels of an image\n"
            "  metadata     Text stored in image/file metadata comments (EXIF, tEXt, ...)\n"
            "  unicode      Text hidden in invisible unicode characters\n"
            "  carving      Raw byte carving for embedded files/chunks\n"
            "  audio-lsb    Data hidden in the lowest bits of WAV audio samples\n"
            "  spectrogram  Data hidden as a visual image inside a WAV's frequencies\n"
            "  dtmf         Phone-tone (DTMF) digits hidden in audio\n"
            "  pdf          Text hidden inside PDF streams/objects\n"
            "  video        Text hidden in video frames/metadata (needs ffmpeg)\n\n"
            "Tip: if you know the flag prefix, pass -r to reduce false positives, e.g.\n"
            "  -r 'IceCTF{.*?}'\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "file",
        help="Path to the file you want to analyze (PNG, JPG, WAV, PDF, video, ...)",
    )
    parser.add_argument(
        "-r",
        "--regex",
        default=None,
        metavar="REGEX",
        help=(
            "Custom flag pattern written as a regular expression. "
            "Examples: 'FLAG{.*?}', 'IceCTF{.*?}'. "
            "(Default: many common CTF patterns are checked automatically)"
        ),
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Only print the final results, without progress/discovery messages",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print live progress to stderr as each technique runs (helps on large files)",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default=None,
        metavar="DIR",
        help=(
            "Directory where report.md and results.json are saved. "
            "(Default: a temporary folder)"
        ),
    )
    parser.add_argument(
        "-d",
        "--depth",
        type=int,
        default=4,
        metavar="N",
        help=(
            "How many layers of encoding to try to undo (base64, rot13, hex, ...). "
            "Higher values find more nested flags but are slower. (Default: 4)"
        ),
    )
    parser.add_argument(
        "-t",
        "--technique",
        default=None,
        metavar="TECHNIQUE",
        help=(
            "Run only one technique instead of everything. "
            f"Valid values: {', '.join(TECHNIQUE_MAP.keys())}. "
            "(Default: auto-detect and try all)"
        ),
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"stegscan {__version__}",
        help="Show the program version and exit",
    )

    args = parser.parse_args(argv)

    filepath = args.file
    if not Path(filepath).is_file():
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        return 2

    try:
        if args.technique:
            if args.technique not in TECHNIQUE_MAP:
                print(f"Error: Unknown technique '{args.technique}'", file=sys.stderr)
                print(f"Available: {', '.join(TECHNIQUE_MAP.keys())}", file=sys.stderr)
                return 2
            results = _run_technique(filepath, args.technique, args.regex, args.quiet)
            all_flags = []
            for r in results:
                all_flags.extend(r.get("detections", []))
            from stegscan.auto_scan import ScanResult, print_summary

            elapsed = 0.0
            scan_result = ScanResult(
                filepath=filepath,
                results=results,
                flags_found=all_flags,
                total_detections=sum(len(r.get("detections", [])) for r in results),
                elapsed_seconds=elapsed,
            )
            print(print_summary(scan_result))
            return 0 if all_flags else 1
        else:
            from stegscan.auto_scan import print_summary, scan

            result = scan(
                filepath,
                flag_regex=args.regex,
                quiet=args.quiet,
                output_dir=args.output_dir,
                max_depth=args.depth,
                verbose=args.verbose,
            )
            print(print_summary(result))
            return 0 if result.flags_found else 1
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
