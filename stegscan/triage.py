from __future__ import annotations

from stegscan.core.file import carve_embedded_files
from stegscan.core.io import FileInfo
from stegscan.core.metadata import all_metadata
from stegscan.core.polyglot import detect_polyglot
from stegscan.core.unicode import all_unicode_strings
from stegscan.flagfinder.cascade import run_cascade
from stegscan.flagfinder.detector import Detection, Detector


def triage(
    filepath: str,
    flag_regex: str | None = None,
    quiet: bool = True,
) -> list[dict]:
    fi = FileInfo.from_path(filepath)
    data = fi.data
    mime = fi.mime

    detector = Detector(flag_regex=flag_regex)
    results: list[dict] = []

    detections = run_cascade(data, detector)
    if detections:
        results.append({
            "module": "triage",
            "type": "flag",
            "detections": detections,
            "detail": f"Universal cascade scan on {fi.size} bytes",
            "confidence": max(d.confidence for d in detections),
        })

    try:
        embedded = carve_embedded_files(data)
        if embedded:
            for emb in embedded:
                emb_detections: list[Detection] = []
                if hasattr(emb, "data") and emb.data:
                    emb_detections = run_cascade(emb.data, detector)
                detail = f"Embedded {getattr(emb, 'name', 'file')} at offset {getattr(emb, 'offset', 0)}"
                results.append({
                    "module": "triage",
                    "type": "embedded",
                    "detections": emb_detections,
                    "detail": detail,
                    "confidence": max((d.confidence for d in emb_detections), default=0.6),
                })
    except Exception:
        pass

    try:
        unicode_strings = all_unicode_strings(data)
        for ustr in unicode_strings:
            u_detections = detector.scan_bytes(ustr.encode("utf-8", errors="replace"))
            if u_detections:
                results.append({
                    "module": "triage",
                    "type": "text",
                    "detections": u_detections,
                    "detail": f"Unicode string: {ustr[:200]}",
                    "confidence": max(d.confidence for d in u_detections),
                })
    except Exception:
        pass

    try:
        polyglots = detect_polyglot(data)
        for pg in polyglots:
            detail = f"Polyglot: {pg.format}" if hasattr(pg, "format") else "Polyglot detected"
            results.append({
                "module": "triage",
                "type": "anomaly",
                "detections": [],
                "detail": detail,
                "confidence": getattr(pg, "confidence", 0.5),
            })
    except Exception:
        pass

    try:
        meta = all_metadata(str(fi.path))
        if meta:
            meta_bytes = str(meta).encode("utf-8", errors="replace")
            meta_detections = detector.scan_bytes(meta_bytes)
            results.append({
                "module": "triage",
                "type": "metadata",
                "detections": meta_detections,
                "detail": f"Metadata: {str(meta)[:500]}",
                "confidence": max((d.confidence for d in meta_detections), default=0.3),
            })
    except Exception:
        pass

    if mime.startswith("image/png"):
        try:
            from stegscan.image.png import analyze_png
            png_results = analyze_png(filepath, flag_regex, quiet)
            for r in png_results:
                r.setdefault("module", "image.png")
                results.append(r)
        except Exception:
            pass

    if mime.startswith("image/jpeg"):
        try:
            from stegscan.image.jpeg import analyze_jpeg
            jpeg_results = analyze_jpeg(filepath, flag_regex, quiet)
            for r in jpeg_results:
                r.setdefault("module", "image.jpeg")
                results.append(r)
        except Exception:
            pass

    if mime in ("audio/wav", "audio/mpeg"):
        try:
            from stegscan.audio.lsb import extract_audio_lsb
            audio_raw = extract_audio_lsb(data)
            if audio_raw:
                audio_detections = run_cascade(audio_raw, detector)
                if audio_detections:
                    results.append({
                        "module": "audio.lsb",
                        "type": "flag",
                        "detections": audio_detections,
                        "detail": "Audio LSB extraction",
                        "confidence": max(d.confidence for d in audio_detections),
                    })
        except Exception:
            pass
        try:
            from stegscan.audio.spectrogram import analyze_spectrogram
            spec_results = analyze_spectrogram(data)
            if spec_results:
                for r in spec_results:
                    r.setdefault("module", "audio.spectrogram")
                    results.append(r)
        except Exception:
            pass
        try:
            from stegscan.audio.dtmf import detect_dtmf
            dtmf_results = detect_dtmf(data)
            if dtmf_results:
                for dr in dtmf_results:
                    results.append({
                        "module": "audio.dtmf",
                        "type": "dtmf",
                        "detections": [],
                        "detail": f"DTMF digit {dr.digit} at {dr.start_time:.2f}s-{dr.end_time:.2f}s",
                        "confidence": dr.confidence,
                    })
        except Exception:
            pass

    if mime.startswith("video/"):
        try:
            from stegscan.video.frames import analyze_video_frames
            video_results = analyze_video_frames(filepath, flag_regex, quiet)
            results.extend(video_results)
        except Exception:
            pass

    if mime == "application/pdf":
        try:
            from stegscan.document.pdf import analyze_pdf
            pdf_results = analyze_pdf(filepath, flag_regex, quiet)
            results.extend(pdf_results)
        except Exception:
            pass

    return results
