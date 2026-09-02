# stegscan

A Python CLI tool for steganography analysis in CTF competitions. It auto-detects
a file's format, applies format-specific stego techniques, runs encoding-aware flag
detection with recursive decode cascades, and produces a consolidated report.

## Features

- **Auto-detection** of file type (PNG, JPEG, WAV, PDF, video, ...) via magic bytes
- **Image** techniques: LSB extraction, bitplane analysis, channel comparison,
  image diffing, PNG chunk / JPEG marker carving
- **Audio** techniques: LSB extraction, spectrogram rendering, DTMF tone decoding
- **Document** techniques: PDF stream/object and metadata analysis
- **Video** techniques: frame extraction and metadata (requires `ffmpeg`/`ffprobe`)
- **Encoding-aware flag detection**: base64, rot13, hex, base32, and single-byte XOR
  brute-force, with recursive decode cascades
- **Custom flag formats** via `-r/--regex`, e.g. `-r 'IceCTF{.*?}'`
- **Verbose** progress output (`-v`) and **colorized** results via `rich`
- **Report generation**: writes `results.json` and `report.md` to an output directory

## Requirements

- Python 3.11+
- See `requirements.txt` (Pillow, numpy, pyzbar, rich, scipy, matplotlib)
- Optional: `ffmpeg` / `ffprobe` for video frame analysis and metadata

Install dependencies:

```
python -m pip install -r requirements.txt
```

## Usage

```
python -m stegscan.cli <file> [options]
```

### Options

| Flag | Description |
|------|-------------|
| `-r, --regex REGEX` | Custom flag pattern (e.g. `-r 'picoCTF{.*?}'`) |
| `-q, --quiet` | Suppress progress/discovery output |
| `-v, --verbose` | Print live progress to stderr as techniques run |
| `-o, --output-dir DIR` | Save `report.md` and `results.json` to DIR |
| `-d, --depth N` | Max decode-cascade depth (default 4) |
| `-t, --technique TECH` | Run only a single technique |
| `-V, --version` | Show the program version |
| `-h, --help` | Show help |

### Examples

```
python -m stegscan.cli image.png
python -m stegscan.cli file.png -r 'picoCTF{.*?}'
python -m stegscan.cli file.png -t lsb
python -m stegscan.cli file.wav -t spectrogram
python -m stegscan.cli file.png -v -o out/
python -m stegscan.cli file.pdf -r 'picoCTF{[A-Za-z0-9_!]}'
```

### Techniques (`-t`)

- `lsb` — least-significant-bit image encoding
- `bitplane` — single color-bit plane extraction
- `channels` — per-channel comparison
- `metadata` — EXIF / tEXt / IPTC / XMP metadata
- `unicode` — hidden unicode / homoglyph text
- `carving` — raw byte carving of embedded files/chunks
- `audio-lsb` — LSB in WAV samples
- `spectrogram` — render audio as a waterfall image
- `dtmf` — phone-tone (DTMF) digit decoding
- `pdf` — PDF streams/objects and metadata
- `video` — video frames/metadata (needs ffmpeg)

## Project Layout

```
stegscan/
  core/         file/io/magic, carving, metadata, polyglot, unicode, encoding utils
  flagfinder/   flag patterns, detector, decode cascade, XOR brute-force
  image/        png, jpeg, lsb, bitplane, channel, diff
  audio/        lsb, spectrogram, dtmf
  video/        frame extraction
  document/     pdf
  triage.py     format dispatch + technique orchestration
  auto_scan.py  high-level scan() + summary/report rendering
  cli.py        argparse CLI
tests/          pytest suite + synthetic CTF challenge builder
```

## Tests

```
python -m pytest tests/ -q
python -m pytest tests/ -q --cov=stegscan --cov-report=term
```

## Notes / Known Limitations

- Video frame analysis requires `ffmpeg`/`ffprobe`; missing tools degrade gracefully.
- pyzbar (QR detection in spectrograms) needs a system zbar DLL; if unavailable it
  is skipped without breaking the rest of the analysis.
- Decode-cascade and XOR brute-force passes are capped on large opaque files to keep
  scans within reasonable time.
