from __future__ import annotations

from PIL import Image

from stegscan.core.utils import which
from stegscan.video.frames import (
    FrameInfo,
    analyze_video_frames,
    extract_frames,
)


def test_extract_frames_on_png_graceful(tmp_path) -> None:
    # Without ffmpeg, extract_frames should degrade gracefully
    img = Image.new("RGB", (20, 20), (1, 2, 3))
    path = str(tmp_path / "fake.avi")
    # save as PNG bytes under an .avi name (PIL won't save unknown ext)
    import io as _io
    buf = _io.BytesIO()
    img.save(buf, "PNG")
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    if which("ffmpeg") is None:
        frames = extract_frames(path)
        assert frames is not None
    else:
        extract_frames(path)


def test_analyze_video_frames_graceful(tmp_path) -> None:
    img = Image.new("RGB", (20, 20), (4, 5, 6))
    path = str(tmp_path / "video.mp4")
    import io as _io
    buf = _io.BytesIO()
    img.save(buf, "PNG")
    with open(path, "wb") as f:
        f.write(buf.getvalue())
    results = analyze_video_frames(path, None, True)
    assert isinstance(results, list)


def test_frameinfo_dataclass() -> None:
    fi = FrameInfo(index=0, path="foo.png", timestamp=1.5)
    assert fi.index == 0
    assert fi.path == "foo.png"
    assert fi.timestamp == 1.5
