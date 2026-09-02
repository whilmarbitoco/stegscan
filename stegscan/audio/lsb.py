from __future__ import annotations

import struct


def _parse_wav_header(data: bytes) -> tuple[int, int, int, int, int]:
    if len(data) < 44:
        raise ValueError("Data too short to be a WAV file")

    if data[:4] != b"RIFF":
        raise ValueError("Not a RIFF file")

    if data[8:12] != b"WAVE":
        raise ValueError("Not a WAVE file")

    fmt_pos = data.find(b"fmt ")
    if fmt_pos < 0:
        raise ValueError("No fmt chunk found")

    struct.unpack_from("<H", data, fmt_pos + 8)[0]
    num_channels = struct.unpack_from("<H", data, fmt_pos + 10)[0]
    sample_rate = struct.unpack_from("<I", data, fmt_pos + 12)[0]
    bits_per_sample = struct.unpack_from("<H", data, fmt_pos + 22)[0]

    data_pos = data.find(b"data")
    if data_pos < 0:
        raise ValueError("No data chunk found")

    data_size = struct.unpack_from("<I", data, data_pos + 4)[0]
    audio_data_start = data_pos + 8

    return audio_data_start, data_size, num_channels, bits_per_sample, sample_rate


def extract_audio_lsb(data: bytes, bits_per_sample: int = 1, channels: int = 1, sample_width: int = 2) -> bytes:
    audio_start, data_size, file_channels, file_bps, _ = _parse_wav_header(data)

    if channels <= 1:
        channels = file_channels
    if sample_width <= 0:
        sample_width = max(file_bps // 8, 1)

    sample_data = data[audio_start:audio_start + data_size]
    return extract_raw_lsb(sample_data, bits_per_sample, channels, sample_width)


def extract_raw_lsb(samples: bytes, bits_per_sample: int = 1, channels: int = 1, sample_width: int = 2) -> bytes:
    if sample_width == 2:
        pass
    elif sample_width == 4:
        pass
    elif sample_width == 1:
        pass
    else:
        pass

    bytes_per_sample = sample_width
    bytes_per_frame = bytes_per_sample * channels
    if bytes_per_frame == 0:
        return b""

    num_frames = len(samples) // bytes_per_frame
    lsb_bits: list[int] = []

    for frame_idx in range(num_frames):
        frame_offset = frame_idx * bytes_per_frame
        for ch in range(channels):
            sample_offset = frame_offset + ch * bytes_per_sample
            if sample_offset + bytes_per_sample > len(samples):
                break
            if sample_width == 2:
                sample_val = struct.unpack_from("<h", samples, sample_offset)[0]
            elif sample_width == 4:
                sample_val = struct.unpack_from("<i", samples, sample_offset)[0]
            elif sample_width == 1:
                sample_val = struct.unpack_from("<b", samples, sample_offset)[0]
            else:
                sample_val = 0

            for bit in range(bits_per_sample):
                lsb_bits.append((sample_val >> bit) & 1)

    result = bytearray()
    for i in range(0, len(lsb_bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte |= lsb_bits[i + j] << j
        result.append(byte)

    return bytes(result)
