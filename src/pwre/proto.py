"""报文分析：把一段抓包按帧切开，逐字节看"哪些位恒定、哪些位在变"。

这是猜字段最快的一步：恒定位是协议头/固定参数，变化位才是载荷。
"""

from dataclasses import dataclass


@dataclass
class ByteStat:
    offset: int
    values: list[int]
    constant: bool

    @property
    def sample(self) -> int:
        return self.values[0] if self.values else 0


def split(data: bytes, frame_len: int) -> list[bytes]:
    if frame_len <= 0:
        raise ValueError("frame_len 必须大于 0")
    return [data[offset: offset + frame_len] for offset in range(0, len(data) - frame_len + 1, frame_len)]


def analyze(frames: list[bytes]) -> list[ByteStat]:
    if not frames:
        return []
    width = min(len(frame) for frame in frames)
    stats = []
    for offset in range(width):
        values = sorted({frame[offset] for frame in frames})
        stats.append(ByteStat(offset, values, len(values) == 1))
    return stats


def ranges(stats: list[ByteStat], constant: bool) -> list[tuple[int, int]]:
    """把连续的恒定/变化字节压成区间。"""
    out = []
    start = None
    for stat in stats:
        if stat.constant == constant and start is None:
            start = stat.offset
        elif stat.constant != constant and start is not None:
            out.append((start, stat.offset))
            start = None
    if start is not None:
        out.append((start, len(stats)))
    return out


def hexdump(frame: bytes, limit: int = 16) -> list[str]:
    lines = []
    for offset in range(0, min(len(frame), limit * 16), 16):
        chunk = frame[offset: offset + 16]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {offset:04x}  {chunk.hex(' '):<47}  {text}")
    return lines
