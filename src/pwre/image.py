"""统一映像模型：所有固件格式先变成段表，后面的分析只认段表。"""

from dataclasses import dataclass, field


@dataclass
class Segment:
    addr: int
    data: bytes

    @property
    def end(self) -> int:
        return self.addr + len(self.data)


@dataclass
class Image:
    segments: list[Segment] = field(default_factory=list)
    start: int | None = None
    records: int = 0
    errors: list[str] = field(default_factory=list)

    def __post_init__(self):
        self.normalize()

    def normalize(self) -> None:
        """按地址排序合并连续段；重叠且内容不一致就记错误——不悄悄覆盖。"""
        if not self.segments:
            return
        ordered = sorted(self.segments, key=lambda segment: segment.addr)
        merged = [ordered[0]]
        for segment in ordered[1:]:
            last = merged[-1]
            if segment.addr > last.end:
                merged.append(segment)
                continue
            overlap_end = min(last.end, segment.end)
            mine = last.data[segment.addr - last.addr: overlap_end - last.addr]
            theirs = segment.data[: overlap_end - segment.addr]
            if mine != theirs:
                self.errors.append(
                    f"段重叠且内容不同：0x{segment.addr:08x} 起 {overlap_end - segment.addr} 字节"
                )
                merged.append(segment)
                continue
            tail = segment.data[overlap_end - segment.addr:]
            merged[-1] = Segment(last.addr, last.data + tail)
        self.segments = merged

    @property
    def span(self) -> tuple[int, int]:
        if not self.segments:
            return (0, 0)
        return (self.segments[0].addr, self.segments[-1].end)

    @property
    def total(self) -> int:
        return sum(len(segment.data) for segment in self.segments)

    def read(self, addr: int, size: int) -> bytes | None:
        """跨段读；中间有洞就返回 None，不编造数据。"""
        out = bytearray()
        cursor = addr
        while len(out) < size:
            for segment in self.segments:
                if segment.addr <= cursor < segment.end:
                    take = min(size - len(out), segment.end - cursor)
                    out += segment.data[cursor - segment.addr: cursor - segment.addr + take]
                    cursor += take
                    break
            else:
                return None
        return bytes(out)

    def to_flat(self, fill: int = 0xFF) -> tuple[int, bytes]:
        """拼成一段连续内存，空洞填 fill。反汇编引擎只吃这种。"""
        if not self.segments:
            return (0, b"")
        base, end = self.span
        buffer = bytearray([fill]) * (end - base)
        for segment in self.segments:
            offset = segment.addr - base
            buffer[offset: offset + len(segment.data)] = segment.data
        return base, bytes(buffer)

    def gaps(self) -> list[tuple[int, int]]:
        holes = []
        for previous, current in zip(self.segments, self.segments[1:]):
            if current.addr > previous.end:
                holes.append((previous.end, current.addr))
        return holes
