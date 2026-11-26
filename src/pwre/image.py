"""统一映像模型：所有固件格式先变成段表，后面的分析只认段表。"""

from dataclasses import dataclass, field

from .errors import ReError

# 展开成连续内存的上限：洞太大会把内存吃光（0x08000000 与 0x20000000 之间就有 384 MB）
MAX_FLAT = 64 << 20


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
        """按地址排序合并连续段；重叠且内容不一致就记错误，并且**保留先出现的段**。

        重叠冲突时两段都留会让 total 与 span 自相矛盾，read() 和 to_flat() 还会
        给出不同的值；这里统一成"先到先得"，被覆盖的部分丢弃并记一条错误。
        """
        if not self.segments:
            return
        ordered = sorted(self.segments, key=lambda segment: segment.addr)
        merged: list[list] = []  # [addr, bytearray]
        for segment in ordered:
            if not merged:
                merged.append([segment.addr, bytearray(segment.data)])
                continue
            last_addr, last_buf = merged[-1]
            last_end = last_addr + len(last_buf)
            if segment.addr > last_end:
                merged.append([segment.addr, bytearray(segment.data)])
                continue
            overlap_end = min(last_end, segment.end)
            offset = segment.addr - last_addr
            mine = bytes(last_buf[offset: offset + (overlap_end - segment.addr)])
            theirs = segment.data[: overlap_end - segment.addr]
            if mine != theirs:
                self.errors.append(
                    f"段重叠且内容不同：0x{segment.addr:08x} 起 {overlap_end - segment.addr} 字节（保留先出现的段）"
                )
            tail = segment.data[overlap_end - segment.addr:]
            if tail:
                last_buf.extend(tail)
        self.segments = [Segment(addr, bytes(buf)) for addr, buf in merged]

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
        """拼成一段连续内存，空洞填 fill。反汇编引擎只吃这种。

        洞太大就报错而不是把内存吃光——`--fill` 也救不了 384 MB 的空洞。
        """
        if not self.segments:
            return (0, b"")
        base, end = self.span
        size = end - base
        if size > MAX_FLAT:
            raise ReError(
                f"展开成连续内存要 {size:,} 字节（上限 {MAX_FLAT:,}），段之间空洞太大",
                hint="先把空洞拆开处理，或只分析包含目标代码的那一段",
            )
        buffer = bytearray([fill]) * size
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
