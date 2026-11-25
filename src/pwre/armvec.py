"""Cortex-M 向量表：从映像里认出初始 SP、Reset 与异常/中断入口。"""

from dataclasses import dataclass, field

from .errors import ReError
from .image import Image

EXCEPTIONS = {
    2: "NMI",
    3: "HardFault",
    4: "MemManage",
    5: "BusFault",
    6: "UsageFault",
    11: "SVCall",
    12: "DebugMon",
    14: "PendSV",
    15: "SysTick",
}

SRAM_RANGES = ((0x20000000, 0x30000000), (0x10000000, 0x10010000), (0x30000000, 0x30010000))


@dataclass
class VectorTable:
    base: int
    sp: int
    reset: int
    entries: list[tuple[int, int]] = field(default_factory=list)

    @property
    def irq_handlers(self) -> list[tuple[int, int]]:
        return [(index, value) for index, value in self.entries if index >= 16 and value & 1]

    @property
    def code_span(self) -> tuple[int, int]:
        targets = [value & ~1 for _, value in self.entries if value & 1]
        return (min(targets), max(targets)) if targets else (0, 0)


def _plausible_sp(value: int) -> bool:
    if value == 0 or value & 3:
        return False
    return any(low <= value < high for low, high in SRAM_RANGES) or 0x20000000 <= value < 0x40000000


def find_table(image: Image, base: int | None = None) -> VectorTable:
    """找向量表。规则只有三条：SP 合理、Reset 带 Thumb 位、Reset 落在映像里。"""
    if base is not None:
        candidates = [base]
    else:
        candidates = [segment.addr for segment in image.segments]
    low, high = image.span
    for candidate in candidates:
        if candidate & 3:
            continue
        head = image.read(candidate, 8)
        if not head:
            continue
        sp = int.from_bytes(head[:4], "little")
        reset = int.from_bytes(head[4:8], "little")
        if not _plausible_sp(sp):
            continue
        if not reset & 1:
            continue
        if not low <= (reset & ~1) < high:
            continue
        entries = _entries(image, candidate)
        return VectorTable(candidate, sp, reset, entries)
    raise ReError(
        "没找到 Cortex-M 向量表",
        hint="确认这是 ARM Cortex-M 固件，或用 --base 指定向量表地址",
    )


def _entries(image: Image, base: int, limit: int = 512) -> list[tuple[int, int]]:
    entries = []
    for index in range(limit):
        raw = image.read(base + index * 4, 4)
        if not raw:
            break
        value = int.from_bytes(raw, "little")
        entries.append((index, value))
        # 前 16 个是固定异常，之后一旦遇到不落在代码里的值就停
        if index >= 15 and not (value & 1):
            break
    return entries


def describe(table: VectorTable, image: Image) -> dict:
    low, high = image.span
    exceptions = []
    for index, name in EXCEPTIONS.items():
        value = next((v for i, v in table.entries if i == index), 0)
        if value & 1:
            exceptions.append({"index": index, "name": name, "addr": value & ~1})
    irqs = table.irq_handlers
    code_low, code_high = table.code_span
    return {
        "base": table.base,
        "sp": table.sp,
        "reset": table.reset,
        "exceptions": exceptions,
        "irq_count": len(irqs),
        "irqs": [{"index": index - 16, "addr": value & ~1} for index, value in irqs],
        "code_span": [code_low, code_high],
        "image_span": [low, high],
    }
