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

SRAM_RANGES = (
    (0x20000000, 0x20100000),  # 主 SRAM（M0/M3/M4 一般不超过 1 MB）
    (0x10000000, 0x10010000),  # CCM / TCM
    (0x30000000, 0x30010000),  # 备份域 SRAM
    (0x24000000, 0x24080000),  # STM32H7 AXI SRAM
)

# 表尾判定：连续这么多个"既不是 0 也不像向量"的字，就当表已经结束、后面是代码
TAIL_RUN = 4
MAX_ENTRIES = 496


@dataclass
class VectorTable:
    base: int
    sp: int
    reset: int
    entries: list[tuple[int, int]] = field(default_factory=list)

    @property
    def irq_handlers(self) -> list[tuple[int, int]]:
        low, high = self.image_span
        rows = []
        for index, value in self.entries:
            if index < 16 or not value & 1:
                continue
            if self.image_span != (0, 0) and not (low <= (value & ~1) < high):
                continue
            rows.append((index, value))
        return rows

    @property
    def code_span(self) -> tuple[int, int]:
        """向量目标的范围。注意：这不是代码范围，只是"向量指向了哪一段"。"""
        low, high = self.image_span
        targets = [
            value & ~1
            for _, value in self.entries
            if value & 1 and (self.image_span == (0, 0) or low <= (value & ~1) < high)
        ]
        return (min(targets), max(targets)) if targets else (0, 0)

    @property
    def common_handler(self) -> tuple[int, int]:
        """出现次数最多的目标地址（通常是编译器的默认处理函数）。"""
        targets = [value & ~1 for _, value in self.entries if value & 1]
        if not targets:
            return (0, 0)
        counts = {}
        for item in targets:
            counts[item] = counts.get(item, 0) + 1
        target = max(counts, key=lambda key: counts[key])
        return (target, counts[target])

    @property
    def reserved(self) -> int:
        """表里保留（值为 0）或指向映像外的槽位数。"""
        low, high = self.image_span
        total = 0
        for index, value in self.entries:
            if index < 16:
                continue
            if value == 0 or not (value & 1) or not (low <= (value & ~1) < high):
                total += 1
        return total

    image_span: tuple[int, int] = (0, 0)


def _plausible_sp(value: int) -> bool:
    if value == 0 or value & 3:
        return False
    return any(low <= value < high for low, high in SRAM_RANGES)


def find_table(image: Image, base: int | None = None) -> VectorTable:
    """找向量表。规则只有三条：SP 合理、Reset 带 Thumb 位、Reset 落在某个段里。"""
    if base is not None:
        candidates = [base]
    else:
        candidates = [segment.addr for segment in image.segments]
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
        # 必须真的落在某个段里；落在段间空洞里的不算
        if image.read(reset & ~1, 2) is None:
            continue
        entries = _entries(image, candidate)
        table = VectorTable(candidate, sp, reset, entries)
        table.image_span = image.span
        return table
    raise ReError(
        "没找到 Cortex-M 向量表",
        hint="确认这是 ARM Cortex-M 固件，或用 --base 指定向量表地址",
    )


def _entries(image: Image, base: int, limit: int = MAX_ENTRIES) -> list[tuple[int, int]]:
    """枚举向量表。

    不能"遇到第一个 0 就停"：PY32 这类器件在 IRQ8 上是保留槽（值为 0），
    真正的处理函数在 IRQ16，一停就把唯一的中断处理漏掉。
    规则改成：0 是保留槽，继续往下读；第一个"非 0 又不像向量"的字才是表尾
    （向量表后面紧跟的就是代码/字面量池）。
    """
    entries = []
    low, high = image.span
    for index in range(limit):
        raw = image.read(base + index * 4, 4)
        if not raw:
            break
        value = int.from_bytes(raw, "little")
        if index >= 16 and value != 0:
            if not (value & 1 and low <= (value & ~1) < high):
                break
        entries.append((index, value))
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
    common_addr, common_count = table.common_handler
    return {
        "base": table.base,
        "sp": table.sp,
        "reset": table.reset,
        "exceptions": exceptions,
        "irq_count": len(irqs),
        "irqs": [{"index": index - 16, "addr": value & ~1} for index, value in irqs],
        "code_span": [code_low, code_high],
        "image_span": [low, high],
        "reserved": table.reserved,
        "common_handler": {"addr": common_addr, "count": common_count},
    }
