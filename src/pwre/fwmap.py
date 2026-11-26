"""固件结构分析：一次产出全量反汇编、函数地图、外设引用。

这是把实验室里那套脚本（线性反汇编 + movw/movt 跟踪 + 外设归属）固化进 `re`，
换任何固件都能一条命令复现，不用再临时写脚本。

用法：
    re fwmap firmware.hex -o out/
产出：
    image.bin / full.asm / functions.json / analysis.json / function-map.md
"""

import bisect
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

import capstone

from . import armvec, firmware
from .detect import sniff
from .errors import ReError

PERIPH_RANGES = [
    (0x40000000, 0x40040000, "APB 外设"),
    (0x48000000, 0x48002000, "AHB 外设"),
    (0x50000000, 0x50002000, "GPIO/AHB"),
    (0x52000000, 0x52002000, "AHB2 外设"),
    (0x60000000, 0x61000000, "外部总线（FSMC/QSPI）"),
    (0xE000E000, 0xE000F000, "Cortex-M 内核（SCB/NVIC/SysTick）"),
    (0xE0040000, 0xE0042000, "调试块（TPIU/ITM/DWT）"),
]


def classify(addr: int) -> str | None:
    for low, high, name in PERIPH_RANGES:
        if low <= addr < high:
            return name
    return None


def load(path: Path, base: int | None):
    """读固件，返回 (image, 展开后的连续字节, 基址)。"""
    image = firmware.load(path, base)
    flat_base, flat = image.to_flat()
    return image, flat, flat_base


def disassemble(code: bytes, base: int) -> list[dict]:
    """线性反汇编，遇到无效字节按 2 字节跳过，保证覆盖每个字节。"""
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS)
    md.detail = True
    out = []
    offset = 0
    while offset < len(code):
        found = list(md.disasm(code[offset: offset + 4], base + offset))
        if not found:
            out.append({"addr": base + offset, "bytes": code[offset:offset + 2].hex(), "asm": ".2byte", "size": 2})
            offset += 2
            continue
        insn = found[0]
        out.append({
            "addr": insn.address,
            "bytes": code[offset: offset + insn.size].hex(),
            "asm": f"{insn.mnemonic} {insn.op_str}".strip(),
            "size": insn.size,
        })
        offset += insn.size
    return out


def analyze(insns: list[dict], code: bytes, base: int, functions: list[dict]) -> dict:
    """调用图 + 外设引用（字面量池与 movw/movt 两种构造都跟）。"""
    md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB | capstone.CS_MODE_MCLASS)
    md.detail = True
    starts = sorted((f["addr"], f.get("size", 0), f["name"]) for f in functions)
    start_values = [s[0] for s in starts]

    def func_of(addr):
        index = bisect.bisect_right(start_values, addr) - 1
        if index < 0:
            return None
        start, size, name = starts[index]
        if addr < start + max(size, 4096):
            return name
        return None

    calls = defaultdict(set)
    per_func_insn = Counter()
    periph = defaultdict(lambda: {"count": 0, "funcs": set()})
    regs = {}

    for item in insns:
        func = func_of(item["addr"])
        per_func_insn[func] += 1
        found = list(md.disasm(bytes.fromhex(item["bytes"]), item["addr"]))
        if not found:
            continue
        insn = found[0]
        mnemonic = insn.mnemonic.split(".")[0]

        if mnemonic.startswith("bl"):
            for op in insn.operands:
                if op.type == capstone.arm.ARM_OP_IMM:
                    calls[func].add(op.imm & ~1)

        if mnemonic in ("movw", "mov", "movs") and len(insn.operands) == 2:
            dst, src = insn.operands
            if dst.type == capstone.arm.ARM_OP_REG and src.type == capstone.arm.ARM_OP_IMM:
                regs[insn.reg_name(dst.reg)] = src.imm & 0xFFFF
                continue
        elif mnemonic == "movt" and len(insn.operands) == 2:
            dst, src = insn.operands
            if dst.type == capstone.arm.ARM_OP_REG and src.type == capstone.arm.ARM_OP_IMM:
                regs[insn.reg_name(dst.reg)] = (regs.get(insn.reg_name(dst.reg), 0) & 0xFFFF) | ((src.imm & 0xFFFF) << 16)
                continue

        if mnemonic in ("ldr", "str", "ldrb", "strb", "ldrh", "strh"):
            for op in insn.operands:
                if op.type != capstone.arm.ARM_OP_MEM:
                    continue
                target = None
                if op.mem.base == capstone.arm.ARM_REG_PC:
                    literal = ((insn.address + 4) & ~3) + op.mem.disp
                    slot = literal - base
                    if 0 <= slot <= len(code) - 4:
                        target = int.from_bytes(code[slot: slot + 4], "little")
                else:
                    base_name = insn.reg_name(op.mem.base)
                    if base_name in regs:
                        target = regs[base_name] + op.mem.disp
                if target is not None and classify(target):
                    entry = periph[target]
                    entry["count"] += 1
                    entry["funcs"].add(func)

        written = [insn.reg_name(op.reg) for op in insn.operands
                   if op.type == capstone.arm.ARM_OP_REG and (op.access & capstone.CS_AC_WRITE)]
        for name in written:
            regs.pop(name, None)

    return {
        "functions": [
            {"name": name, "addr": addr, "size": size,
             "insn": per_func_insn.get(name, 0), "calls": sorted(calls.get(name, []))}
            for addr, size, name in starts
        ],
        "peripherals": [
            {"addr": addr, "kind": classify(addr), "count": info["count"],
             "funcs": sorted(f for f in info["funcs"] if f)}
            for addr, info in sorted(periph.items())
        ],
    }


def function_map_md(result: dict, limit: int = 40) -> str:
    rows = ["| 地址 | 大小 | 指令 | 直接调用 |", "|---|---|---|---|"]
    for item in sorted(result["functions"], key=lambda f: -f["size"])[:limit]:
        rows.append(f"| {item['addr']:#010x} | {item['size']} | {item['insn']} | {len(item['calls'])} |")
    return "\n".join(rows) + "\n"


def run(path: Path, out_dir: Path, base: int | None = None, partial: bool = False) -> dict:
    """把一套结构分析产出写到 out_dir。"""
    image, code, flat_base = load(path, base)
    if base is None:
        base = flat_base
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "image.bin").write_bytes(code)

    # 线性反汇编从第一个向量目标开始：向量表本身是数据，从 0 开始扫只会得到垃圾
    start_offset = 0
    try:
        table = armvec.find_table(image)
        targets = [value & ~1 for index, value in table.entries if index >= 1 and value & 1]
        if targets:
            start_offset = max(0, min(targets) - base - (min(targets) - base) % 2)
    except ReError:
        start_offset = 0
    insns = disassemble(code[start_offset:], base + start_offset)
    lines = [f"# 0x{base:08x}–0x{base + start_offset:08x} 是向量表/头部，未按代码反汇编" if start_offset else "# 全量线性反汇编"]
    for item in insns:
        lines.append(f"{item['addr']:#010x}  {item['bytes']:<12}  {item['asm']}")
    (out_dir / "full.asm").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # 函数边界：优先用向量表当种子，再用 rizin 深扫
    from . import disasm as disasm_mod

    try:
        raw, _total = disasm_mod.functions(path, limit=100_000, arch="arm", bits=16, base=base)
    except ReError as exc:
        if not partial:
            raise ReError(
                f"函数表拿不到，fwmap 不产出半成品：{exc.message}",
                hint="先 re setup --rizin；确实只想要线性反汇编就加 --partial",
            ) from exc
        print(f"警告：函数表拿不到（{exc}），只做线性反汇编（--partial）", file=sys.stderr)
        raw = []
    funcs = [
        {"addr": row.get("offset", 0), "size": row.get("size", 0), "name": row.get("name", "?")}
        for row in raw
    ]
    result = analyze(insns, code[start_offset:], base + start_offset, funcs)
    result["image"] = str(path)
    result["base"] = base
    result["size"] = len(code)
    result["errors"] = image.errors
    result["degraded"] = not funcs
    (out_dir / "analysis.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "functions.json").write_text(json.dumps(funcs, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "function-map.md").write_text(function_map_md(result), encoding="utf-8")
    return result
