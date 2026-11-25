"""反汇编：统一走 rizin。

固件（HEX/S-record/裸 BIN）先摊平成一段，架构从映像内容推（Cortex-M 向量表
→ Thumb），并把向量表里的入口当作函数种子——中断驱动的固件只有这样才分析得动。
PE/ELF/Mach-O 交给 rizin 自己认。没有 rizin 就直接报错，不降级。
"""

import json
import os
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from . import armvec, engines, firmware
from .detect import packed_reasons, sniff
from .errors import ReError

MAX_DIS = 400
MAX_SEEDS = 64


@dataclass
class Target:
    prefix: list[str]
    file: str
    base: int | None = None
    vectors: list[int] = field(default_factory=list)
    temp: Path | None = None


def _rizin(args: list[str], timeout: int = 180) -> str:
    exe = engines.require("rizin")
    cmd = [exe, "-q", "-e", "scr.color=0"] + args
    result = engines.run(cmd, timeout=timeout)
    if result.returncode != 0 and not result.stdout.strip():
        raise ReError(
            f"rizin 失败（退出码 {result.returncode}）：{result.stderr.strip()[:300]}",
            hint="确认文件没损坏；必要时 re doctor 复查引擎",
        )
    return result.stdout


def _rizin_json(args: list[str], timeout: int = 180):
    text = _rizin(args, timeout=timeout)
    start = min([pos for pos in (text.find("["), text.find("{")) if pos >= 0], default=-1)
    if start < 0:
        return []
    try:
        return json.loads(text[start:])
    except json.JSONDecodeError:
        raise ReError("rizin 输出的 JSON 解析不了", hint="把命令和文件报上来")


def _load_vectors(image) -> list[int]:
    """向量表里的入口就是函数种子；认不出来就空着，不猜。"""
    try:
        table = armvec.find_table(image)
    except ReError:
        return []
    return sorted({value & ~1 for index, value in table.entries if index >= 1 and value & 1})


@contextmanager
def target(path: Path, arch: str | None = None, bits: int | None = None, base: int | None = None):
    """产出 Target：前缀参数、文件、基址、函数种子。"""
    kind = sniff(path).kind
    ctx = Target(prefix=[], file=str(path))
    try:
        if kind in ("ihex", "srec"):
            image = firmware.load(path, base)
            flat_base, flat = image.to_flat()
            handle, name = tempfile.mkstemp(prefix="re-fw-", suffix=".bin")
            os.close(handle)
            ctx.temp = Path(name)
            ctx.temp.write_bytes(flat)
            ctx.base = flat_base
            ctx.vectors = _load_vectors(image)
            if not arch or not bits:
                guessed_arch, guessed_bits = guess_arch(image)
                arch = arch or guessed_arch
                bits = bits or guessed_bits
            ctx.prefix = ["-a", arch, "-b", str(bits), "-m", hex(flat_base)]
            ctx.file = str(ctx.temp)
            yield ctx
            return
        if base is not None:
            if not arch or not bits:
                raise ReError("裸二进制要给 --arch 和 --bits", hint="例如 --arch arm --bits 16 --base 0x08000000")
            ctx.prefix = ["-a", arch, "-b", str(bits), "-m", hex(base)]
            ctx.base = base
            yield ctx
            return
        yield ctx
    finally:
        if ctx.temp and ctx.temp.exists():
            ctx.temp.unlink()


def guess_arch(image) -> tuple[str, int]:
    """从映像内容推架构：向量表像 Cortex-M 就当 Thumb。"""
    try:
        table = armvec.find_table(image)
    except ReError:
        raise ReError(
            "认不出架构",
            hint="裸固件请显式给 --arch / --bits（例如 --arch arm --bits 16）",
        )
    return ("arm", 16) if table.reset & 1 else ("arm", 32)


def _seed_commands(ctx: Target) -> list[str]:
    """固件：aa + 每个向量入口建函数；PE/ELF：aa 够了。"""
    commands = ["aa"]
    if ctx.vectors:
        seeds = " ; ".join(f"af @ {addr:#x}" for addr in ctx.vectors[:MAX_SEEDS])
        commands.append(seeds)
    return commands


def dis(path: Path, at: int | None, sym: str | None, count: int,
        arch: str | None, bits: int | None, base: int | None):
    count = max(1, min(count, MAX_DIS))
    with target(path, arch, bits, base) as ctx:
        where = ""
        if at is not None:
            where = f" @ {at:#x}"
        elif sym:
            where = f" @ {sym}"
        elif ctx.vectors:
            where = f" @ {ctx.vectors[0]:#x}"
        rows = _rizin_json(ctx.prefix + ["-c", f"pdj {count}{where}", ctx.file])
    return [
        {
            "addr": row["offset"],
            "bytes": row.get("bytes", ""),
            "disasm": row.get("disasm") or row.get("opcode", ""),
            "kind": row.get("type", ""),
        }
        for row in rows
    ]


def _guard_packed(path: Path, force: bool) -> None:
    reasons = packed_reasons(sniff(path))
    if reasons and not force:
        raise ReError(
            "文件疑似加壳/保护：" + "，".join(reasons) + "；静态分析只会得到垃圾，还可能跑很久",
            hint="先 re unpack、或从内存 dump 后再分析；确实要硬跑就加 --force",
        )


def functions(path: Path, limit: int = 60, arch: str | None = None, bits: int | None = None,
              deep: bool = False, force: bool = False):
    _guard_packed(path, force)
    with target(path, arch, bits, None) as ctx:
        args = ctx.prefix[:]
        for command in _seed_commands(ctx):
            args += ["-c", command]
        # 固件用 aaaa（有向量表当根，197 个函数 2.4 秒）；PE/ELF 默认 aa，--deep 才 aaaa
        args += ["-c", "aaaa" if (deep or ctx.vectors) else "aa"]
        args += ["-c", "aflj", ctx.file]
        rows = _rizin_json(args, timeout=90 if ctx.vectors else 45)
    if not isinstance(rows, list):
        rows = []
    rows.sort(key=lambda row: row.get("offset", 0) or 0)
    return rows[:limit], len(rows)


def xrefs(path: Path, at: int, arch: str | None = None, bits: int | None = None,
          deep: bool = False, force: bool = False):
    _guard_packed(path, force)
    with target(path, arch, bits, None) as ctx:
        args = ctx.prefix[:]
        for command in _seed_commands(ctx):
            args += ["-c", command]
        args += ["-c", "aaaa" if (deep or ctx.vectors) else "aa"]
        args += ["-c", f"axtj @ {at:#x}", ctx.file]
        rows = _rizin_json(args, timeout=90 if ctx.vectors else 45)
    return rows if isinstance(rows, list) else []
