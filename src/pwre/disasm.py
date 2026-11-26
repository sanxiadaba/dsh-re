"""反汇编：统一走 rizin。

固件（HEX/S-record/裸 BIN）先摊平成一段，架构从映像内容推（Cortex-M 向量表
→ Thumb），并把向量表里的入口当作函数种子——中断驱动的固件只有这样才分析得动。
PE/ELF/Mach-O 交给 rizin 自己认。没有 rizin 就直接报错，不降级。
"""

import json
import os
import re
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from . import armvec, engines, firmware
from .detect import packed_reasons, sniff
from .errors import ReError
from .out import warn

CODE_KINDS = ("pe", "dll", "elf", "macho", "macho-fat", "wasm", "ihex", "srec", "unknown", "dex")

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


def _rizin_json(args: list[str], timeout: int = 180, allow_empty: bool = False):
    text = _rizin(args, timeout=timeout)
    # rizin 偶尔会在 JSON 前后打日志：从后往前找第一个能解析的起点，别被日志里的 [ 骗了
    decoder = json.JSONDecoder()
    for index in range(len(text)):
        if text[index] not in "[{":
            continue
        try:
            value, _ = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            continue
        return value
    if allow_empty:
        return []
    raise ReError(
        "rizin 输出的 JSON 解析不了",
        hint=f"命令：{' '.join(map(str, args))[-200:]}",
    )


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
    info = sniff(path)
    kind = info.kind
    if kind not in CODE_KINDS:
        raise ReError(
            f"这是 {info.label}，不是可反汇编的代码",
            hint="先 re id 确认是什么；文本用 re strings，压缩包用 re unpack，图片/文档没有代码可看",
        )
    ctx = Target(prefix=[], file=str(path))
    try:
        if kind in ("ihex", "srec") or base is not None:
            # 裸 BIN 与 HEX 走同一条路：先装进映像，再从向量表推架构与种子
            image = firmware.load(path, base)
            flat_base, flat = image.to_flat()
            handle, name = tempfile.mkstemp(prefix="re-fw-", suffix=".bin")
            os.close(handle)
            ctx.temp = Path(name)
            ctx.temp.write_bytes(flat)
            ctx.base = flat_base
            ctx.vectors = _load_vectors(image)
            if not arch or not bits:
                guessed = guess_arch(image)
                arch = arch or guessed[0]
                bits = bits or guessed[1]
            ctx.prefix = ["-a", arch, "-b", str(bits), "-m", hex(flat_base)]
            ctx.file = str(ctx.temp)
            yield ctx
            return
        if kind == "unknown":
            raise ReError(
                "未识别的裸二进制：反汇编前要给加载地址",
                hint="先 re fw 看向量表/入口；或者给 --base 0x08000000 --arch arm --bits 16",
            )
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
    """种子必须在 aa 之前发。

    rizin 的 aa 会把整段固件认成一个函数，之后再 `af @ 地址` 落在已有函数体内会被忽略，
    向量表种子等于白给。先建函数，再分析。
    """
    commands = []
    if ctx.vectors:
        seeds = ctx.vectors[:MAX_SEEDS]
        if len(ctx.vectors) > len(seeds):
            warn(f"向量种子太多，只用前 {MAX_SEEDS} 个（共 {len(ctx.vectors)} 个）")
        commands.extend(f"af @ {addr:#x}" for addr in seeds)
    return commands


def dis(path: Path, at: int | None, sym: str | None, count: int,
        arch: str | None, bits: int | None, base: int | None):
    count = max(1, min(count, MAX_DIS))
    with target(path, arch, bits, base) as ctx:
        where = ""
        if at is not None:
            where = f" @ {at:#x}"
        elif sym:
            where = f" @ {_resolve_symbol(ctx, sym)}"
        elif ctx.vectors:
            where = f" @ {ctx.vectors[0]:#x}"
        rows = _rizin_json(ctx.prefix + ["-c", f"pdj {count}{where}", ctx.file], allow_empty=True)
        if not rows and sym and not at:
            raise ReError(
                f"找不到符号 {sym}",
                hint="先用 re funcs 看有哪些函数；符号名不认识就别硬猜",
            )
    return [
        {
            "addr": row["offset"],
            "bytes": row.get("bytes", ""),
            "disasm": row.get("disasm") or row.get("opcode", ""),
            "kind": row.get("type", ""),
        }
        for row in rows
    ]


SAFE_SYM = re.compile(r"^[A-Za-z0-9_.$@:]+$")


def _resolve_symbol(ctx: Target, sym: str) -> str:
    """把符号名换成地址再拼进命令。

    用户串不能直接进 rizin 命令行（`;` 能注入命令），所以先做字符白名单；
    然后在函数表/符号表里找地址。找不到才把（已经安全的）名字交给 rizin 当 flag 用。
    """
    if re.fullmatch(r"0x[0-9a-fA-F]+|\d+", sym):
        return sym
    if not SAFE_SYM.match(sym):
        raise ReError(
            f"符号名里有不安全字符：{sym}",
            hint="只接受字母/数字/._$@:；先 re funcs 看真实符号名",
        )
    for command in ("aflj", "isj"):
        rows = _rizin_json(ctx.prefix + ["-c", command, ctx.file], timeout=60, allow_empty=True)
        for row in rows if isinstance(rows, list) else []:
            for key in ("name", "flagname", "realname"):
                if row.get(key) == sym:
                    return f"{row.get('offset', row.get('vaddr', 0)):#x}"
        for row in rows if isinstance(rows, list) else []:
            for key in ("name", "flagname"):
                value = row.get(key) or ""
                if value.endswith("." + sym) and "offset" in row:
                    return f"{row['offset']:#x}"
    return sym


def _guard_packed(path: Path, force: bool) -> None:
    reasons = packed_reasons(sniff(path))
    if reasons and not force:
        raise ReError(
            "文件疑似加壳/保护：" + "，".join(reasons) + "；静态分析只会得到垃圾，还可能跑很久",
            hint="先 re unpack（会识别 UPX 壳）；或从内存 dump 后再分析；确实要硬跑就加 --force",
        )


def functions(path: Path, limit: int = 60, arch: str | None = None, bits: int | None = None,
              deep: bool = False, force: bool = False, base: int | None = None,
              timeout: int | None = None):
    _guard_packed(path, force)
    with target(path, arch, bits, base) as ctx:
        args = ctx.prefix[:]
        for command in _seed_commands(ctx):
            args += ["-c", command]
        # 固件用 aaaa（有向量表当根）；PE/ELF 默认 aa，--deep 才 aaaa
        args += ["-c", "aaaa" if (deep or ctx.vectors) else "aa"]
        args += ["-c", "aflj", ctx.file]
        rows = _rizin_json(args, timeout=timeout or (90 if ctx.vectors else 45))
    if not isinstance(rows, list):
        rows = []
    rows.sort(key=lambda row: row.get("offset", 0) or 0)
    return rows[:limit], len(rows)


def xrefs(path: Path, at: int, arch: str | None = None, bits: int | None = None,
          deep: bool = False, force: bool = False, base: int | None = None,
          timeout: int | None = None):
    _guard_packed(path, force)
    with target(path, arch, bits, base) as ctx:
        args = ctx.prefix[:]
        for command in _seed_commands(ctx):
            args += ["-c", command]
        args += ["-c", "aaaa" if (deep or ctx.vectors) else "aa"]
        args += ["-c", f"axtj @ {at:#x}", ctx.file]
        rows = _rizin_json(args, timeout=timeout or (90 if ctx.vectors else 45))
    return rows if isinstance(rows, list) else []
