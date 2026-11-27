"""反编译：Ghidra headless。

固件先摊平成一段并按向量表推处理器；PE/ELF 让 Ghidra 自己认。
结果由脚本写到文件，stdout 只用来判断成败——Ghidra 的日志不会污染反编译结果。
每次调用都会重新导入分析，所以第一次慢；慢是能力的一部分，不糊弄。
"""

import os
import shutil
import tempfile
from pathlib import Path

from . import engines, firmware
from .detect import sniff
from .errors import ReError

SCRIPT_DIR = Path(__file__).parent / "ghidra_scripts"
DEFAULT_TIMEOUT = 300


def _processor_for(image) -> str:
    from . import armvec

    try:
        table = armvec.find_table(image)
    except ReError:
        return ""
    return "ARM:LE:32:Cortex" if table.reset & 1 else "ARM:LE:32:v7"


# Ghidra 的启动脚本是 .bat，参数要过 cmd 解析。路径里的空格、括号、& 会在
# analyzeHeadless.bat 内部被拆开（`...) was unexpected at this time`）。
# 与其和 cmd 的引号规则搏斗，不如把输入摊到一个干净路径上再交给它。
HOSTILE = set(' ()[]{}&^%!,;=\'"')


def _needs_staging(path: Path) -> bool:
    return any(ch in HOSTILE for ch in str(path))


def _stage_dir() -> Path:
    return Path(tempfile.mkdtemp(prefix="re-stage-", dir=str(engines.data_dir())))


def _prepare(path: Path, base: int | None, work: Path):
    """返回 (输入文件, loader 参数列表)。输入一律落在 work 里，绝不让 cmd 见到用户路径。"""
    kind = sniff(path).kind
    if kind in ("ihex", "srec"):
        image = firmware.load(path, base)
        flat_base, flat = image.to_flat()
        temp = work / "input.bin"
        temp.write_bytes(flat)
        processor = _processor_for(image)
        loader = ["-loader", "BinaryLoader", "-loader-baseAddr", hex(flat_base)]
        if processor:
            loader += ["-processor", processor]
        return temp, loader
    if _needs_staging(path):
        temp = work / ("input" + path.suffix.lower())
        shutil.copy2(path, temp)
        loader = ["-loader", "BinaryLoader", "-loader-baseAddr", hex(base)] if base is not None else []
        return temp, loader
    if base is not None:
        loader = ["-loader", "BinaryLoader", "-loader-baseAddr", hex(base)]
        return path, loader
    return path, []


def _vector_seeds(path: Path, base: int | None) -> list[int]:
    """向量表里的 Thumb 入口（含 Reset/异常/IRQ），给 Ghidra 当函数种子。"""
    from . import armvec

    try:
        kind = sniff(path).kind
    except Exception:
        return []
    if kind not in ("ihex", "srec") and base is None:
        return []
    try:
        image = firmware.load(path, base)
        table = armvec.find_table(image)
    except ReError:
        return []
    seeds = {value & ~1 for index, value in table.entries if index >= 1 and value & 1}
    return sorted(seeds)


def decompile_all(path: Path, out_file: Path, base: int | None = None,
                  timeout: int = 900) -> str:
    """一次性把目标里所有函数反编译到 out_file（导入+分析只做一遍）。"""
    exe = engines.require("ghidra")
    java = engines.require("java")
    env = dict(os.environ)
    env["JAVA_HOME"] = str(Path(java).parent.parent)
    project_root = Path(tempfile.mkdtemp(prefix="re-proj-", dir=str(engines.data_dir())))
    work = _stage_dir()
    try:
        target, loader = _prepare(path, base, work)
        staged_out = work / "all.c"
        # 固件：把向量表里的入口写成种子文件——BinaryLoader 不知道向量表，
        # 不给种子的话 Reset/NMI/ISR 根本不会成为函数，反编译结果里就缺它们
        seed_args = []
        seeds = _vector_seeds(path, base)
        if seeds:
            seed_file = work / "seeds.txt"
            seed_file.write_text("\n".join(f"0x{addr:08x}" for addr in seeds) + "\n", encoding="utf-8")
            seed_args = [str(seed_file)]
        command = [
            exe,
            str(project_root), "re",
            "-import", str(target),
            "-postScript", "DumpAll.java", str(staged_out), *seed_args,
            "-scriptPath", str(SCRIPT_DIR),
            "-deleteProject",
            "-analysisTimeoutPerFile", "600",
        ] + loader
        result = engines.run(command, timeout=timeout, env=env)
        text = (result.stdout or "") + "\n" + (result.stderr or "")
        marker = "RE_DONE "
        if marker not in text:
            tail = "\n".join(text.strip().splitlines()[-8:])
            raise ReError("Ghidra 批量反编译没给出结果", hint=tail[:400])
        out_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(staged_out, out_file)
        return text.split(marker, 1)[1].splitlines()[0].strip()
    finally:
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(project_root, ignore_errors=True)


def decompile(path: Path, at: int | None, sym: str | None, base: int | None,
              timeout: int = DEFAULT_TIMEOUT) -> dict:
    exe = engines.require("ghidra")
    java = engines.require("java")
    env = dict(os.environ)
    env["JAVA_HOME"] = str(Path(java).parent.parent)

    project_root = Path(tempfile.mkdtemp(prefix="re-proj-", dir=str(engines.data_dir())))
    work = _stage_dir()
    try:
        target, loader = _prepare(path, base, work)
        arg = f"0x{at:08x}" if at is not None else (f"sym:{sym}" if sym else "")
        if not arg:
            raise ReError("要给 --at 或 --sym", hint="先用 re fw / re funcs 找地址")
        out_file = project_root / "decompiled.c"
        command = [
            exe,
            str(project_root), "re",
            "-import", str(target),
            "-postScript", "DumpFunction.java", arg, str(out_file),
            "-scriptPath", str(SCRIPT_DIR),
            "-deleteProject",
            "-analysisTimeoutPerFile", "180",
        ] + loader
        result = engines.run(command, timeout=timeout, env=env)
        text = (result.stdout or "") + "\n" + (result.stderr or "")
        if "RE_NO_FUNCTION" in text:
            raise ReError(
                f"Ghidra 在 {arg} 没找到函数",
                hint="换一个地址；或先用 re dis 确认这里是函数入口",
            )
        if "RE_FAILED" in text:
            detail = text.split("RE_FAILED", 1)[1].splitlines()[0].strip()
            raise ReError(f"Ghidra 反编译失败：{detail}")
        if not out_file.is_file() or not out_file.read_text(encoding="utf-8").strip():
            tail = "\n".join(text.strip().splitlines()[-8:])
            raise ReError("Ghidra 没给出结果", hint=tail[:400] or "确认引擎与 JDK 都在（re doctor）")
        lines = out_file.read_text(encoding="utf-8").splitlines()
        _, name, entry = lines[0].split(" ", 2)
        return {"name": name, "entry": entry.strip(), "c": "\n".join(lines[1:]).strip()}
    finally:
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(project_root, ignore_errors=True)
