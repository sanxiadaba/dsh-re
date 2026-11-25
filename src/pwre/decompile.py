"""反编译：Ghidra headless。

固件先摊平成一段并按向量表推处理器；PE/ELF 让 Ghidra 自己认。
每次调用都会重新导入分析，所以第一次会慢——慢是能力的一部分，不糊弄。
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


def _prepare(path: Path, base: int | None):
    """返回 (输入文件, loader 参数列表)。"""
    kind = sniff(path).kind
    if kind in ("ihex", "srec"):
        image = firmware.load(path, base)
        flat_base, flat = image.to_flat()
        handle, name = tempfile.mkstemp(prefix="re-ghidra-", suffix=".bin")
        os.close(handle)
        temp = Path(name)
        temp.write_bytes(flat)
        processor = _processor_for(image)
        loader = ["-loader", "BinaryLoader", "-loader-baseAddr", hex(flat_base)]
        if processor:
            loader += ["-processor", processor]
        return temp, loader
    if base is not None:
        loader = ["-loader", "BinaryLoader", "-loader-baseAddr", hex(base)]
        return path, loader
    return path, []


def decompile(path: Path, at: int | None, sym: str | None, base: int | None,
              timeout: int = DEFAULT_TIMEOUT) -> dict:
    exe = engines.require("ghidra")
    java = engines.require("java")
    if not java:
        raise ReError("Ghidra 需要 Java", hint="re setup --java")
    env = dict(os.environ)
    env["JAVA_HOME"] = str(Path(java).parent.parent)

    project_root = Path(tempfile.mkdtemp(prefix="re-proj-", dir=str(engines.data_dir())))
    temp_input = None
    try:
        target, loader = _prepare(path, base)
        if target != path:
            temp_input = target
        arg = f"0x{at:08x}" if at is not None else (f"sym:{sym}" if sym else "")
        if not arg:
            raise ReError("要给 --at 或 --sym", hint="先用 re fw / re funcs 找地址")
        command = [
            exe,
            str(project_root), "re",
            "-import", str(target),
            "-postScript", "DumpFunction.java", arg,
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
        marker = text.find("RE_FUNC ")
        if marker < 0:
            tail = text.strip().splitlines()[-8:]
            raise ReError("Ghidra 没给出结果", hint="\n".join(tail)[:400])
        lines = text[marker:].splitlines()
        _, name, entry = lines[0].split(" ", 2)
        body = "\n".join(lines[1:]).strip()
        return {"name": name, "entry": entry, "c": body}
    finally:
        if temp_input and temp_input.exists():
            temp_input.unlink()
        shutil.rmtree(project_root, ignore_errors=True)
