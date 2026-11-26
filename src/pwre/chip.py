"""真硬件：J-Link + SWD。

静态分析只能回答"文件里是什么"；"芯片里跑的是不是这份"必须去问芯片。
这个模块用 SEGGER 的 JLink.exe 命令行做四件事：探测、读回、比对、烧写。
没有 J-Link 就明确报错，不假装能跑；所有调用都是 headless（`-NoGui 1` +
`-ExitOnError 1`），不会弹选择框等人点。
"""

import re
import shutil
import struct
import tempfile
from pathlib import Path

from . import engines, firmware
from .detect import sniff
from .errors import ReError

DEFAULT_FLASH = 0x08000000
DEFAULT_SIZE = 0x8000
DEFAULT_DEVICE = "Cortex-M0"


# ------------------------------------------------------------------ 定位


def jlink_exe() -> str | None:
    found = shutil.which("JLink")
    if found:
        return found
    for candidate in (
        r"C:\Program Files\SEGGER\JLink\JLink.exe",
        r"C:\Program Files (x86)\SEGGER\JLink\JLink.exe",
    ):
        if Path(candidate).is_file():
            return candidate
    return None


def _require() -> str:
    exe = jlink_exe()
    if not exe:
        raise ReError(
            "找不到 JLink.exe（SEGGER J-Link 软件）",
            hint="装 J-Link 驱动，或把 JLink.exe 放进 PATH",
        )
    return exe


def _workdir() -> Path:
    return Path(tempfile.mkdtemp(prefix="re-chip-", dir=str(engines.data_dir())))


def _head(device: str | None, speed: int, devices_xml: str | None = None) -> list[str]:
    # 不给器件名时 J-Link 会弹交互式选择（脚本里就卡住），所以永远显式给一个
    lines = []
    if devices_xml:
        lines.append(f"Exec JLinkDevicesXMLPath={devices_xml}")
    lines += ["si SWD", f"speed {speed}", f"device {device or DEFAULT_DEVICE}", "connect"]
    return lines


def _run(script_lines: list[str], cwd: Path, timeout: int = 120) -> str:
    exe = _require()
    script = cwd / "re-chip.jlink"
    script.write_text("\n".join(script_lines + ["q"]) + "\n", encoding="ascii", errors="replace")
    # -ExitOnError 1：器件名不对/连不上时立刻退出，别掉进 Device> 交互提示
    result = engines.run(
        [exe, "-NoGui", "1", "-ExitOnError", "1", "-CommanderScript", str(script)],
        timeout=timeout, cwd=str(cwd),
    )
    text = (result.stdout or "") + "\n" + (result.stderr or "")
    if "No valid device has been selected" in text or "Device>" in text:
        raise ReError(
            "J-Link 不认识这个器件名",
            hint="用 --device 指定 J-Link 支持的型号；Keil 的器件包可以 --devices-xml 指过去",
        )
    return text


def _words(text: str) -> dict[int, int]:
    """解析 J-Link `mem` 的输出：`08000000 = 00 20 ...`。"""
    out = {}
    for line in text.splitlines():
        match = re.match(r"^([0-9A-Fa-f]{8}) = ((?:[0-9A-Fa-f]{2} ?){4,16})", line.strip())
        if not match:
            continue
        addr = int(match.group(1), 16)
        raw = bytes.fromhex(match.group(2).replace(" ", ""))
        for index in range(len(raw) // 4):
            out[addr + index * 4] = struct.unpack_from("<I", raw, index * 4)[0]
    return out


def _dump_to(work: Path, base: int, size: int, device: str | None, speed: int,
             devices_xml: str | None = None) -> bytes:
    text = _run(_head(device, speed, devices_xml) + [f"savebin flash.bin, {base:#010x}, {size:x}"], work)
    produced = work / "flash.bin"
    if not produced.is_file() or produced.stat().st_size < size:
        tail = "\n".join(text.strip().splitlines()[-6:])
        raise ReError("读 flash 失败", hint=tail[:400])
    return produced.read_bytes()


# ------------------------------------------------------------------ 四个动作


def probe(device: str | None = None, speed: int = 4000, devices_xml: str | None = None) -> dict:
    """连上芯片，读 CPUID、向量表。"""
    work = _workdir()
    try:
        text = _run(_head(device, speed, devices_xml) + [
            "mem 0xE000ED00, 0x10",
            f"mem {DEFAULT_FLASH:#010x}, 0x40",
        ], work)
        words = _words(text)
        if not words:
            tail = "\n".join(text.strip().splitlines()[-6:])
            raise ReError("J-Link 连上了但没读到内存", hint=tail[:400])
        reset = words.get(DEFAULT_FLASH + 4, 0)
        return {
            "device": device or "（默认）",
            "cpuid": words.get(0xE000ED00, 0),
            "sp": words.get(DEFAULT_FLASH, 0),
            "reset": reset,
            "thumb": bool(reset & 1),
            "target": (reset & ~1) if reset & 1 else reset,
        }
    finally:
        shutil.rmtree(work, ignore_errors=True)


def dump(out: Path, base: int = DEFAULT_FLASH, size: int = DEFAULT_SIZE,
         device: str | None = None, speed: int = 4000, force: bool = False,
         devices_xml: str | None = None) -> Path:
    if out.exists() and not force:
        raise ReError(f"目标已存在：{out}", hint="换个文件名，或加 --force 覆盖")
    work = _workdir()
    try:
        data = _dump_to(work, base, size, device, speed, devices_xml)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    return out


def _load_image(path: Path, base: int):
    kind = sniff(path).kind
    if kind in ("ihex", "srec"):
        return firmware.load(path, None)
    return firmware.load(path, base)


def compare(path: Path, base: int = DEFAULT_FLASH, size: int = DEFAULT_SIZE,
            device: str | None = None, speed: int = 4000,
            devices_xml: str | None = None) -> dict:
    """把芯片 flash 与一个固件文件（HEX/SREC/BIN）逐字节比对。

    读回窗口自动放大到"文件跨度"：默认 32 KiB 会让 40 KiB 的镜像整段判成不同，
    结论就假了。
    """
    image = _load_image(path, base)
    low, high = image.span
    need = max(size, high - base)
    work = _workdir()
    try:
        chip = _dump_to(work, base, need, device, speed, devices_xml)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    same, diffs, outside = 0, [], 0
    for segment in image.segments:
        offset = segment.addr - base
        if offset < 0 or offset + len(segment.data) > len(chip):
            outside += len(segment.data)
            continue
        for index, value in enumerate(segment.data):
            if chip[offset + index] == value:
                same += 1
            elif len(diffs) < 20:
                diffs.append((segment.addr + index, value, chip[offset + index]))
    total = image.total
    return {
        "file": str(path),
        "file_size": total,
        "chip_size": len(chip),
        "same": same,
        "diff": total - same,
        "outside_window": outside,
        "first_diffs": diffs,
        "chip_nonff": sum(1 for byte in chip if byte != 0xFF),
    }


def flash(path: Path, device: str | None, base: int = DEFAULT_FLASH, speed: int = 4000,
          verify: bool = True, devices_xml: str | None = None) -> dict:
    """烧写固件，然后读回逐字节校验。

    成功与否只看校验结果：J-Link 连上就会打印 O.K.，用"输出里有 O.K."判断烧写成功
    会把失败当成功（实测踩过）。
    """
    if not device:
        raise ReError(
            "烧写必须给 --device（J-Link 靠器件名选 flash 算法）",
            hint="例如 --device PY32F030；先 re chip --info 确认连接正常",
        )
    kind = sniff(path).kind
    image = _load_image(path, base)
    work = _workdir()
    try:
        if kind in ("ihex", "srec"):
            shutil.copy2(path, work / "firmware.hex")
            load = f"loadfile firmware.hex, {base:#010x}"
        else:
            shutil.copy2(path, work / "firmware.bin")
            load = f"loadbin firmware.bin, {base:#010x}"
        text = _run(_head(device, speed, devices_xml) + ["erase", load], work, timeout=900)
        if "O.K." not in text.split("loadfile" if kind in ("ihex", "srec") else "loadbin")[-1]:
            tail = "\n".join(text.strip().splitlines()[-8:])
            raise ReError("烧写没有回 O.K.", hint=tail[:400])
        result = {"wrote": str(path), "verify": "skipped"}
        if verify:
            need = max(DEFAULT_SIZE, image.span[1] - base)
            chip = _dump_to(work, base, need, device, speed, devices_xml)
            bad = 0
            for segment in image.segments:
                offset = segment.addr - base
                if offset < 0 or offset + len(segment.data) > len(chip):
                    bad += len(segment.data)
                    continue
                bad += sum(1 for i, v in enumerate(segment.data) if chip[offset + i] != v)
            if bad:
                raise ReError(
                    f"烧写后读回校验失败：{bad:,} 字节不一致",
                    hint="芯片可能被写保护，或 flash 算法与器件不匹配（试试 --devices-xml）",
                )
            result["verify"] = "ok"
        return result
    finally:
        shutil.rmtree(work, ignore_errors=True)
