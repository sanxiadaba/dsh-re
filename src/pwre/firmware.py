"""把各种固件文件装进统一的 Image。"""

from pathlib import Path

from . import hexfile
from .detect import sniff
from .errors import ReError
from .image import Image, Segment

TEXT_KINDS = ("ihex", "srec")


def _decode(path) -> str:
    """HEX/S-record 是文本：先按 UTF-8（去 BOM）读，坏了再退回 latin-1。"""
    raw = Path(path).read_bytes()
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def load(path, base: int | None = None) -> Image:
    path = Path(path)
    info = sniff(path)
    kind = info.kind
    if kind == "ihex":
        return hexfile.parse_ihex(_decode(path))
    if kind == "srec":
        return hexfile.parse_srec(_decode(path))
    # 认出是别的格式就别当裸固件切：文本/PE/压缩包给 --base 也变不成固件
    if kind != "unknown":
        raise ReError(
            f"{path.name} 是{info.label}，不是固件",
            hint="固件是 .hex/.srec，或裸 .bin 配 --base；看结构用 re id / re pe / re unpack",
            code=2,
        )
    if base is None:
        raise ReError(
            f"{path.name} 不是 HEX/S-record，裸二进制必须给加载地址",
            hint="加 --base 0x08000000",
        )
    data = path.read_bytes()
    return Image([Segment(base, data)])
