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
    kind = sniff(path).kind
    if kind == "ihex":
        return hexfile.parse_ihex(_decode(path))
    if kind == "srec":
        return hexfile.parse_srec(_decode(path))
    if base is None:
        raise ReError(
            f"{path.name} 不是 HEX/S-record，裸二进制必须给加载地址",
            hint="加 --base 0x08000000",
        )
    data = path.read_bytes()
    return Image([Segment(base, data)])
