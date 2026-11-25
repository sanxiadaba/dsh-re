"""把各种固件文件装进统一的 Image。"""

from pathlib import Path

from . import hexfile
from .detect import sniff
from .errors import ReError
from .image import Image, Segment

TEXT_KINDS = ("ihex", "srec")


def load(path, base: int | None = None) -> Image:
    path = Path(path)
    kind = sniff(path).kind
    if kind == "ihex":
        return hexfile.parse_ihex(path.read_text(encoding="latin-1"))
    if kind == "srec":
        return hexfile.parse_srec(path.read_text(encoding="latin-1"))
    if base is None:
        raise ReError(
            f"{path.name} 不是 HEX/S-record，裸二进制必须给加载地址",
            hint="加 --base 0x08000000",
        )
    data = path.read_bytes()
    return Image([Segment(base, data)])
