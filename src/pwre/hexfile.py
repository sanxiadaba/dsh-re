"""固件文本格式：Intel HEX 与 Motorola S-record。

两种格式都只做一件事：把十六进制行变成"地址→字节"的段表。
校验错的行不会静默丢弃——记进 errors，由调用方决定是报错还是提示。
"""

from .image import Image, Segment

# 每种记录类型的数据字节数；-1 表示不限（数据记录）
IHEX_DATA_LEN = {0x00: -1, 0x01: 0, 0x02: 2, 0x03: 4, 0x04: 2, 0x05: 4}
MAX_ERRORS = 100


def _merge(segments: list[tuple[int, bytes]]) -> list[Segment]:
    return [Segment(addr, data) for addr, data in segments]


def parse_ihex(text: str) -> Image:
    image = Image()
    upper = 0
    pending: list[tuple[int, bytes]] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if lineno == 1:
            line = line.lstrip("\ufeff")
        if not line.startswith(":"):
            image.errors.append(f"第 {lineno} 行不是 ': ' 开头：{line[:40]}")
            continue
        try:
            body = bytes.fromhex(line[1:])
        except ValueError:
            image.errors.append(f"第 {lineno} 行不是合法十六进制：{line[:40]}")
            continue
        if len(body) < 5:
            image.errors.append(f"第 {lineno} 行太短（{len(body)} 字节）")
            continue
        count, offset, rtype = body[0], (body[1] << 8) | body[2], body[3]
        data = body[4: 4 + count]
        if len(data) != count or len(body) != count + 5:
            image.errors.append(f"第 {lineno} 行长度不符：声明 {count}，实际 {len(body) - 5}")
            continue
        if (sum(body) & 0xFF) != 0:
            image.errors.append(f"第 {lineno} 行校验和错")
            continue
        if rtype not in IHEX_DATA_LEN:
            image.errors.append(f"第 {lineno} 行是未知记录类型 0x{rtype:02x}，已忽略")
            continue
        want = IHEX_DATA_LEN[rtype]
        if want >= 0 and count != want:
            image.errors.append(f"第 {lineno} 行类型 0x{rtype:02x} 要 {want} 字节数据，实际 {count}")
            continue
        image.records += 1
        if rtype == 0x00:
            pending.append((upper + offset, data))
        elif rtype == 0x01:
            break
        elif rtype == 0x02:
            upper = int.from_bytes(data, "big") << 4
        elif rtype == 0x04:
            upper = int.from_bytes(data, "big") << 16
        elif rtype == 0x03:
            # CS:IP 两个 16 位字段，线性入口 =(CS<<4)+IP
            image.start = (int.from_bytes(data[:2], "big") << 4) + int.from_bytes(data[2:], "big")
        elif rtype == 0x05:
            image.start = int.from_bytes(data, "big")
        if len(image.errors) >= MAX_ERRORS:
            image.errors.append(f"错误太多，后续不再记录（已到 {MAX_ERRORS} 条上限）")
            break
    image.segments = _merge(pending)
    image.normalize()
    return image


SREC_ADDR_BYTES = {"0": 2, "1": 2, "2": 3, "3": 4, "5": 2, "6": 3, "7": 4, "8": 3, "9": 2}


def parse_srec(text: str) -> Image:
    image = Image()
    pending: list[tuple[int, bytes]] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        if lineno == 1:
            line = line.lstrip("\ufeff")
        if len(line) < 4 or line[0] != "S" or line[1] not in SREC_ADDR_BYTES:
            image.errors.append(f"第 {lineno} 行不是合法 S-record：{line[:40]}")
            continue
        kind = line[1]
        try:
            body = bytes.fromhex(line[2:])
        except ValueError:
            image.errors.append(f"第 {lineno} 行不是合法十六进制：{line[:40]}")
            continue
        count = body[0]
        if count + 1 != len(body):
            image.errors.append(f"第 {lineno} 行长度不符：声明 {count}，实际 {len(body) - 1}")
            continue
        if (sum(body) & 0xFF) != 0xFF:
            image.errors.append(f"第 {lineno} 行校验和错")
            continue
        image.records += 1
        width = SREC_ADDR_BYTES[kind]
        addr = int.from_bytes(body[1: 1 + width], "big")
        data = body[1 + width: -1]
        if kind in ("1", "2", "3"):
            pending.append((addr, data))
        elif kind in ("7", "8", "9"):
            image.start = addr
        # S0 是文件名头，S5/S6 是记录数，都不进段表
        if len(image.errors) >= MAX_ERRORS:
            image.errors.append(f"错误太多，后续不再记录（已到 {MAX_ERRORS} 条上限）")
            break
    image.segments = _merge(pending)
    image.normalize()
    return image


def parse(path) -> Image:
    from pathlib import Path

    raw = Path(path).read_bytes()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    first = text.lstrip()[:2]
    if first.startswith(":"):
        return parse_ihex(text)
    if first.startswith("S"):
        return parse_srec(text)
    raise ValueError(f"既不是 Intel HEX 也不是 S-record：{path}")


def write_ihex(image: Image, upper: int = 0x08000000) -> str:
    """把段表写回 Intel HEX。地址按 0x08000000 起始的 Flash 分布。"""
    lines = []
    current_upper = None
    for segment in image.segments:
        offset = 0
        while offset < len(segment.data):
            addr = segment.addr + offset
            high = (addr >> 16) & 0xFFFF
            if high != current_upper:
                current_upper = high
                payload = bytes([2, 0, 0, 4]) + high.to_bytes(2, "big")
                lines.append(_record(payload))
            chunk = segment.data[offset: offset + 16]
            payload = bytes([len(chunk), (addr >> 8) & 0xFF, addr & 0xFF, 0]) + chunk
            lines.append(_record(payload))
            offset += len(chunk)
    lines.append(_record(bytes([0, 0, 0, 1])))
    return "\n".join(lines) + "\n"


def _record(payload: bytes) -> str:
    checksum = (-sum(payload)) & 0xFF
    return ":" + (payload + bytes([checksum])).hex().upper()
