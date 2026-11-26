"""字符串扫描：ASCII、UTF-16LE/BE，以及 GBK（中文 Windows 程序的主要编码）。

只认 ASCII 会把国内软件的文字全漏掉——Delphi/BCB/MFC 写的界面字符串基本都是 GBK。
"""

import re
from pathlib import Path

ASCII_RE = rb"[\x20-\x7e]{%d,}"
UTF16LE_RE = rb"(?:[\x20-\x7e]\x00){%d,}"
UTF16BE_RE = rb"(?:\x00[\x20-\x7e]){%d,}"
GBK_RE = re.compile(rb"(?:[\x81-\xfe][\x40-\xfe]){2,}")

ENCODINGS = ("ascii", "utf16", "utf16be", "gbk")
MAX_MIN_LEN = 1 << 20  # 再大就不是"最短长度"而是把文件当一条串了


def _is_cjk(ch: str) -> bool:
    return (
        "\u4e00" <= ch <= "\u9fff"      # 基本汉字
        or "\u3400" <= ch <= "\u4dbf"    # 扩展 A
        or "\u3000" <= ch <= "\u303f"    # 中文标点
        or "\uff00" <= ch <= "\uffef"    # 全角字符
    )


def _gbk_hits(data: bytes, min_len: int) -> list[tuple[int, str, str]]:
    hits = []
    for match in GBK_RE.finditer(data):
        try:
            text = match.group().decode("gbk")
        except UnicodeDecodeError:
            continue
        if sum(1 for ch in text if _is_cjk(ch)) < min_len:
            continue
        hits.append((match.start(), "gbk", text))
    return hits


def read_bytes(path: Path, limit: int | None = None) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(limit) if limit else fh.read()


def scan(data: bytes, min_len: int = 4, utf16: bool = True,
         encodings: tuple[str, ...] = ENCODINGS):
    """产出 (offset, encoding, text)。按偏移排序。"""
    hits = []
    if min_len < 2:
        min_len = 2
    if min_len > MAX_MIN_LEN:
        from .errors import ReError

        raise ReError(
            f"最短长度 {min_len:,} 太大（上限 {MAX_MIN_LEN:,}）",
            hint="这只是过滤短串的下限，给个 2–64 就够；要全长文本用 re strings -n 1",
            code=2,
        )
    if "ascii" in encodings:
        for match in re.finditer(ASCII_RE % min_len, data):
            hits.append((match.start(), "ascii", match.group().decode("ascii", "replace")))
    if utf16 and "utf16" in encodings:
        for match in re.finditer(UTF16LE_RE % min_len, data):
            hits.append((match.start(), "utf16", match.group().decode("utf-16-le", "replace")))
    if utf16 and "utf16be" in encodings:
        for match in re.finditer(UTF16BE_RE % min_len, data):
            hits.append((match.start(), "utf16be", match.group().decode("utf-16-be", "replace")))
    if "gbk" in encodings:
        hits.extend(_gbk_hits(data, min_len))
    hits.sort(key=lambda item: item[0])
    return hits


def scan_file(path, min_len: int = 4, utf16: bool = True, encodings: tuple[str, ...] = ENCODINGS):
    return scan(read_bytes(Path(path)), min_len=min_len, utf16=utf16, encodings=encodings)


def interesting(text: str) -> str | None:
    """粗分类，只用来过滤噪声，不当结论。

    宁可漏，不可错：URL 和路径都要有像样的长度和结构，否则
    `j:/(` 这种碎片会被当成路径，过滤就白做了。
    """
    lowered = text.lower()
    size = len(text)
    if size >= 8 and lowered.startswith(("http://", "https://", "ws://", "wss://", "ftp://")):
        return "url"
    if size >= 6:
        if re.match(r"^[a-z]:[\\/][a-z0-9_\-.\\ ]{3,}", lowered):
            return "path"
        if lowered.startswith("\\\\") and size >= 8:
            return "path"
        if re.match(r"^/(usr|opt|etc|var|home|root|data|system|sdcard|proc|sys)/", lowered):
            return "path"
    if re.fullmatch(r"[\w.+-]+@[\w-]+\.[\w.]+", text):
        return "email"
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}(:\d+)?", text):
        return "ip"
    if "%s" in text or "%d" in text or "{}" in text:
        return "format"
    if re.fullmatch(r"[0-9a-fA-F]{16,}", text) and len(text) % 2 == 0:
        return "hex"
    if "-----BEGIN" in text:
        return "pem"
    return None
