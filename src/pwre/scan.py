"""字符串扫描：ASCII 与 UTF-16LE，带文件偏移。"""

import re
from pathlib import Path

# 可打印区间：0x20-0x7e，外加制表符之外的控制符一律不算
ASCII_RE = rb"[\x20-\x7e]{%d,}"
UTF16_RE = rb"(?:[\x20-\x7e]\x00){%d,}"


def read_bytes(path: Path, limit: int | None = None) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(limit) if limit else fh.read()


def scan(data: bytes, min_len: int = 4, utf16: bool = True):
    """产出 (offset, encoding, text)。按偏移排序。"""
    hits = []
    if min_len < 2:
        min_len = 2
    for match in re.finditer(ASCII_RE % min_len, data):
        hits.append((match.start(), "ascii", match.group().decode("ascii", "replace")))
    if utf16:
        for match in re.finditer(UTF16_RE % min_len, data):
            text = match.group().decode("utf-16-le", "replace")
            hits.append((match.start(), "utf16", text))
    hits.sort(key=lambda item: item[0])
    return hits


def scan_file(path, min_len: int = 4, utf16: bool = True):
    return scan(read_bytes(Path(path)), min_len=min_len, utf16=utf16)


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
