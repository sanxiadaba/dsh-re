"""剥包：把各种容器摊开到目录里。每种格式都校验，坏包报错而不是给半个结果。"""

import gzip
import hashlib
import json
import lzma
import bz2
import re
import os
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

from .detect import packer_name, sniff
from .errors import ReError


def _write(dest: Path, name: str, data: bytes) -> dict:
    target = dest / name
    # 兜底：拼出来的路径必须仍在 dest 里
    if not str(target.resolve()).startswith(str(dest.resolve()) + os.sep):
        raise ReError(f"包里的路径跑到解压目录外了，拒绝写：{name}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return {"path": str(target), "size": len(data)}


def _safe_name(name: str) -> str:
    """只接受包内的相对路径；盘符、绝对路径、..、Windows 设备名一律拒绝。"""
    raw = name.replace("\\", "/")
    if raw.startswith("/") or (len(raw) >= 2 and raw[1] == ":"):
        raise ReError(f"包里有绝对路径/盘符，拒绝解压：{name}")
    parts = []
    for part in raw.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise ReError(f"包里有 .. 路径，拒绝解压：{name}")
        if ":" in part:
            raise ReError(f"包里有备用数据流/驱动器语法，拒绝解压：{name}")
        if part.rstrip(" .") != part:
            raise ReError(f"包里有尾部点/空格的路径，Windows 会写到别处，拒绝：{name}")
        if any(ch in part for ch in '<>"|?*'):
            raise ReError(f"包里有 Windows 非法字符，拒绝解压：{name}")
        stem = part.split(".", 1)[0].upper()
        if stem in {"CON", "PRN", "AUX", "NUL"} or re.fullmatch(r"(COM|LPT)[0-9]", stem):
            raise ReError(f"包里有 Windows 设备名，拒绝解压：{name}")
        parts.append(part)
    if not parts:
        raise ReError(f"包里有不安全的路径：{name}")
    return "/".join(parts)


def extract_zip(path: Path, dest: Path) -> list[dict]:
    out = []
    try:
        with zipfile.ZipFile(path) as zf:
            for entry in zf.infolist():
                if entry.is_dir():
                    continue
                out.append(_write(dest, _safe_name(entry.filename), zf.read(entry)))
    except RuntimeError as exc:
        raise ReError(f"这个包解不开：{exc}", hint="加密包要先解密；不是标准 zip 就用 7z")
    except (zipfile.BadZipFile, NotImplementedError) as exc:
        raise ReError(f"这个包坏了或不支持：{exc}", hint="CRC 错说明文件损坏；换个来源重下")
    return out


def extract_tar(path: Path, dest: Path) -> list[dict]:
    out = []
    with tarfile.open(path) as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            handle = tf.extractfile(member)
            if handle is None:
                continue
            out.append(_write(dest, _safe_name(member.name), handle.read()))
    return out


def _decompress(path: Path, dest: Path, opener) -> list[dict]:
    name = path.name
    for suffix in (".gz", ".xz", ".bz2", ".zst", ".zstd"):
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)]
            break
    with opener(path) as fh:
        data = fh.read()
    return [_write(dest, name or path.stem, data)]


def extract_zstd(path: Path, dest: Path) -> list[dict]:
    import zstandard

    return _decompress(path, dest, lambda p: zstandard.ZstdDecompressor().stream_reader(open(p, "rb")))


def asar_header(raw: bytes) -> tuple[dict, int]:
    """解析 asar 头，返回 (JSON 头, 数据起点)。

    真实 asar 是 Chromium pickle 的双层结构：
      u32=4 | u32=第二层总长B | u32=B-4 | u32=JSON 长度D | JSON(16..16+D, 4 对齐) | 数据
    数据起点 = 8 + B。早期实现的单层写法（u32 总长 | u32 JSON 长 | JSON@8）也接受。
    """
    import struct

    if len(raw) < 16:
        raise ReError("asar 文件太短")
    first, second, third, fourth = struct.unpack("<IIII", raw[:16])
    if raw[8:9] == b"{" or first == second + 8:
        # 单层：total | json_len | json
        json_len = second
        data_start = 8 + json_len
        blob = raw[8: 8 + json_len]
        if json_len + 8 > len(raw):
            raise ReError("asar 头部长度自相矛盾，文件可能截断")
    else:
        if first != 4 or second == 0 or second > len(raw) - 8:
            raise ReError(f"asar 头部布局不认识（前四个 u32：{first} {second} {third} {fourth}）")
        json_len = fourth
        if json_len > second or second + 8 > len(raw):
            raise ReError("asar 头部长度自相矛盾，文件可能截断")
        data_start = 8 + second
        blob = raw[16: 16 + json_len]
    try:
        header = json.loads(blob.rstrip(b"\x00").decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ReError(f"asar 头部 JSON 解析失败：{exc}")
    if not isinstance(header, dict) or "files" not in header:
        raise ReError("asar 头部里没有 files 树")
    return header, data_start


def extract_asar(path: Path, dest: Path) -> list[dict]:
    raw = path.read_bytes()
    header, data_start = asar_header(raw)

    out = []

    def walk(node: dict, prefix: str):
        for name, item in (node.get("files") or {}).items():
            rel = f"{prefix}/{name}" if prefix else name
            if "files" in item:
                walk(item, rel)
                continue
            if item.get("unpacked"):
                source = path.with_name(path.name + ".unpacked") / _safe_name(rel)
                if not source.is_file():
                    raise ReError(f"asar 声明了 unpacked 文件但目录里没有：{rel}")
                target = dest / _safe_name(rel)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
                out.append({"path": str(target), "size": source.stat().st_size})
                continue
            offset = int(item.get("offset", 0))
            size = int(item.get("size", 0))
            if offset < 0 or size < 0 or data_start + offset + size > len(raw):
                raise ReError(f"asar 条目越界：{rel}")
            chunk = raw[data_start + offset: data_start + offset + size]
            if len(chunk) != size:
                raise ReError(f"asar 条目越界：{rel}")
            digest = (item.get("integrity") or {}).get("hash")
            if digest and hashlib.sha256(chunk).hexdigest() != digest:
                raise ReError(f"asar 条目哈希不符：{rel}")
            out.append(_write(dest, _safe_name(rel), chunk))

    walk(header, "")
    return out


def extract_cab(path: Path, dest: Path) -> list[dict]:
    expand = shutil.which("expand")
    if not expand:
        raise ReError("缺少 expand.exe（Windows 自带）", hint="在 Windows 上运行，或装 7-Zip 后用 re unpack")
    dest.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [expand, "-F:*", str(path), str(dest)],
        capture_output=True,
        text=True,
        timeout=300,
        errors="replace",
    )
    if result.returncode != 0:
        raise ReError(f"expand 失败：{result.stderr.strip()[:200]}")
    return _collect(dest)


def extract_msi(path: Path, dest: Path) -> list[dict]:
    msiexec = shutil.which("msiexec")
    if not msiexec:
        raise ReError("缺少 msiexec（Windows 自带）")
    dest.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [msiexec, "/a", str(path), "/qn", f"TARGETDIR={dest}"],
        capture_output=True,
        text=True,
        timeout=600,
        errors="replace",
    )
    if result.returncode != 0:
        raise ReError(
            f"msiexec 解包失败（退出码 {result.returncode}）",
            hint="MSI 需要管理安装权限；也可用 7-Zip 打开",
        )
    return _collect(dest)


def extract_7z(path: Path, dest: Path) -> list[dict]:
    exe = shutil.which("7z") or shutil.which("7za")
    if not exe:
        raise ReError(
            f"没有能解 {path.suffix} 的工具",
            hint="装 7-Zip 并确保 7z.exe 在 PATH 上（re doctor 会检测）",
        )
    dest.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [exe, "x", "-y", f"-o{dest}", str(path)],
        capture_output=True,
        text=True,
        timeout=600,
        errors="replace",
    )
    if result.returncode != 0:
        raise ReError(f"7z 解包失败：{result.stderr.strip()[:200]}")
    return _collect(dest)


def extract_pyinstaller(path: Path, dest: Path) -> list[dict]:
    """PyInstaller CArchive：从文件尾部找 MEI cookie，按 TOC 解压。"""
    import struct
    import zlib

    raw = path.read_bytes()
    cookie = b"MEI\x0c\x0b\x0a\x0b\x0e"
    pos = raw.rfind(cookie)
    if pos < 0:
        raise ReError("不是 PyInstaller 打包（没找到 MEI cookie）")
    tail = raw[pos: pos + 88]
    if len(tail) < 88:
        raise ReError("PyInstaller cookie 不完整")
    cookie_magic, length_of_package, toc, toc_len, pyver = struct.unpack("!8sIIII", tail[:24])
    libname = tail[24:88].split(b"\x00", 1)[0].decode("latin-1", "replace")
    start = pos + 88 - length_of_package
    out = []
    cursor = toc
    end = toc + toc_len
    while cursor < end:
        entry_len, offset, csize, usize, flag, type_code = struct.unpack("!IIIIBB", raw[cursor: cursor + 18])
        name = raw[cursor + 18: cursor + entry_len].split(b"\x00", 1)[0].decode("latin-1", "replace")
        cursor += entry_len
        blob = raw[start + offset: start + offset + csize]
        if flag:
            blob = zlib.decompress(blob)
        if len(blob) != usize:
            raise ReError(f"PyInstaller 条目大小不符：{name}")
        out.append(_write(dest, _safe_name(name), blob))
    if libname:
        out.append({"note": f"Python 运行库：{libname}，Python {pyver}"})
    return out


def extract_upx(path: Path, dest: Path) -> list[dict]:
    """UPX 脱壳：调 upx.exe 把它自己解开。"""
    from . import engines

    exe = engines.upx_path()
    if not exe:
        raise ReError(
            f"{path.name} 是 UPX 壳，但没有 upx.exe",
            hint="把 upx.exe 放到 %LOCALAPPDATA%\\dsh-re\\tools\\upx\\ 或装进 PATH；或用 re mem 从内存 dump",
        )
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / f"{path.stem}.unpacked{path.suffix.lower()}"
    result = engines.run([exe, "-d", str(path), "-o", str(target)], timeout=300)
    if result.returncode != 0 or not target.is_file():
        raise ReError(
            f"upx 脱壳失败（退出码 {result.returncode}）：{(result.stderr or result.stdout).strip()[:200]}",
            hint="可能不是标准 UPX，或已被改壳；试试 re mem 从内存 dump",
        )
    return [{"path": str(target), "size": target.stat().st_size}]


def _collect(dest: Path) -> list[dict]:
    return [
        {"path": str(item), "size": item.stat().st_size}
        for item in sorted(dest.rglob("*"))
        if item.is_file()
    ]


def unpack(path: Path, dest: Path, force: bool = False) -> tuple[list[dict], str]:
    """返回 (提取结果, 用到的格式名)。

    先解到 `<dest>.re-tmp`，全部成功才搬进 dest：坏包/路径逃逸不会在目标目录里
    留下半成品（SKILL 承诺"不返回半成品"，这里兑现）。
    """
    if dest.exists() and not dest.is_dir():
        raise ReError(f"-o 指的是文件而不是目录：{dest}")
    if dest.exists() and any(dest.iterdir()) and not force:
        raise ReError(f"目标目录非空：{dest}", hint="换个 -o，或加 --force 覆盖")
    work = dest.with_name(dest.name + ".re-tmp")
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    try:
        items, kind = _dispatch(path, work)
        dest.mkdir(parents=True, exist_ok=True)
        for item in sorted(work.rglob("*")):
            target = dest / item.relative_to(work)
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(item), str(target))
    except Exception:
        shutil.rmtree(work, ignore_errors=True)
        raise
    moved = []
    for item in items:
        if "path" not in item:
            moved.append(item)
            continue
        rel = Path(item["path"]).relative_to(work)
        moved.append({"path": str(dest / rel), "size": item["size"]})
    shutil.rmtree(work, ignore_errors=True)
    return moved, kind


def _dispatch(path: Path, dest: Path) -> tuple[list[dict], str]:
    info = sniff(path)
    kind = info.kind
    if kind in ("zip", "apk", "jar", "docx", "xlsx", "pptx", "ooxml"):
        return extract_zip(path, dest), kind
    if kind == "tar":
        return extract_tar(path, dest), kind
    if kind == "gzip":
        return _decompress(path, dest, gzip.open), kind
    if kind == "xz":
        return _decompress(path, dest, lzma.open), kind
    if kind == "bzip2":
        return _decompress(path, dest, bz2.open), kind
    if kind == "zstd":
        return extract_zstd(path, dest), kind
    if kind == "asar":
        return extract_asar(path, dest), kind
    if kind == "cab":
        return extract_cab(path, dest), kind
    if kind == "ole" and path.suffix.lower() == ".msi":
        return extract_msi(path, dest), kind
    if kind in ("7z", "rar"):
        return extract_7z(path, dest), kind
    if kind in ("pe", "dll") and b"MEI\x0c\x0b\x0a\x0b\x0e" in path.read_bytes()[-2 << 20:]:
        return extract_pyinstaller(path, dest), "pyinstaller"
    if kind in ("pe", "dll") and packer_name(info) == "UPX":
        return extract_upx(path, dest), "upx"
    raise ReError(
        f"{path.name} 识别为 {info.label}，不是可剥的包",
        hint="先用 re id 看清楚；固件用 re fw / re hex",
    )
