"""格式识别：先看字节，不看扩展名。"""

import hashlib
import json
import math
import struct
from dataclasses import dataclass, field
from pathlib import Path

PE_MACHINES = {
    0x014C: "x86",
    0x8664: "x86-64",
    0x01C0: "ARM",
    0x01C4: "ARM Thumb-2",
    0xAA64: "ARM64",
    0x0200: "IA-64",
    0x0166: "MIPS",
    0x01A2: "SH",
    0x01F0: "PowerPC",
    0x0EBC: "EFI bytecode",
}

PE_SUBSYSTEMS = {
    1: "native",
    2: "GUI",
    3: "CUI",
    5: "OS/2 CUI",
    7: "POSIX CUI",
    9: "Windows CE",
    10: "EFI 应用",
    11: "EFI 驱动",
    12: "EFI 运行时驱动",
    14: "Xbox",
    16: "Windows 引导",
}

ELF_MACHINES = {
    3: "x86",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    40: "ARM",
    62: "x86-64",
    183: "AArch64",
    243: "RISC-V",
    22: "S390",
    2: "SPARC",
    50: "IA-64",
    94: "Xtensa",
}

ELF_TYPES = {1: "可重定位", 2: "可执行", 3: "共享库", 4: "核心转储"}

MACHO_CPUS = {
    7: "x86",
    0x01000007: "x86-64",
    12: "ARM",
    0x0100000C: "ARM64",
    18: "PowerPC",
    0x01000012: "PowerPC64",
}


@dataclass
class FileInfo:
    path: Path
    size: int
    kind: str
    label: str
    arch: str = ""
    bits: int = 0
    endian: str = ""
    entry: int | None = None
    extra: dict = field(default_factory=dict)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.path.read_bytes()).hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return max(0.0, -sum((c / total) * math.log2(c / total) for c in counts if c))


def looks_text(data: bytes) -> bool:
    sample = data[:4096]
    if not sample:
        return False
    printable = sum(1 for b in sample if 9 <= b <= 13 or 32 <= b <= 126 or b >= 0x80)
    return printable / len(sample) > 0.95


def sniff(path: Path) -> FileInfo:
    path = Path(path)
    if not path.is_file():
        from .errors import ReError

        raise ReError(f"不是文件：{path}")
    size = path.stat().st_size
    with open(path, "rb") as fh:
        head = fh.read(4096)

    if head[:2] == b"MZ":
        return _pe(path, size, head)
    if head[:4] == b"\x7fELF":
        return _elf(path, size, head)
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return _macho(path, size, head)
    if head[:4] == b"\xca\xfe\xba\xbe":
        return FileInfo(path, size, "macho-fat", "Mach-O 通用二进制（多架构）", endian="big")
    if head[:4] == b"\x00asm":
        return FileInfo(path, size, "wasm", "WebAssembly 模块", arch="wasm", bits=32, endian="little")
    if head[:8] == b"SQLite f":
        return FileInfo(path, size, "sqlite", "SQLite 数据库")
    if head[:4] == b"dex\n":
        return FileInfo(path, size, "dex", "Android DEX 字节码", arch="dalvik", endian="little")
    if head[:4] == b"PK\x03\x04":
        return _zip(path, size)
    if head[:4] == b"MSCF":
        return FileInfo(path, size, "cab", "Windows Cabinet 安装包")
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return FileInfo(path, size, "ole", "OLE 复合文档（MSI / Office 旧格式）")
    if head[:4] == b"%PDF":
        return FileInfo(path, size, "pdf", "PDF 文档")
    if head[:2] == b"\x1f\x8b":
        return FileInfo(path, size, "gzip", "gzip 压缩流")
    if head[:6] == b"\xfd7zXZ\x00":
        return FileInfo(path, size, "xz", "xz 压缩流")
    if head[:3] == b"BZh":
        return FileInfo(path, size, "bzip2", "bzip2 压缩流")
    if head[:4] == b"\x28\xb5\x2f\xfd":
        return FileInfo(path, size, "zstd", "zstd 压缩流")
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return FileInfo(path, size, "7z", "7-Zip 压缩包")
    if head[:4] == b"Rar!":
        return FileInfo(path, size, "rar", "RAR 压缩包")
    if head[:2] == b"\x89P":
        return FileInfo(path, size, "png", "PNG 图片")
    if head[:3] == b"\xff\xd8\xff":
        return FileInfo(path, size, "jpeg", "JPEG 图片")
    if len(head) > 265 and head[257:262] == b"ustar":
        return FileInfo(path, size, "tar", "tar 归档")
    asar = _try_asar(path)
    if asar:
        return asar
    if looks_text(head):
        text = head.lstrip()
        if text[:1] == b":":
            return FileInfo(path, size, "ihex", "Intel HEX 固件镜像")
        if text[:2] in (b"S0", b"S1", b"S2", b"S3", b"S5", b"S7", b"S8", b"S9"):
            return FileInfo(path, size, "srec", "Motorola S-record 固件镜像")
        if head[:4] == b"\xef\xbb\xbf{" or text[:1] == b"{":
            try:
                json.loads(path.read_text(encoding="utf-8-sig"))
                return FileInfo(path, size, "json", "JSON 文本")
            except ValueError:
                pass
        first = text.split(b"\n", 1)[0][:80].decode("utf-8", "replace").rstrip()
        return FileInfo(path, size, "text", f"文本（首行：{first}）")

    return FileInfo(
        path,
        size,
        "unknown",
        f"未知格式（magic {head[:8].hex(' ')}）",
        extra={"entropy": round(entropy(head), 2)},
    )


def _try_asar(path: Path):
    """asar 头：u32 总长、u32 JSON 长、JSON（4 对齐）。"""
    with open(path, "rb") as fh:
        head = fh.read(8)
        if len(head) < 8:
            return None
        total, json_len = struct.unpack("<II", head)
        if json_len < 8 or json_len + 8 > total or total > 64 << 20:
            return None
        fh.seek(8)
        blob = fh.read(json_len)
    try:
        header = json.loads(blob.rstrip(b"\x00").decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or "files" not in header:
        return None
    return FileInfo(path, path.stat().st_size, "asar", "Electron asar 归档", extra={"header": header})


def packed_reasons(info: FileInfo) -> list[str]:
    """加壳/保护的可验证迹象。空列表表示没看出异常。"""
    if info.kind not in ("pe", "dll"):
        return []
    sections = info.extra.get("sections") or []
    empty = [section["name"] for section in sections if section["vsize"] and not section["raw"]]
    hot = [section for section in sections if section["raw"] and section["entropy"] > 7.2]
    entry_section = info.extra.get("entry_section", "")
    reasons = []
    if empty:
        reasons.append(f"{'/'.join(dict.fromkeys(empty))} 在文件里没有原始数据")
    if entry_section and entry_section in empty:
        reasons.append(f"入口落在 {entry_section}")
    if hot:
        section = max(hot, key=lambda item: item["entropy"])
        reasons.append(f"{section['name']} 熵 {section['entropy']}")
    return reasons if len(reasons) >= 2 else []


def _pe(path: Path, size: int, head: bytes) -> FileInfo:
    try:
        import pefile

        pe = pefile.PE(str(path), fast_load=True)
    except Exception as exc:  # 损坏的 PE 也要能报出来
        return FileInfo(path, size, "pe-broken", f"PE 但解析失败：{exc}")
    machine = pe.FILE_HEADER.Machine
    subsystem = pe.OPTIONAL_HEADER.Subsystem
    bits = 64 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 32
    is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    kind = "dll" if is_dll else "pe"
    label = f"PE{bits} {'DLL' if is_dll else '可执行文件'}"
    if subsystem in PE_SUBSYSTEMS:
        label += f"（{PE_SUBSYSTEMS[subsystem]}）"
    extra = {
        "machine": machine,
        "subsystem": subsystem,
        "dll": is_dll,
        "linker": f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}",
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "sections": _pe_sections(pe),
        "characteristics": pe.FILE_HEADER.Characteristics,
        "optional": pe.OPTIONAL_HEADER,
        "file_header": pe.FILE_HEADER,
        "entry_rva": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
    }
    extra["entry_section"] = _section_at(extra["sections"], extra["entry_rva"])
    return FileInfo(
        path,
        size,
        kind,
        label,
        arch=PE_MACHINES.get(machine, f"machine 0x{machine:04x}"),
        bits=bits,
        endian="little",
        entry=pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase,
        extra=extra,
    )


def _pe_sections(pe) -> list[dict]:
    rows = []
    for section in pe.sections:
        rows.append(
            {
                "name": section.Name.rstrip(b"\x00").decode("latin-1"),
                "rva": section.VirtualAddress,
                "vsize": section.Misc_VirtualSize,
                "raw": section.SizeOfRawData,
                "ptr": section.PointerToRawData,
                "flags": section.Characteristics,
                "entropy": round(section.get_entropy(), 2),
            }
        )
    return rows


def _section_at(sections: list[dict], rva: int) -> str:
    for section in sections:
        span = max(section["vsize"], section["raw"])
        if section["rva"] <= rva < section["rva"] + span:
            return section["name"]
    return ""


def _elf(path: Path, size: int, head: bytes) -> FileInfo:
    bits = 64 if head[4] == 2 else 32
    endian = "little" if head[5] == 1 else "big"
    try:
        from elftools.elf.elffile import ELFFile

        with open(path, "rb") as fh:
            elf = ELFFile(fh)
            machine = elf.header["e_machine"]
            etype = elf.header["e_type"]
            entry = elf.header["e_entry"]
            extra = {
                "type": ELF_TYPES.get(etype, str(etype)),
                "machine": machine,
                "sections": [
                    {
                        "name": s.name,
                        "rva": s["sh_addr"],
                        "size": s["sh_size"],
                        "type": s["sh_type"],
                    }
                    for s in elf.iter_sections()
                ],
            }
    except Exception as exc:
        return FileInfo(path, size, "elf-broken", f"ELF 但解析失败：{exc}")
    label = f"ELF{bits} {ELF_TYPES.get(etype, '')}".strip()
    return FileInfo(
        path,
        size,
        "elf",
        label,
        arch=ELF_MACHINES.get(machine, f"machine {machine}"),
        bits=bits,
        endian=endian,
        entry=entry,
        extra=extra,
    )


def _macho(path: Path, size: int, head: bytes) -> FileInfo:
    magic = head[:4]
    endian = "big" if magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf") else "little"
    fmt = ">" if endian == "big" else "<"
    cputype = struct.unpack(fmt + "i", head[4:8])[0] & 0xFFFFFFFF
    bits = 64 if magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe") else 32
    return FileInfo(
        path,
        size,
        "macho",
        f"Mach-O {bits} 位",
        arch=MACHO_CPUS.get(cputype, f"cputype 0x{cputype:x}"),
        bits=bits,
        endian=endian,
    )


def _zip(path: Path, size: int) -> FileInfo:
    import zipfile

    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
    except zipfile.BadZipFile:
        return FileInfo(path, size, "zip-broken", "ZIP 但中央目录损坏（可能是自解压包或截断）")
    top = {n.split("/")[0] for n in names}
    if "AndroidManifest.xml" in names:
        return FileInfo(path, size, "apk", "Android APK", extra={"entries": names})
    if "[Content_Types].xml" in names:
        suffix = path.suffix.lower()
        kind = {".docx": "docx", ".xlsx": "xlsx", ".pptx": "pptx"}.get(suffix, "ooxml")
        return FileInfo(path, size, kind, f"OOXML 文档（{kind}）", extra={"entries": names})
    if "META-INF/MANIFEST.MF" in names:
        return FileInfo(path, size, "jar", "Java JAR", extra={"entries": names})
    return FileInfo(path, size, "zip", f"ZIP 归档（{len(names)} 个条目）", extra={"entries": names})
