"""PE / ELF 结构摘要：给 re pe / re elf 用。"""

from pathlib import Path

from .errors import ReError

RESOURCE_TYPES = {
    1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG", 6: "STRINGTABLE",
    7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR", 10: "RCDATA", 11: "MESSAGETABLE",
    12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION", 17: "DLGINCLUDE",
    19: "PLUGPLAY", 20: "VXD", 21: "ANICURSOR", 22: "ANIICON", 23: "HTML", 24: "MANIFEST",
}


def version_info(pe) -> dict:
    """VERSIONINFO 里的产品名/版本/公司——逆向第一眼就该知道这是什么软件。"""
    out = {}
    try:
        for group in pe.FileInfo or []:
            for entry in group:
                for table in getattr(entry, "StringTable", []) or []:
                    for key, value in table.entries.items():
                        name = key.decode("utf-8", "replace")
                        out.setdefault(name, value.decode("utf-8", "replace"))
    except Exception:
        return out
    return out


def _flags(value: int) -> str:
    parts = []
    if value & 0x20000000:
        parts.append("X")
    if value & 0x80000000:
        parts.append("W")
    if value & 0x40000000:
        parts.append("R")
    if value & 0x00000020:
        parts.append("c")  # CNT_CODE
    if value & 0x00000040:
        parts.append("d")  # CNT_INITIALIZED_DATA
    if value & 0x00000080:
        parts.append("u")  # CNT_UNINITIALIZED_DATA
    if value & 0x02000000:
        parts.append("s")  # MEM_DISCARDABLE
    return "".join(parts) or "-"


def pe_report(path: Path) -> tuple[list[str], dict]:
    import pefile

    pe = pefile.PE(str(path))
    sections = []
    lines = ["节"]
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("latin-1")
        row = {
            "name": name,
            "rva": section.VirtualAddress,
            "vsize": section.Misc_VirtualSize,
            "raw": section.SizeOfRawData,
            "flags": _flags(section.Characteristics),
            "entropy": round(section.get_entropy(), 2),
        }
        sections.append(row)
        lines.append(
            f"  {name:<10} rva {row['rva']:#010x}  {row['vsize']:>9,} 字节  "
            f"文件 {row['raw']:>9,}  {row['flags']:<4} 熵 {row['entropy']}"
        )

    imports = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("latin-1", "replace")
        names = []
        for imp in entry.imports:
            if imp.name:
                names.append(imp.name.decode("latin-1", "replace"))
            else:
                names.append(f"#{imp.ordinal}")
        imports[dll] = names
    if imports:
        lines.append("导入")
        for dll, names in list(imports.items()):
            sample = ", ".join(names[:6]) + (f" …（{len(names)}）" if len(names) > 6 else "")
            lines.append(f"  {dll:<24} {sample}")

    exports = {}
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports[exp.name.decode("latin-1", "replace")] = exp.address
    if exports:
        lines.append(f"导出     {len(exports)} 个")
        for name, addr in list(exports.items())[:12]:
            lines.append(f"  {name:<34} {addr:#010x}")

    resources = []
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if entry.name:
                resources.append(str(entry.name))
            else:
                resources.append(RESOURCE_TYPES.get(entry.id, str(entry.id)))
    if resources:
        lines.append(f"资源     {len(resources)} 类：{', '.join(resources[:10])}")

    info = version_info(pe)
    if info:
        keys = ("ProductName", "FileDescription", "FileVersion", "CompanyName", "OriginalFilename")
        brief = "  ".join(f"{key}={info[key]}" for key in keys if info.get(key))
        if brief:
            lines.append(f"版本信息 {brief}")

    # pefile 从不解析 DIRECTORY_ENTRY_SECURITY，只能看数据目录里的实际大小
    security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ]
    signed = bool(security.Size and security.VirtualAddress)
    lines.append(f"签名     {'有 Authenticode' if signed else '无'}")
    payload = {
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "resources": resources,
        "version_info": info,
        "signed": signed,
    }
    return lines, payload


def elf_report(path: Path) -> tuple[list[str], dict]:
    from elftools.elf.elffile import ELFFile

    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        lines = ["节"]
        sections = []
        for section in elf.iter_sections():
            if not section.name:
                continue
            row = {
                "name": section.name,
                "type": section["sh_type"],
                "addr": section["sh_addr"],
                "size": section["sh_size"],
            }
            sections.append(row)
            if section["sh_addr"] or section["sh_size"]:
                lines.append(f"  {row['name']:<20} {row['addr']:#010x}  {row['size']:>9,}  {row['type']}")

        needed, soname, rpath, runpath = [], "", "", ""
        for section in elf.iter_sections():
            if section.name == ".dynamic":
                for tag in section.iter_tags():
                    kind = tag.entry.d_tag
                    # pyelftools 已经把 d_val 里的字符串偏移解析成 tag.needed/.soname/.rpath
                    if kind == "DT_NEEDED":
                        needed.append(getattr(tag, "needed", str(tag.entry.d_val)))
                    elif kind == "DT_SONAME":
                        soname = getattr(tag, "soname", str(tag.entry.d_val))
                    elif kind == "DT_RPATH":
                        rpath = getattr(tag, "rpath", str(tag.entry.d_val))
                    elif kind == "DT_RUNPATH":
                        runpath = getattr(tag, "runpath", str(tag.entry.d_val))
        if needed:
            lines.append(f"依赖     {', '.join(needed)}")
        if soname:
            lines.append(f"SONAME   {soname}")
        if rpath:
            lines.append(f"RPATH    {rpath}")
        if runpath:
            lines.append(f"RUNPATH  {runpath}")
        symbols = 0
        if elf.get_section_by_name(".dynsym"):
            symbols = elf.get_section_by_name(".dynsym").num_symbols()
        hardened = []
        for segment in elf.iter_segments():
            if segment["p_type"] == "PT_GNU_STACK":
                hardened.append("NX" if segment["p_flags"] & 1 == 0 else "可执行栈")
            if segment["p_type"] == "PT_GNU_RELRO":
                hardened.append("RELRO")
        if hardened:
            lines.append(f"加固     {', '.join(hardened)}")
        payload = {
            "sections": sections,
            "needed": needed,
            "soname": soname,
            "rpath": rpath,
            "runpath": runpath,
            "dynsym": symbols,
            "hardened": hardened,
        }
        return lines, payload


def report(path: Path) -> tuple[list[str], dict]:
    from .detect import sniff

    kind = sniff(path).kind
    if kind in ("pe", "dll"):
        return pe_report(path)
    if kind == "elf":
        return elf_report(path)
    raise ReError(
        f"{path.name} 不是 PE/ELF（识别为 {kind}）",
        hint="PE/ELF 用本命令；固件用 re fw / re hex；归档用 re unpack",
    )
