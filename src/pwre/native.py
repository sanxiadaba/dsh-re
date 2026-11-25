"""PE / ELF 结构摘要：给 re pe / re elf 用。"""

from pathlib import Path

from .errors import ReError


def _flags(value: int) -> str:
    parts = []
    if value & 0x20000000:
        parts.append("X")
    if value & 0x80000000:
        parts.append("W")
    if value & 0x40000000:
        parts.append("R")
    if value & 0x02000000:
        parts.append("C")
    if value & 0x04000000:
        parts.append("I")
    if value & 0x00000040:
        parts.append("D")
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
        imports[dll] = [imp.name.decode("latin-1", "replace") for imp in entry.imports if imp.name]
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
            resources.append(str(entry.name or entry.id))
    if resources:
        lines.append(f"资源     {len(resources)} 类：{', '.join(resources[:10])}")

    signed = bool(
        hasattr(pe, "DIRECTORY_ENTRY_SECURITY")
        and getattr(pe, "DIRECTORY_ENTRY_SECURITY", None)
    )
    lines.append(f"签名     {'有 Authenticode' if signed else '无'}")
    payload = {
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "resources": resources,
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

        needed, soname, rpath = [], "", ""
        for section in elf.iter_sections():
            if section.name == ".dynamic":
                for tag in section.iter_tags():
                    if tag.entry.d_tag == "DT_NEEDED":
                        needed.append(tag.entry.d_val)
                    elif tag.entry.d_tag == "DT_SONAME":
                        soname = tag.entry.d_val
                    elif tag.entry.d_tag == "DT_RPATH":
                        rpath = tag.entry.d_val
        if needed:
            lines.append(f"依赖     {', '.join(needed)}")
        if soname:
            lines.append(f"SONAME   {soname}")
        if rpath:
            lines.append(f"RPATH    {rpath}")
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
