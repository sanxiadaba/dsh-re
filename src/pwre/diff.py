"""两版对比：先字节级定位，再按格式给结构差异。"""

from pathlib import Path

from .detect import entropy, sniff

BLOCK = 4096


def _blocks(a: bytes, b: bytes) -> list[tuple[int, int]]:
    """返回不同的块区间（闭开区间），相邻块自动合并。"""
    limit = min(len(a), len(b))
    ranges = []
    start = None
    for offset in range(0, limit, BLOCK):
        same = a[offset: offset + BLOCK] == b[offset: offset + BLOCK]
        if same and start is not None:
            ranges.append((start, offset))
            start = None
        elif not same and start is None:
            start = offset
    if start is not None:
        ranges.append((start, limit))
    # 尾部长度不同，多出来的部分本身就是差异
    if len(a) != len(b):
        tail = max(len(a), len(b))
        if ranges and ranges[-1][1] == limit:
            ranges[-1] = (ranges[-1][0], tail)
        else:
            ranges.append((limit, tail))
    return ranges


def _pe_structure(path: Path):
    import pefile

    pe = pefile.PE(str(path))
    sections = {
        section.Name.rstrip(b"\x00").decode("latin-1"): {
            "rva": section.VirtualAddress,
            "vsize": section.Misc_VirtualSize,
            "raw": section.SizeOfRawData,
            "entropy": round(section.get_entropy(), 2),
        }
        for section in pe.sections
    }
    imports = {}
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = entry.dll.decode("latin-1", "replace")
        imports[dll] = {imp.name.decode("latin-1", "replace") for imp in entry.imports if imp.name}
    exports = set()
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        exports = {
            exp.name.decode("latin-1", "replace")
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols
            if exp.name
        }
    return {
        "sections": sections,
        "imports": imports,
        "exports": exports,
        "entry": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        "timestamp": pe.FILE_HEADER.TimeDateStamp,
    }


def compare(a: Path, b: Path) -> tuple[list[str], dict]:
    ka, kb = sniff(a), sniff(b)
    raw_a, raw_b = a.read_bytes(), b.read_bytes()
    ranges = _blocks(raw_a, raw_b)
    changed = sum(end - start for start, end in ranges)
    total = max(len(raw_a), len(raw_b))
    same_pct = 100.0 if total == 0 else (total - changed) * 100 / total

    lines = [
        f"A        {a.name}  {len(raw_a):,} 字节  熵 {entropy(raw_a[:2 << 20]):.2f}",
        f"B        {b.name}  {len(raw_b):,} 字节  熵 {entropy(raw_b[:2 << 20]):.2f}",
        f"相同     {same_pct:.2f}%（按 {BLOCK} 字节块）",
    ]
    if len(raw_a) != len(raw_b):
        lines.append(f"大小     B 比 A {'多' if len(raw_b) > len(raw_a) else '少'} {abs(len(raw_b) - len(raw_a)):,} 字节")
    if ranges:
        lines.append(f"差异     {len(ranges)} 段，共 {changed:,} 字节")
        for start, end in ranges[:5]:
            lines.append(f"  {start:#010x} – {end:#010x}  {end - start:,} 字节")
        if len(ranges) > 5:
            lines.append(f"  … 还有 {len(ranges) - 5} 段")
    else:
        lines.append("差异     无（内容完全相同）")

    payload = {
        "a": {"path": str(a), "size": len(raw_a), "kind": ka.kind},
        "b": {"path": str(b), "size": len(raw_b), "kind": kb.kind},
        "same_pct": round(same_pct, 2),
        "ranges": [{"start": start, "end": end} for start, end in ranges],
    }

    if ka.kind in ("pe", "dll") and kb.kind in ("pe", "dll"):
        sa, sb = _pe_structure(a), _pe_structure(b)
        names = list(dict.fromkeys(list(sa["sections"]) + list(sb["sections"])))
        lines.append("段")
        for name in names:
            left, right = sa["sections"].get(name), sb["sections"].get(name)
            if left is None:
                lines.append(f"  {name:<10} 只在 B")
            elif right is None:
                lines.append(f"  {name:<10} 只在 A")
            elif left == right:
                lines.append(f"  {name:<10} 相同")
            elif not left["raw"] and not right["raw"]:
                lines.append(f"  {name:<10} 虚拟大小 {left['vsize']:,}→{right['vsize']:,} 字节（文件里都没有原始数据）")
            else:
                lines.append(
                    f"  {name:<10} 不同：文件 {left['raw']:,}→{right['raw']:,} 字节，"
                    f"熵 {left['entropy']}→{right['entropy']}"
                )
        all_dlls = list(dict.fromkeys(list(sa["imports"]) + list(sb["imports"])))
        added, removed = [], []
        for dll in all_dlls:
            before = sa["imports"].get(dll, set())
            after = sb["imports"].get(dll, set())
            added += [f"{dll}!{name}" for name in sorted(after - before)]
            removed += [f"{dll}!{name}" for name in sorted(before - after)]
        if added:
            lines.append(f"导入新增 {len(added)}：{', '.join(added[:6])}{' …' if len(added) > 6 else ''}")
        if removed:
            lines.append(f"导入删除 {len(removed)}：{', '.join(removed[:6])}{' …' if len(removed) > 6 else ''}")
        exp_added = sorted(sb["exports"] - sa["exports"])
        exp_removed = sorted(sa["exports"] - sb["exports"])
        if exp_added or exp_removed:
            lines.append(f"导出     +{len(exp_added)} / -{len(exp_removed)}")
        if sa["entry"] != sb["entry"]:
            lines.append(f"入口     {sa['entry']:#x} → {sb['entry']:#x}")
        if sa["timestamp"] != sb["timestamp"]:
            lines.append(f"时间戳   {sa['timestamp']} → {sb['timestamp']}")
        payload["pe"] = {"imports_added": added, "imports_removed": removed,
                         "exports_added": exp_added, "exports_removed": exp_removed}
    return lines, payload
