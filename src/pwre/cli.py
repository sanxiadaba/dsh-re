"""命令行入口。"""

import argparse
import datetime as _dt
import os
import sys
from pathlib import Path

from . import __version__, armvec, decompile, diff, disasm, engines, firmware, fwmap, mem, native, proto, unpack
from .detect import FileInfo, entropy, packed_reasons, sniff
from .errors import ReError
from .out import emit, human_size, warn
from .scan import interesting, scan_file


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except ReError as exc:
        print(f"re: {exc.message}", file=sys.stderr)
        if exc.hint:
            print(f"    {exc.hint}", file=sys.stderr)
        return exc.code
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        if os.environ.get("RE_DEBUG"):
            raise
        print(f"re: 内部错误 {type(exc).__name__}: {exc}", file=sys.stderr)
        print("    RE_DEBUG=1 可看堆栈；请把命令和文件一起报上来", file=sys.stderr)
        return 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="re",
        description="逆向军刀：一条命令看清一个二进制、一个固件、一个安装包",
    )
    parser.add_argument("--version", action="version", version=f"re {__version__}")
    parser.add_argument("--json", action="store_true", help="输出完整 JSON（默认是给人读的紧凑文本）")
    sub = parser.add_subparsers(dest="cmd", metavar="<命令>")

    p = sub.add_parser("id", help="识别文件：格式、架构、编译器、哈希、关键字符串")
    p.add_argument("path")
    p.set_defaults(func=cmd_id)

    p = sub.add_parser("strings", help="提取字符串：偏移、编码、按类型过滤")
    p.add_argument("path")
    p.add_argument("-n", "--min", type=int, default=4, help="最短长度（默认 4）")
    p.add_argument("-m", "--max", type=int, default=0, help="最长长度（0 表示不限）")
    p.add_argument("-k", "--kind", action="append", default=None,
                   help="只留某类：url/path/email/ip/format/hex/pem，可重复")
    p.add_argument("-c", "--contains", default=None, help="只留包含该子串的")
    p.add_argument("-r", "--regex", default=None, help="只留匹配该正则的")
    p.add_argument("-l", "--limit", type=int, default=0, help="最多输出条数（0 表示不限）")
    p.add_argument("--no-utf16", action="store_true", help="不扫 UTF-16LE")
    p.set_defaults(func=cmd_strings)

    p = sub.add_parser("hex", help="Intel HEX / S-record：段表、校验、转 BIN")
    p.add_argument("path")
    p.add_argument("--base", type=_number, default=None, help="裸 BIN 的加载地址，如 0x08000000")
    p.add_argument("--to", choices=["bin"], default=None, help="转换目标格式")
    p.add_argument("--out", default=None, help="输出文件（--to bin 时必需）")
    p.add_argument("--fill", type=_number, default=0xFF, help="空洞填充字节（默认 0xFF）")
    p.set_defaults(func=cmd_hex)

    p = sub.add_parser("fw", help="固件：向量表、入口、中断、代码区")
    p.add_argument("path")
    p.add_argument("--base", type=_number, default=None, help="裸 BIN 的加载地址，如 0x08000000")
    p.add_argument("--vectors", action="store_true", help="列出全部中断向量")
    p.set_defaults(func=cmd_fw)

    p = sub.add_parser("doctor", help="体检：依赖、引擎、版本")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("pe", help="PE 结构：节、导入、导出、资源、签名")
    p.add_argument("path")
    p.set_defaults(func=cmd_pe)

    p = sub.add_parser("elf", help="ELF 结构：节、依赖、加固、符号")
    p.add_argument("path")
    p.set_defaults(func=cmd_elf)

    p = sub.add_parser("dis", help="反汇编：按地址/符号/入口")
    p.add_argument("path")
    p.add_argument("--at", type=_number, default=None, help="起始地址，如 0x08000114")
    p.add_argument("--sym", default=None, help="起始符号名")
    p.add_argument("-n", "--count", type=int, default=20, help="指令条数（默认 20，上限 400）")
    p.add_argument("--arch", default=None, help="架构（固件推断不出时必填）")
    p.add_argument("--bits", type=int, default=None, help="位宽：16/32/64")
    p.add_argument("--base", type=_number, default=None, help="裸 BIN 的加载地址")
    p.set_defaults(func=cmd_dis)

    p = sub.add_parser("funcs", help="函数表：地址、大小、基本块")
    p.add_argument("path")
    p.add_argument("-l", "--limit", type=int, default=40, help="最多显示几个（默认 40）")
    p.add_argument("--arch", default=None)
    p.add_argument("--bits", type=int, default=None)
    p.add_argument("--deep", action="store_true", help="深度分析（aaaa，慢；PE 上可能几十秒）")
    p.add_argument("--force", action="store_true", help="文件疑似加壳也硬跑")
    p.set_defaults(func=cmd_funcs)

    p = sub.add_parser("xref", help="谁引用了这个地址")
    p.add_argument("path")
    p.add_argument("--at", type=_number, required=True, help="被引用的地址")
    p.add_argument("--arch", default=None)
    p.add_argument("--bits", type=int, default=None)
    p.add_argument("--deep", action="store_true", help="深度分析（aaaa，慢）")
    p.add_argument("--force", action="store_true", help="文件疑似加壳也硬跑")
    p.set_defaults(func=cmd_xref)

    p = sub.add_parser("diff", help="两版对比：字节差异 + 结构差异")
    p.add_argument("a")
    p.add_argument("b")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("decompile", help="反编译一个函数（Ghidra）")
    p.add_argument("path")
    p.add_argument("--at", type=_number, default=None, help="函数地址")
    p.add_argument("--sym", default=None, help="函数名")
    p.add_argument("--base", type=_number, default=None, help="裸 BIN 的加载地址")
    p.add_argument("--timeout", type=int, default=300, help="Ghidra 超时秒数（默认 300）")
    p.set_defaults(func=cmd_decompile)

    p = sub.add_parser("mem", help="运行时内存：列进程、列模块、按地址 dump")
    p.add_argument("--list", action="store_true", help="列进程")
    p.add_argument("--filter", default="", help="按进程名过滤")
    p.add_argument("--pid", type=int, default=None, help="目标进程")
    p.add_argument("--modules", action="store_true", help="列模块（配合 --pid）")
    p.add_argument("--addr", type=_number, default=None, help="起始地址")
    p.add_argument("--size", type=_number, default=None, help="长度（字节）")
    p.add_argument("-o", "--out", default=None, help="dump 输出文件")
    p.set_defaults(func=cmd_mem)

    p = sub.add_parser("proto", help="报文：按帧切分，找恒定位与变化位")
    p.add_argument("path")
    p.add_argument("--frame", type=int, default=None, help="帧长（字节）")
    p.add_argument("--max", type=int, default=8, help="最多打印几帧（默认 8）")
    p.set_defaults(func=cmd_proto)

    p = sub.add_parser("decompile-all", help="把所有函数反编译到一个 .c（Ghidra，一次分析）")
    p.add_argument("path")
    p.add_argument("-o", "--out", default=None, help="输出 .c 文件")
    p.add_argument("--base", type=_number, default=None, help="裸 BIN 的加载地址")
    p.add_argument("--timeout", type=int, default=900, help="超时秒数（默认 900）")
    p.set_defaults(func=cmd_decompile_all)

    p = sub.add_parser("fwmap", help="固件结构：全量反汇编 + 函数地图 + 外设引用")
    p.add_argument("path")
    p.add_argument("-o", "--out", default=None, help="输出目录（默认 <文件名>.fwmap）")
    p.add_argument("--base", type=_number, default=None, help="裸 BIN 的加载地址")
    p.set_defaults(func=cmd_fwmap)

    p = sub.add_parser("unpack", help="剥包：zip/apk/jar/asar/tar/gz/xz/zst/cab/msi/pyinstaller")
    p.add_argument("path")
    p.add_argument("-o", "--out", default=None, help="输出目录（默认 <文件名>.unpacked）")
    p.add_argument("--force", action="store_true", help="目标目录非空也照剥")
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser("setup", help="下载并安装引擎")
    p.add_argument("--rizin", action="store_true", help="反汇编引擎（re dis/funcs/xref 必需）")
    p.add_argument("--ghidra", action="store_true", help="反编译器（re decompile 必需，会自动带 JDK）")
    p.add_argument("--java", action="store_true", help="只装 JDK 21")
    p.add_argument("--all", action="store_true", help="装齐 rizin + ghidra + JDK")
    p.set_defaults(func=cmd_setup)

    return parser


def _number(value: str) -> int:
    try:
        return int(value, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(f"不是合法数字：{value}")


# ------------------------------------------------------------------ id


def _timestamp(value: int) -> str:
    if not value:
        return "0（未设置）"
    stamp = _dt.datetime.fromtimestamp(value, _dt.timezone.utc)
    return stamp.strftime("%Y-%m-%d %H:%M:%S UTC")


def _pe_deps(info: FileInfo) -> tuple[list[str], int]:
    import pefile

    pe = pefile.PE(str(info.path))
    dlls, count = [], 0
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dlls.append(entry.dll.decode("latin-1", "replace"))
        count += len(entry.imports or [])
    return dlls, count


def cmd_id(args):
    path = Path(args.path)
    info = sniff(path)
    payload = {
        "path": str(path),
        "size": info.size,
        "kind": info.kind,
        "label": info.label,
        "arch": info.arch,
        "bits": info.bits,
        "endian": info.endian,
        "entry": info.entry,
        "sha256": info.sha256,
    }
    head = entropy(path.read_bytes()[: 2 << 20])
    lines = [
        f"文件     {path}",
        f"大小     {human_size(info.size)}（{info.size} 字节）",
        f"格式     {info.label}",
    ]
    if info.arch:
        lines.append(f"架构     {info.arch}" + (f"   {info.bits} 位" if info.bits else ""))
    if info.entry is not None:
        where = info.extra.get("entry_section")
        lines.append(f"入口     0x{info.entry:x}" + (f"（在 {where} 内）" if where else ""))

    if info.kind in ("pe", "dll"):
        extra = info.extra
        lines.append(f"编译器   linker {extra['linker']}，时间戳 {_timestamp(extra['timestamp'])}")
        sections = extra["sections"]
        names = [section["name"] for section in sections]
        lines.append(f"节       {len(names)} 个：{' '.join(names)}")
        reasons = packed_reasons(info)
        if reasons:
            lines.append("壳       疑似加壳/保护：" + "，".join(reasons))
        try:
            dlls, count = _pe_deps(info)
        except Exception as exc:
            warn(f"导入表读不出来：{exc}")
            dlls, count = [], 0
        if dlls:
            lines.append(f"导入     {count} 个函数 / {len(dlls)} 个 DLL")
            lines.append(f"依赖     {', '.join(dlls[:8])}{' …' if len(dlls) > 8 else ''}")
        payload["imports"] = dlls
        payload["sections"] = sections
    elif info.kind == "elf":
        extra = info.extra
        lines.append(f"类型     {extra['type']}")
        names = [section["name"] for section in extra["sections"] if section["name"]]
        lines.append(f"节       {len(names)} 个：{' '.join(names[:12])}{' …' if len(names) > 12 else ''}")
        payload["sections"] = extra["sections"]
    elif info.kind in ("asar", "apk", "jar", "zip", "docx", "xlsx", "pptx", "ooxml"):
        entries = info.extra.get("entries") or []
        if entries:
            lines.append(f"条目     {len(entries)} 个")
    elif info.kind == "unknown":
        lines.append(f"magic    {path.read_bytes()[:8].hex(' ')}")
        lines.append(f"熵       {head:.2f}{_entropy_note(head)}")

    if info.kind in ("ihex", "srec"):
        lines.append("下一步   re hex 看段与地址，re fw 看向量表与入口")
    elif info.kind == "unknown":
        samples = [text for _, _, text in scan_file(path, 6) if interesting(text)][:5]
        if samples:
            lines.append("线索     以下字符串值得先看：")
            lines.extend(f"         {text[:100]}" for text in samples)

    lines.append(f"SHA256   {payload['sha256']}")
    payload["entropy"] = round(head, 2)
    emit(args, lines, payload)
    return 0


def cmd_strings(args):
    path = Path(args.path)
    if not path.is_file():
        raise ReError(f"不是文件：{path}")
    rows = scan_file(path, min_len=args.min, utf16=not args.no_utf16)
    kinds = set(args.kind or [])
    regex = None
    if args.regex:
        import re

        try:
            regex = re.compile(args.regex)
        except re.error as exc:
            raise ReError(f"正则写错了：{exc}")
    out = []
    for offset, encoding, text in rows:
        if args.max and len(text) > args.max:
            continue
        if args.contains and args.contains not in text:
            continue
        if regex and not regex.search(text):
            continue
        if kinds:
            kind = interesting(text)
            if kind not in kinds:
                continue
        out.append((offset, encoding, text))
        if args.limit and len(out) >= args.limit:
            break
    lines = [f"{offset:#010x}  {encoding:<5}  {text}" for offset, encoding, text in out]
    if not lines:
        lines = ["（没有匹配的字符串）"]
    payload = [{"offset": o, "encoding": e, "text": t} for o, e, t in out]
    emit(args, lines, payload)
    return 0


# --------------------------------------------------------------- 结构


def cmd_pe(args):
    path = Path(args.path)
    kind = sniff(path).kind
    if kind not in ("pe", "dll"):
        raise ReError(f"{path.name} 不是 PE（识别为 {kind}）", hint="ELF 用 re elf；固件用 re fw")
    lines, payload = native.pe_report(path)
    emit(args, [f"文件     {path}", *lines], {"path": str(path), **payload})
    return 0


def cmd_elf(args):
    path = Path(args.path)
    kind = sniff(path).kind
    if kind != "elf":
        raise ReError(f"{path.name} 不是 ELF（识别为 {kind}）", hint="PE 用 re pe")
    lines, payload = native.elf_report(path)
    emit(args, [f"文件     {path}", *lines], {"path": str(path), **payload})
    return 0


def cmd_dis(args):
    path = Path(args.path)
    rows = disasm.dis(path, args.at, args.sym, args.count, args.arch, args.bits, args.base)
    lines = [f"{row['addr']:#010x}  {row['bytes']:<12}  {row['disasm']}" for row in rows]
    if not lines:
        lines = ["（这个位置没有可反汇编的指令）"]
    emit(args, lines, {"path": str(path), "instructions": rows})
    return 0


def cmd_funcs(args):
    path = Path(args.path)
    rows, total = disasm.functions(path, limit=10_000, arch=args.arch, bits=args.bits, deep=args.deep, force=args.force)
    rows.sort(key=lambda row: row.get("size", 0) or 0, reverse=True)
    rows = rows[: args.limit]
    lines = [f"函数     {total} 个" + (f"，按大小列前 {len(rows)}" if total > len(rows) else "")]
    for row in rows:
        name = row.get("name", "?")
        lines.append(
            f"  {row.get('offset', 0):#010x}  {row.get('size', 0):>7,} 字节  "
            f"bb {row.get('nbbs', 0):<3} {name}"
        )
    emit(args, lines, {"path": str(path), "total": total, "functions": rows})
    return 0


def cmd_xref(args):
    path = Path(args.path)
    rows = disasm.xrefs(path, args.at, args.arch, args.bits, deep=args.deep, force=args.force)
    lines = [f"引用     0x{args.at:x} 的位置共 {len(rows)} 处"]
    for row in rows:
        lines.append(f"  {row.get('from', 0):#010x}  {row.get('type', ''):<8} {row.get('opcode', '')}")
    emit(args, lines, {"path": str(path), "at": args.at, "xrefs": rows})
    return 0


def cmd_diff(args):
    a, b = Path(args.a), Path(args.b)
    lines, payload = diff.compare(a, b)
    emit(args, lines, payload)
    return 0


def cmd_decompile(args):
    path = Path(args.path)
    result = decompile.decompile(path, args.at, args.sym, args.base, timeout=args.timeout)
    lines = [f"函数     {result['name']} @ {result['entry']}", "", result["c"]]
    emit(args, lines, {"path": str(path), **result})
    return 0


def cmd_mem(args):
    if args.list:
        rows = mem.list_processes(args.filter)
        lines = [f"进程     {len(rows)} 个"]
        for row in rows[:60]:
            lines.append(f"  {row['pid']:>6}  {row['name']}")
        if len(rows) > 60:
            lines.append(f"  … 还有 {len(rows) - 60} 个")
        emit(args, lines, {"processes": rows})
        return 0
    if args.pid is None:
        raise ReError("要给 --pid（或用 --list 先看进程）")
    if args.modules:
        rows = mem.modules(args.pid)
        lines = [f"模块     {len(rows)} 个（pid {args.pid}）"]
        for row in rows[:40]:
            lines.append(f"  {row['base']:#012x}  {row['size']:>10,}  {row['name']}")
        if len(rows) > 40:
            lines.append(f"  … 还有 {len(rows) - 40} 个")
        emit(args, lines, {"modules": rows})
        return 0
    if args.addr is None or args.size is None:
        raise ReError("dump 要给 --addr 和 --size", hint="例：--pid 1234 --addr 0x400000 --size 0x1000")
    if args.out:
        count = mem.dump(args.pid, args.addr, args.size, Path(args.out))
        emit(args, [f"写出     {args.out}（{count:,} 字节，pid {args.pid}，{args.addr:#x}）"],
             {"path": args.out, "size": count})
        return 0
    data = mem.read(args.pid, args.addr, args.size)
    lines = [f"内存     pid {args.pid}  {args.addr:#x}  {len(data):,} 字节"]
    lines += proto.hexdump(data, limit=max(1, args.size // 16))
    emit(args, lines, {"pid": args.pid, "addr": args.addr, "hex": data.hex()})
    return 0


def cmd_proto(args):
    path = Path(args.path)
    data = path.read_bytes()
    if not args.frame:
        raise ReError("要给 --frame（帧长）", hint="先 re hex / re id 看清楚结构；按帧切开才能看字段")
    frames = proto.split(data, args.frame)
    if not frames:
        raise ReError(f"文件只有 {len(data)} 字节，切不出 {args.frame} 字节的帧")
    stats = proto.analyze(frames)
    const = proto.ranges(stats, True)
    varying = proto.ranges(stats, False)
    lines = [
        f"文件     {path.name}  {len(data):,} 字节",
        f"帧       {len(frames)} 帧 × {args.frame} 字节",
        "恒定     " + "，".join(f"[{start:#x},{end:#x})" for start, end in const) if const else "恒定     无",
    ]
    if const:
        head = "".join(f"{byte:02x} " for byte in data[: min(len(data), args.frame)])
        lines.append(f"首帧     {head.strip()}")
    lines.append("变化     " + "，".join(f"[{start:#x},{end:#x})" for start, end in varying) if varying else "变化     无")
    for frame in frames[: args.max]:
        lines.append("帧 " + frame.hex(" "))
    emit(args, lines, {
        "frames": len(frames),
        "frame_len": args.frame,
        "constant": const,
        "varying": varying,
    })
    return 0


def cmd_decompile_all(args):
    path = Path(args.path)
    out = Path(args.out) if args.out else path.with_suffix(".all.c")
    stat = decompile.decompile_all(path, out, args.base, timeout=args.timeout)
    lines = [f"输出     {out}", f"函数     {stat}（成功/总数）"]
    emit(args, lines, {"path": str(path), "out": str(out), "stat": stat})
    return 0


def cmd_fwmap(args):
    path = Path(args.path)
    out = Path(args.out) if args.out else path.with_name(path.stem + ".fwmap")
    result = fwmap.run(path, out, args.base)
    top = sorted(result["peripherals"], key=lambda p: -p["count"])[:5]
    lines = [
        f"输出     {out}",
        f"函数     {len(result['functions'])} 个",
        f"外设     {len(result['peripherals'])} 个地址",
        f"映像     {result['size']:,} 字节，基址 {result['base']:#010x}",
    ]
    for item in top:
        lines.append(f"  {item['addr']:#010x}  {item['kind']:<22} {item['count']:>3} 次")
    emit(args, lines, {"out": str(out), "functions": len(result["functions"]),
                       "peripherals": len(result["peripherals"]), "base": result["base"]})
    return 0


def cmd_unpack(args):
    path = Path(args.path)
    dest = Path(args.out) if args.out else path.with_name(path.name + ".unpacked")
    items, kind = unpack.unpack(path, dest, force=args.force)
    files = [item for item in items if "path" in item]
    total = sum(item["size"] for item in files)
    lines = [f"格式     {kind}", f"输出     {dest}", f"条目     {len(files)} 个，共 {human_size(total)}"]
    for item in files[:20]:
        rel = Path(item["path"]).relative_to(dest).as_posix()
        lines.append(f"  {rel:<50} {item['size']:>10,}")
    if len(files) > 20:
        lines.append(f"  … 还有 {len(files) - 20} 个")
    notes = [item["note"] for item in items if "note" in item]
    lines.extend(f"备注     {note}" for note in notes)
    emit(args, lines, {"format": kind, "dest": str(dest), "files": files, "notes": notes})
    return 0


# --------------------------------------------------------------- 固件


def _image_head(image, kind: str) -> list[str]:
    low, high = image.span
    lines = [f"格式     {kind}"]
    lines.append(f"段       {len(image.segments)} 段，共 {image.total:,} 字节")
    for segment in image.segments[:8]:
        lines.append(f"  {segment.addr:#010x}  {len(segment.data):,} 字节")
    if len(image.segments) > 8:
        lines.append(f"  … 还有 {len(image.segments) - 8} 段")
    if image.segments:
        lines.append(f"范围     {low:#010x} – {high:#010x}")
    if image.records:
        lines.append(f"记录     {image.records:,} 条")
    if image.errors:
        lines.append(f"错误     {len(image.errors)} 处")
        for message in image.errors[:5]:
            lines.append(f"  {message}")
        if len(image.errors) > 5:
            lines.append(f"  … 还有 {len(image.errors) - 5} 处")
    return lines


def cmd_hex(args):
    path = Path(args.path)
    image = firmware.load(path, args.base)
    lines = _image_head(image, sniff(path).label)
    if image.start is not None:
        lines.append(f"起始     0x{image.start:08x}")
    if image.gaps():
        gaps = image.gaps()
        total = sum(end - start for start, end in gaps)
        lines.append(f"空洞     {len(gaps)} 处，共 {total:,} 字节")
    payload = {
        "segments": [{"addr": s.addr, "size": len(s.data)} for s in image.segments],
        "total": image.total,
        "span": list(image.span),
        "records": image.records,
        "errors": image.errors,
        "start": image.start,
    }
    if args.to == "bin":
        if not args.out:
            raise ReError("--to bin 要配 --out", hint="例如 --to bin --out firmware.bin")
        base, flat = image.to_flat(args.fill)
        Path(args.out).write_bytes(flat)
        lines.append(f"输出     {args.out}（{len(flat):,} 字节，基址 {base:#010x}，填充 {args.fill:#04x}）")
        payload["out"] = {"path": args.out, "base": base, "size": len(flat)}
    emit(args, lines, payload)
    return 0 if not image.errors else 1


def cmd_fw(args):
    path = Path(args.path)
    info = sniff(path)
    image = firmware.load(path, args.base)
    table = armvec.find_table(image, args.base)
    data = armvec.describe(table, image)
    low, high = data["image_span"]
    code_low, code_high = data["code_span"]
    lines = [
        f"文件     {path.name}（{info.label}）",
        f"段       {len(image.segments)} 段，共 {image.total:,} 字节，{low:#010x} – {high:#010x}",
        f"向量表   {table.base:#010x}   SP {table.sp:#010x}   Reset {table.reset & ~1:#010x}（Thumb）",
    ]
    if data["exceptions"]:
        items = "  ".join(f"{item['name']} {item['addr']:#010x}" for item in data["exceptions"])
        lines.append(f"异常     {items}")
    irqs = data["irqs"]
    if irqs:
        lines.append(f"中断     {len(irqs)} 个：IRQ{irqs[0]['index']} {irqs[0]['addr']:#010x}"
                     + (f" … IRQ{irqs[-1]['index']} {irqs[-1]['addr']:#010x}" if len(irqs) > 1 else ""))
    else:
        lines.append("中断     全 0（没有注册中断）")
    lines.append(f"代码区   {code_low:#010x} – {code_high + 1:#010x}（{code_high + 1 - code_low:,} 字节）")
    if image.errors:
        lines.append(f"错误     {len(image.errors)} 处（先跑 re hex 看清楚）")
    if args.vectors:
        lines.append("")
        lines.append("向量表")
        for index, value in table.entries:
            if not value & 1:
                continue
            name = armvec.EXCEPTIONS.get(index) or ("Reset" if index == 1 else f"IRQ{index - 16}")
            lines.append(f"  {index:>3}  {name:<10} {value & ~1:#010x}")
    payload = {"path": str(path), "kind": info.kind, **data}
    emit(args, lines, payload)
    return 0 if not image.errors else 1


# ------------------------------------------------------------- doctor


def cmd_doctor(args):
    lines = [f"re {__version__}  python {sys.version.split()[0]}  {sys.executable}"]
    lines.append("引擎")
    payload = {"version": __version__, "python": sys.version.split()[0], "engines": []}
    for row in engines.status():
        mark = "OK  " if row["ok"] else "缺失"
        path = row["path"] or row["purpose"]
        lines.append(f"  {mark} {row['name']:<8} {path}")
        payload["engines"].append(row)
    missing = [row["name"] for row in payload["engines"] if not row["ok"]]
    lines.append(f"数据目录 {engines.data_dir()}")
    if missing:
        lines.append("")
        lines.append(f"缺：{', '.join(missing)}")
        lines.append("装：re setup " + " ".join(f"--{name}" for name in missing))
    emit(args, lines, payload)
    return 0


def cmd_setup(args):
    names = []
    if args.all:
        names = ["rizin", "ghidra"]
    else:
        for name in ("rizin", "ghidra", "java"):
            if getattr(args, name):
                names.append(name)
    if not names:
        raise ReError("没说装什么", hint="用 --rizin / --ghidra / --all")
    code = engines.setup(names)
    if code == 0:
        print("装好了。运行 `re doctor` 复核。")
    return code


if __name__ == "__main__":
    sys.exit(main())
