"""命令行入口。"""

import argparse
import datetime as _dt
import importlib
import os
import shutil
import sys
from pathlib import Path

from . import __version__, apk, armvec, chip, decompile, diff, disasm, engines, firmware, fwmap, gate, mem, native, patch, proto, repack, scan, serialport, unpack
from .detect import FileInfo, entropy, packer_name, packed_reasons, sniff
from .errors import ReError
from .out import emit, human_size, warn
from .scan import interesting, scan_file

KINDS = ("url", "path", "email", "ip", "format", "hex", "pem")


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # 全局开关放子命令后面也认：re id x --json 和 re --json id x 等价
    if "--json" in argv:
        while "--json" in argv:
            argv.remove("--json")
        argv.insert(0, "--json")
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    try:
        return args.func(args)
    except ReError as exc:
        print(f"re: {exc.message}", file=sys.stderr)
        if exc.hint:
            print(f"    {exc.hint}", file=sys.stderr)
        return exc.code
    except KeyboardInterrupt:
        return 130
    except (PermissionError, FileNotFoundError, IsADirectoryError, NotADirectoryError) as exc:
        print(f"re: 文件操作失败：{exc}", file=sys.stderr)
        print("    目标可能不存在、是目录，或没有写权限", file=sys.stderr)
        return 1
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
    p.add_argument("-k", "--kind", action="append", default=None, choices=list(KINDS),
                   help="只留某类：url/path/email/ip/format/hex/pem，可重复")
    p.add_argument("-c", "--contains", default=None, help="只留包含该子串的")
    p.add_argument("-r", "--regex", default=None, help="只留匹配该正则的")
    p.add_argument("-l", "--limit", type=int, default=200, help="最多输出条数（默认 200）")
    p.add_argument("--all", action="store_true", help="不限条数（30MB 的包会刷屏）")
    p.add_argument("-e", "--encoding", action="append", default=None, choices=list(scan.ENCODINGS),
                   help="只扫某种编码：ascii/utf16/utf16be/gbk，可重复")
    p.add_argument("--no-utf16", action="store_true", help="不扫 UTF-16")
    p.set_defaults(func=cmd_strings)

    p = sub.add_parser("hex", help="Intel HEX / S-record：段表、校验、转 BIN")
    p.add_argument("path")
    p.add_argument("--base", type=_number, default=None, help="裸 BIN 的加载地址，如 0x08000000")
    p.add_argument("--to", choices=["bin"], default=None, help="转换目标格式")
    p.add_argument("--out", default=None, help="输出文件（--to bin 时必需）")
    p.add_argument("--fill", type=_byte, default=0xFF, help="空洞填充字节（默认 0xFF，0x00–0xFF）")
    p.add_argument("--force", action="store_true", help="--out 已存在也覆盖")
    p.set_defaults(func=cmd_hex)

    p = sub.add_parser("fw", help="固件：向量表、入口、中断、向量目标")
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
    p.add_argument("--base", type=_number, default=None, help="裸二进制的加载地址")
    p.add_argument("--force", action="store_true", help="文件疑似加壳也硬跑")
    p.add_argument("--timeout", type=int, default=None, help="rizin 分析超时秒数")
    p.set_defaults(func=cmd_funcs)

    p = sub.add_parser("xref", help="谁引用了这个地址")
    p.add_argument("path")
    p.add_argument("--at", type=_number, required=True, help="被引用的地址")
    p.add_argument("--arch", default=None)
    p.add_argument("--bits", type=int, default=None)
    p.add_argument("--deep", action="store_true", help="深度分析（aaaa，慢）")
    p.add_argument("--base", type=_number, default=None, help="裸二进制的加载地址")
    p.add_argument("--force", action="store_true", help="文件疑似加壳也硬跑")
    p.add_argument("--timeout", type=int, default=None, help="rizin 分析超时秒数")
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
    p.add_argument("--force", action="store_true", help="目标文件已存在也覆盖")
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
    p.add_argument("--force", action="store_true", help="输出文件已存在也覆盖")
    p.set_defaults(func=cmd_decompile_all)

    p = sub.add_parser("fwmap", help="固件结构：全量反汇编 + 函数地图 + 外设引用")
    p.add_argument("path")
    p.add_argument("-o", "--out", default=None, help="输出目录（默认 <文件名>.fwmap）")
    p.add_argument("--force", action="store_true", help="输出目录非空也写")
    p.add_argument("--partial", action="store_true", help="没有 rizin 时只出线性反汇编（不推荐）")
    p.add_argument("--base", type=_number, default=None, help="裸 BIN 的加载地址")
    p.set_defaults(func=cmd_fwmap)

    p = sub.add_parser("unpack", help="剥包：zip/apk/jar/asar/tar/gz/xz/zst/cab/msi/pyinstaller")
    p.add_argument("path")
    p.add_argument("-o", "--out", default=None, help="输出目录（默认 <文件名>.unpacked）")
    p.add_argument("--force", action="store_true", help="目标目录非空也照剥")
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser("apk", help="APK 结构：包名、版本、框架、壳、原生库、SDK 线索")
    p.add_argument("path")
    p.set_defaults(func=cmd_apk)

    p = sub.add_parser("patch", help="打补丁：按计划改字节、加节、装 5 字节跳板")
    p.add_argument("--plan", required=True, help="补丁计划 JSON（file + ops）")
    p.add_argument("--dry-run", action="store_true", help="只演算，不写文件")
    p.set_defaults(func=cmd_patch)

    p = sub.add_parser("repack", help="重打包 APK：替换文件、对齐、重签、校验")
    p.add_argument("src")
    p.add_argument("-o", "--out", required=True, help="输出 APK 路径")
    p.add_argument("-r", "--replace", default=None, help="替换目录（按相对路径覆盖包内同名条目）")
    p.add_argument("--no-align", action="store_true", help="不做 4 字节对齐")
    p.add_argument("--sign", action="store_true", help="重打包后重签")
    p.add_argument("--keystore", default=None, help="已有 keystore（.jks/.keystore）")
    p.add_argument("--ks-pass", default=None, help="keystore 口令")
    p.add_argument("--key-alias", default=None, help="密钥别名")
    p.add_argument("--key-pass", default=None, help="密钥口令（默认同 keystore 口令）")
    p.add_argument("--gen-key", default=None, help="先用 keytool 生成密钥到这个路径，再签")
    p.add_argument("--dname", default="CN=re, O=dsh-re, C=CN", help="--gen-key 的证书主题")
    p.set_defaults(func=cmd_repack)

    p = sub.add_parser("gate", help="判定：客户端可改，还是服务端权威")
    p.add_argument("path")
    p.add_argument("--probe", default=None, help="额外探测这个 URL（只看响应是不是加密信封）")
    p.add_argument("--timeout", type=float, default=8.0, help="探测超时秒数（默认 8）")
    p.set_defaults(func=cmd_gate)

    p = sub.add_parser("chip", help="真硬件：J-Link/SWD 探测、读回、比对、烧写")
    p.add_argument("path", nargs="?", default=None, help="固件文件（--compare/--flash 时给）")
    p.add_argument("--info", action="store_true", help="连上芯片读 CPUID 与向量表")
    p.add_argument("--dump", default=None, help="把 flash 读回这个文件")
    p.add_argument("--compare", action="store_true", help="芯片 flash 与 path 逐字节比对")
    p.add_argument("--flash", action="store_true", help="把 path 烧进芯片（要配 --yes）")
    p.add_argument("--yes", action="store_true", help="确认烧写（会擦除整个 flash）")
    p.add_argument("--device", default=None, help="J-Link 器件名，例如 PY32F030")
    p.add_argument("--base", type=_number, default=0x08000000, help="flash 起始地址")
    p.add_argument("--size", type=_number, default=0x8000, help="读多少字节（上限 16 MiB）")
    p.add_argument("--speed", type=int, default=4000, help="SWD 速度 kHz")
    p.add_argument("--devices-xml", default=None, help="额外的 J-Link 器件库（如 Keil 器件包里的 JLinkDevices.xml）")
    p.add_argument("--force", action="store_true", help="--dump 的目标已存在也覆盖")
    p.add_argument("--timeout", type=int, default=120, help="单次 J-Link 调用超时秒数（默认 120）")
    p.set_defaults(func=cmd_chip)

    p = sub.add_parser("serial", help="串口：列端口、监听、环回自检、收发")
    p.add_argument("-p", "--port", default=None, help="串口名，例如 COM11")
    p.add_argument("-b", "--baud", type=int, default=115200, help="波特率")
    p.add_argument("--list", action="store_true", help="列出本机串口")
    p.add_argument("--listen", type=float, default=0.0, help="监听多少秒")
    p.add_argument("--loopback", action="store_true", help="发探针并校验回显（验证短接/接线）")
    p.add_argument("--send", default=None, help="发送 text:内容 或 hex:01 02 03")
    p.add_argument("--wait", type=float, default=1.0, help="发送后等多久收（秒）")
    p.set_defaults(func=cmd_serial)

    p = sub.add_parser("setup", help="下载并安装引擎")
    p.add_argument("--rizin", action="store_true", help="反汇编引擎（re dis/funcs/xref 必需）")
    p.add_argument("--ghidra", action="store_true", help="反编译器（re decompile 必需，会自动带 JDK）")
    p.add_argument("--java", action="store_true", help="装 JDK（版本按 Ghidra 要求，当前 25）")
    p.add_argument("--buildtools", action="store_true", help="装 Android build-tools（apksigner/zipalign）")
    p.add_argument("--all", action="store_true", help="装齐 java + rizin + ghidra")
    p.set_defaults(func=cmd_setup)

    # 四簇（设备/插桩/抓包/证据）各自带 add_parser；模块没合入时给个明确的骨架，
    # 让并行开发期也能 `re dev list` 这种调用拿到"尚未实现"而不是 argparse 的 invalid choice。
    _add_optional(sub, "dev", "设备/模拟器生命周期")
    _add_optional(sub, "dyn", "frida 插桩")
    _add_optional(sub, "net", "抓包与 flow")
    _add_optional(sub, "case", "证据目录与报告")

    return parser


# 子命令名 ≠ 模块名：R-01 是 device.py、R-03 是 netcap.py。
# 不映射的话 `re dev`/`re net` 永远找不到模块，合入后也只会落到 stub。
_OPTIONAL_MODULES = {"dev": "device", "dyn": "dyn", "net": "netcap", "case": "case"}


def _add_optional(subparsers, name, help_text):
    """模块在就让它自己注册子命令；不在就注册一个报 code=3 的骨架。"""
    module = _OPTIONAL_MODULES.get(name, name)
    try:
        mod = importlib.import_module(f"pwre.{module}")
    except ImportError:
        mod = None
    if mod is not None and hasattr(mod, "add_parser"):
        mod.add_parser(subparsers)
        return
    p = subparsers.add_parser(name, help=help_text)
    # 骨架也要吃下 `re dev list` 这种尾部参数（含 -x 形式）：否则 argparse 先报
    # 用法错误（2），调用方看到的就不是"尚未实现"（3）。
    p.add_argument("rest", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)

    def _stub(args, _name=name):
        raise ReError(f"re {_name} 尚未实现", hint="该簇尚未合入当前分支", code=3)

    p.set_defaults(func=_stub)


def _byte(value: str) -> int:
    number = _number(value)
    if not 0 <= number <= 0xFF:
        raise argparse.ArgumentTypeError(f"必须是 0x00–0xFF，收到 {value}")
    return number


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


def _pe_deps(info: FileInfo) -> tuple[list[str], int, dict]:
    import pefile

    from .native import version_info

    pe = pefile.PE(str(info.path))
    dlls, count = [], 0
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dlls.append(entry.dll.decode("latin-1", "replace"))
        count += len(entry.imports or [])
    return dlls, count, version_info(pe)


def _entropy_note(value: float) -> str:
    """给熵值补一句人话判断。"""
    if value >= 7.9:
        return "（接近 8：几乎肯定是压缩或加密）"
    if value >= 7.0:
        return "（偏高：可能压缩或加密）"
    if value <= 1.0:
        return "（接近 0：大量重复字节）"
    return ""


def _head_bytes(path: Path, count: int) -> bytes:
    """只读文件头：大文件整读会把内存吃光，头读只要 count 字节。"""
    with open(path, "rb") as fh:
        return fh.read(count)


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
    head = entropy(_head_bytes(path, 2 << 20))
    # 壳的判定也进 JSON：文本行里说了壳名，机器读的载荷里不能没有
    packed = packed_reasons(info)
    payload["packer"] = packer_name(info)
    payload["packed_reasons"] = packed
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
        reasons = packed
        if reasons:
            name = packer_name(info)
            prefix = f"{name} 壳：" if name else "疑似加壳/保护："
            lines.append("壳       " + prefix + "，".join(reasons))
            if name:
                lines.append("下一步   re unpack（UPX 这类壳会直接脱掉）")
        try:
            dlls, count, version = _pe_deps(info)
        except Exception as exc:
            warn(f"导入表读不出来：{exc}")
            dlls, count, version = [], 0, {}
        if version:
            keys = ("ProductName", "FileDescription", "FileVersion", "CompanyName")
            brief = "  ".join(f"{key}={version[key]}" for key in keys if version.get(key))
            if brief:
                lines.append(f"版本信息 {brief}")
            payload["version_info"] = version
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
        count = entries if isinstance(entries, int) else len(entries)
        if count:
            lines.append(f"条目     {count} 个")
    elif info.kind == "unknown":
        lines.append(f"magic    {_head_bytes(path, 8).hex(' ')}")
        lines.append(f"熵       {head:.2f}{_entropy_note(head)}")

    if info.kind in ("ihex", "srec"):
        lines.append("下一步   re hex 看段与地址，re fw 看向量表与入口")
    elif info.kind == "unknown":
        blob = _head_bytes(path, 4 << 20)
        samples = [text for _, _, text in scan.scan(blob, 6) if interesting(text)][:5]
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
    if args.min < 2:
        warn(f"-n {args.min} 太小，按 2 处理（最短长度下限就是 2）")
    encodings = tuple(args.encoding) if args.encoding else scan.ENCODINGS
    if args.no_utf16:
        encodings = tuple(name for name in encodings if not name.startswith("utf16"))
    rows = scan.scan_file(path, min_len=args.min, encodings=encodings)
    kinds = set(args.kind or [])
    regex = None
    if args.regex:
        import re

        try:
            regex = re.compile(args.regex)
        except re.error as exc:
            raise ReError(f"正则写错了：{exc}")
    limit = 0 if args.all else max(0, args.limit)
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
        if limit and len(out) >= limit:
            break
    lines = [f"{offset:#010x}  {encoding:<7}  {text}" for offset, encoding, text in out]
    if not lines:
        lines = [f"（没有匹配的字符串；本次扫了 {'/'.join(encodings)}，共找到 0 条）"]
    elif limit and len(rows) > len(out):
        lines.append(f"… 只显示前 {len(out)} 条（加 --all 看全部）")
    payload = [{"offset": o, "encoding": e, "text": t} for o, e, t in out]
    emit(args, lines, payload)
    return 0


# --------------------------------------------------------------- 结构


def cmd_pe(args):
    path = Path(args.path)
    info = sniff(path)
    kind = info.kind
    if kind not in ("pe", "dll"):
        hint = {
            "elf": "ELF 用 re elf",
            "apk": "APK 用 re apk（结构）或 re unpack（摊开）",
            "zip": "压缩包用 re unpack",
            "ihex": "固件用 re hex / re fw",
            "srec": "固件用 re hex / re fw",
        }.get(kind, "先用 re id 看清楚它是什么")
        raise ReError(f"{path.name} 不是 PE（识别为 {info.label}）", hint=hint)
    lines, payload = native.pe_report(path)
    emit(args, [f"文件     {path}", *lines], {"path": str(path), **payload})
    return 0


def cmd_elf(args):
    path = Path(args.path)
    info = sniff(path)
    kind = info.kind
    if kind != "elf":
        hint = {"pe": "PE 用 re pe", "dll": "PE 用 re pe",
                "apk": "APK 用 re apk", "zip": "压缩包用 re unpack"}.get(kind, "先用 re id 看清楚")
        raise ReError(f"{path.name} 不是 ELF（识别为 {info.label}）", hint=hint)
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
    rows, total = disasm.functions(path, limit=10_000, arch=args.arch, bits=args.bits, deep=args.deep, force=args.force, base=getattr(args, "base", None), timeout=getattr(args, "timeout", None))
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
    rows = disasm.xrefs(path, args.at, args.arch, args.bits, deep=args.deep, force=args.force, base=getattr(args, "base", None), timeout=getattr(args, "timeout", None))
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
        rows, skipped = mem.list_processes(args.filter)
        lines = [f"进程     {len(rows)} 个" + (f"（另有 {skipped} 个打不开，权限不足）" if skipped else "")]
        for row in rows[:60]:
            lines.append(f"  {row['pid']:>6}  {row['name']}")
        if len(rows) > 60:
            lines.append(f"  … 还有 {len(rows) - 60} 个")
        emit(args, lines, {"processes": rows, "skipped": skipped})
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
    if not 0 < args.size <= 64 << 20:
        raise ReError(f"--size 要在 1 到 64 MiB 之间，收到 {args.size}")
    if args.out:
        target = Path(args.out)
        if not target.parent.is_dir():
            raise ReError(f"输出目录不存在：{target.parent}", hint="先建目录，或换个 --out")
        if target.exists() and not args.force:
            raise ReError(f"目标已存在：{target}", hint="换个文件名，或加 --force 覆盖")
        count = mem.dump(args.pid, args.addr, args.size, target)
        emit(args, [f"写出     {args.out}（{count:,} 字节，pid {args.pid}，{args.addr:#x}）"],
             {"path": args.out, "size": count})
        return 0
    data = mem.read(args.pid, args.addr, args.size)
    lines = [f"内存     pid {args.pid}  {args.addr:#x}  {len(data):,} 字节"]
    lines += proto.hexdump(data, limit=32)
    if len(data) > 32 * 16:
        lines.append(f"  … 共 {len(data):,} 字节，要全量用 -o 落盘")
    emit(args, lines, {"pid": args.pid, "addr": args.addr, "size": len(data)})
    return 0


def cmd_proto(args):
    path = Path(args.path)
    if not path.is_file():
        raise ReError(f"不是文件：{path}")
    info = sniff(path)
    if info.kind != "unknown":
        raise ReError(
            f"{path.name} 是{info.label}，不是裸帧数据",
            hint="proto 只吃裸帧（不认格式的二进制）；认格式用 re id，容器/安装包用 re unpack",
            code=2,
        )
    data = path.read_bytes()
    if not args.frame or args.frame < 1:
        raise ReError("要给正的 --frame（帧长）", hint="先 re hex / re id 看清楚结构；按帧切开才能看字段")
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
    rest = len(data) % args.frame
    if rest:
        lines.append(f"尾部     {rest} 字节不足一帧，已忽略（换 --frame，或协议带同步字）")
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
    if out.exists() and not args.force:
        raise ReError(f"目标已存在：{out}", hint="换个 -o，或加 --force 覆盖")
    stat = decompile.decompile_all(path, out, args.base, timeout=args.timeout)
    lines = [f"输出     {out}", f"函数     {stat}（成功/总数）"]
    emit(args, lines, {"path": str(path), "out": str(out), "stat": stat})
    return 0


def cmd_fwmap(args):
    path = Path(args.path)
    out = Path(args.out) if args.out else path.with_name(path.stem + ".fwmap")
    if out.exists() and out.is_file():
        raise ReError(f"-o 是个文件：{out}", hint="fwmap 要一个目录，例如 -o out/fwmap")
    if out.exists() and any(out.iterdir()) and not args.force:
        raise ReError(f"输出目录非空：{out}", hint="换个 -o，或加 --force 覆盖")
    result = fwmap.run(path, out, args.base, partial=args.partial)
    top = sorted(result["peripherals"], key=lambda p: -p["count"])[:5]
    lines = [
        f"输出     {out}",
        f"函数     {len(result['functions'])} 个" + ("（线性模式：没有函数表）" if result.get("degraded") else ""),
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


def cmd_apk(args):
    path = Path(args.path)
    info = sniff(path)
    if info.kind != "apk":
        raise ReError(
            f"{path.name} 不是 APK（识别为 {info.label}）",
            hint="APK 长这样：顶层有 AndroidManifest.xml 的 zip；jar 用 re unpack",
        )
    lines, payload = apk.report(path)
    emit(args, lines, payload)
    return 0


# --------------------------------------------------------------- 改二进制


def cmd_patch(args):
    plan = patch.load_plan(Path(args.plan))
    result = patch.apply_plan(plan, dry_run=args.dry_run)
    target = Path(result["file"])
    mark = "[干跑] " if args.dry_run else ""
    lines = [
        f"{mark}{target.name}  {result['size_before']:,} → {result['size_after']:,} 字节",
    ]
    for change in result["changes"]:
        if change.get("superseded"):
            continue
        note = f"  {change['note']}" if change.get("note") else ""
        lines.append(
            f"  {change['kind']:<11} +0x{change['offset']:x} {change['length']}B  "
            f"{change['before'] or '-'} → {change['after']}{note}"
        )
    for section in result["sections"]:
        lines.append(
            f"  节 {section['name']:<8} VA=0x{section['va']:x} vsize={section['vsize']} "
            f"raw=0x{section['raw_offset']:x}+{section['raw_size']} ({section['status']})"
        )
    for warning in result.get("warnings", []):
        warn(warning)
    if not args.dry_run:
        lines.append(f"自检 {'通过' if result['verify'] else '失败'}")
    emit(args, lines, result)
    if not (args.dry_run or result["verify"]):
        raise ReError(
            "补丁写回后自检不一致",
            hint="文件可能被占用或写到一半；关掉占用进程后用副本重试",
        )
    return 0


def cmd_repack(args):
    src = Path(args.src)
    dst = Path(args.out)
    replace_dir = Path(args.replace) if args.replace else None
    result = repack.repack(src, dst, replace_dir=replace_dir, align=not args.no_align)
    lines = [
        f"{src.name} → {dst.name}  {result['entries']} 条，{human_size(result['size'])}，"
        f"对齐={result['alignment']}"
    ]
    if result["replaced"]:
        lines.append("  替换 " + "、".join(result["replaced"]))
    if result["unmatched"]:
        warn("替换目录里这些文件在包里没有同名条目：" + "、".join(result["unmatched"]))
    if result["duplicates"]:
        warn("源包里重名条目（只写第一份）：" + "、".join(result["duplicates"]))
    payload = {"repack": result}

    if args.gen_key or args.sign:
        if args.gen_key:
            if not (args.ks_pass and args.key_alias):
                raise ReError(
                    "--gen-key 还要给 --ks-pass 和 --key-alias",
                    hint="例：re repack in.apk -o out.apk --gen-key my.jks --ks-pass pass:123456 --key-alias re --sign",
                )
            generated = repack.gen_key(Path(args.gen_key), args.key_alias, args.ks_pass, args.dname)
            lines.append(
                f"生成密钥 {generated['keystore']}  alias={generated['alias']}  "
                f"{human_size(generated['size'])}"
            )
            payload["gen_key"] = generated
            keystore = Path(args.gen_key)
        else:
            if not args.keystore:
                raise ReError(
                    "--sign 要给 --keystore，或用 --gen-key 现场生成",
                    hint="已有密钥：--keystore x.jks --ks-pass 口令 --key-alias 别名",
                )
            keystore = Path(args.keystore)
        signed = repack.sign(dst, keystore, args.ks_pass or "", args.key_alias or "", args.key_pass)
        checked = repack.verify(dst)
        schemes = ",".join(checked["schemes"]) or "?"
        lines.append(
            f"签名 {schemes}  校验={'通过' if checked['ok'] else '失败'}  "
            f"{checked['sha256'][:16]}"
        )
        payload["sign"] = signed
        payload["verify"] = checked
        if not checked["ok"]:
            raise ReError(
                "签名校验没通过",
                hint="先看 apksigner 原始输出；口令/别名不对、APK 缺 AndroidManifest 都会走到这里",
            )

    emit(args, lines, payload)
    return 0


def cmd_gate(args):
    result = gate.gate(Path(args.path), probe_url=args.probe, timeout=args.timeout)
    verdict = {
        "client_patchable": "客户端可改",
        "server_authoritative": "疑似服务端权威",
        "inconclusive": "证据不足",
    }[result["verdict"]]
    lines = [
        f"{Path(args.path).name}  判定：{verdict}（置信度 {result['confidence']}）",
    ]
    for signal in result["signals"]:
        if signal["name"] == "api_hosts":
            lines.append(f"  {signal['weight']:+d} {signal['name']:<26} {signal['evidence']}")
        else:
            lines.append(f"  {signal['weight']:+d} {signal['name']:<26} {signal['evidence']}")
    probe = result.get("probe")
    if probe:
        state = "ok" if probe.get("ok") else f"失败({probe.get('error') or probe.get('status')})"
        lines.append(f"  探测 {probe['url']} → {state}")
    for step in result["next_steps"]:
        lines.append(f"  · {step}")
    emit(args, lines, result)
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
        if image.errors:
            raise ReError(
                f"映像有 {len(image.errors)} 处错误，拒绝转 BIN（先 re hex 看清楚）",
                hint="先用 re hex 看错误行；确认只是校验和错可以修好文件再转",
            )
        if not image.total:
            raise ReError("映像里没有数据，转 BIN 没有意义")
        target = Path(args.out)
        if not target.parent.is_dir():
            raise ReError(f"输出目录不存在：{target.parent}", hint="先建目录，或换个 --out")
        if target.exists() and not args.force:
            raise ReError(f"目标已存在：{target}", hint="换个文件名，或加 --force 覆盖")
        base, flat = image.to_flat(args.fill)
        target.write_bytes(flat)
        lines.append(f"输出     {args.out}（{len(flat):,} 字节，基址 {base:#010x}，填充 {args.fill:#04x}）")
        payload["out"] = {"path": args.out, "base": base, "size": len(flat)}
    emit(args, lines, payload)
    return 0 if not image.errors else 1


def cmd_fw(args):
    path = Path(args.path)
    info = sniff(path)
    if info.kind in ("pe", "dll", "elf", "macho", "macho-fat", "wasm", "dex"):
        raise ReError(
            f"{path.name} 是 {info.label}，不是固件",
            hint="看结构用 re pe / re elf；固件是 .hex / .srec，或者带向量表的裸 .bin",
        )
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
    common = data["common_handler"]
    if irqs:
        line = f"中断     {len(irqs)} 个 Thumb 目标"
        if common["count"] > 1:
            line += f"（其中 {common['count']} 个都指向 {common['addr']:#010x}，通常是默认处理）"
        lines.append(line)
        nz = [item for item in irqs if item["addr"] != common["addr"]]
        if nz:
            shown = "  ".join(f"IRQ{item['index']} {item['addr']:#010x}" for item in nz[:6])
            lines.append(f"独立处理 {shown}" + (f" … 还有 {len(nz) - 6} 个" if len(nz) > 6 else ""))
    else:
        lines.append(f"中断     没有 Thumb 向量（表里 {data['reserved']} 个槽保留或指向映像外）")
    lines.append(f"向量目标 {code_low:#010x} – {code_high + 1:#010x}（{code_high + 1 - code_low:,} 字节，不是代码总量）")
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


def _entry_checks() -> tuple[list[str], dict]:
    """入口三项：re.cmd 的 CRLF、console script、PATH。任一项缺，`re` 就不是随手能跑的命令。"""
    root = Path(__file__).resolve().parents[2]
    lines, payload = [], {}

    script = root / "re.cmd"
    raw = script.read_bytes() if script.is_file() else b""
    cr, lf = raw.count(b"\r"), raw.count(b"\n")
    # cmd.exe 逐行解析；只剩 LF 时整行被当成一条命令（`'t' 不是内部命令`）
    crlf = bool(raw) and cr > 0 and cr >= lf - 1
    lines.append(f"  {'OK  ' if crlf else '缺  '} re.cmd   CRLF={crlf}（{cr} CR / {lf} LF）")
    if not crlf:
        lines.append("       修法：按 CRLF 重写 re.cmd（.gitattributes 已声明 *.cmd eol=crlf），或重新检出")
    payload["re_cmd"] = {"path": str(script), "exists": script.is_file(), "crlf": crlf,
                         "cr": cr, "lf": lf}

    exe = root / ".venv" / "Scripts" / "re.exe"
    has_exe = exe.is_file()
    where = str(exe) if has_exe else "不在 .venv\\Scripts 里"
    lines.append(f"  {'OK  ' if has_exe else '缺  '} re.exe   {where}")
    if not has_exe:
        lines.append("       修法：在仓库根 python -m venv .venv 后 .venv\\Scripts\\pip install -e .")
    payload["re_exe"] = {"path": str(exe), "exists": has_exe}

    on_path = shutil.which("re")
    lines.append(f"  {'OK  ' if on_path else '缺  '} PATH     {on_path or 're 不在 PATH'}")
    if not on_path:
        lines.append("       修法：把仓库根加进 PATH，或直接用 re.cmd 的完整路径")
    payload["path"] = {"which": on_path, "on_path": bool(on_path)}
    return lines, payload


def cmd_doctor(args):
    lines = [f"re {__version__}  python {sys.version.split()[0]}  {sys.executable}"]
    lines.append("引擎")
    payload = {"version": __version__, "python": sys.version.split()[0], "engines": []}
    for row in engines.status():
        mark = "OK  " if row["ok"] else "缺失"
        path = row["path"] or row["purpose"]
        suffix = f"  {row['note']}" if row.get("note") else ""
        lines.append(f"  {mark} {row['name']:<8} {path}{suffix}")
        payload["engines"].append(row)
    missing = [row["name"] for row in payload["engines"] if not row["ok"]]
    lines.append("可选工具")
    for row in engines.optional_status():
        mark = "OK  " if row["path"] else "缺失"
        lines.append(f"  {mark} {row['name']:<8} {row['path'] or row['purpose']}")
        payload.setdefault("tools", []).append(row)
    lines.append("入口")
    entry_lines, entry_payload = _entry_checks()
    lines.extend(entry_lines)
    payload["entry"] = entry_payload
    lines.append(f"数据目录 {engines.data_dir()}")
    if missing:
        lines.append("")
        lines.append(f"缺：{', '.join(missing)}")
        lines.append("装：re setup " + " ".join(f"--{name}" for name in missing))
    emit(args, lines, payload)
    return 1 if missing else 0


def cmd_chip(args):
    if args.flash:
        if not args.path:
            raise ReError("--flash 要给固件文件")
        if not args.yes:
            raise ReError(
                "烧写会先擦除整个 flash，确认后才执行",
                hint="确认目标无误后加 --yes；不确定就先 --compare",
            )
        result = chip.flash(Path(args.path), args.device, args.base, args.speed,
                            devices_xml=args.devices_xml, timeout=max(args.timeout, 60))
        lines = [f"烧写     {result['wrote']}", f"校验     {result['verify']}"]
        emit(args, lines, result)
        return 0
    if args.compare:
        if not args.path:
            raise ReError("--compare 要给固件文件")
        data = chip.compare(Path(args.path), args.base, args.size, args.device, args.speed,
                            devices_xml=args.devices_xml, timeout=args.timeout)
        head = "完全相同" if data["diff"] == 0 else f"{data['diff']:,} 字节不同"
        lines = [
            f"文件     {data['file']}  {data['file_size']:,} 字节",
            f"芯片     {data['chip_size']:,} 字节（非 0xFF {data['chip_nonff']:,}）",
            f"结论     {head}",
        ]
        if data.get("outside_window"):
            lines.append(f"注意     {data['outside_window']:,} 字节落在读回窗口外（加大 --size）")
        for addr, want, got in data["first_diffs"][:6]:
            lines.append(f"  {addr:#010x}  文件 {want:#04x}  芯片 {got:#04x}")
        if len(data["first_diffs"]) >= 6:
            lines.append("  … 只列前 6 处")
        emit(args, lines, data)
        return 0 if data["diff"] == 0 else 1
    if args.dump:
        out = chip.dump(Path(args.dump), args.base, args.size, args.device, args.speed,
                        force=args.force, devices_xml=args.devices_xml, timeout=args.timeout)
        emit(args, [f"读回     {out}（{out.stat().st_size:,} 字节，{args.base:#x} 起）"],
             {"path": str(out), "size": out.stat().st_size})
        return 0
    info = chip.probe(args.device, args.speed, args.devices_xml, timeout=args.timeout)
    lines = [
        f"器件     {info['device']}",
        f"CPUID    {info['cpuid']:#010x}",
        f"向量表   SP {info['sp']:#010x}   Reset {info['target']:#010x}"
        + ("（Thumb）" if info["thumb"] else "（没有 Thumb 位，可能不是 Cortex-M）"),
    ]
    emit(args, lines, info)
    return 0


def cmd_serial(args):
    if args.list:
        rows = serialport.ports()
        lines = [f"串口     {len(rows)} 个"]
        for row in rows:
            lines.append(f"  {row['device']:<10} {row['description']}")
        emit(args, lines, {"ports": rows})
        return 0
    if not args.port:
        raise ReError("要给 -p COMx（或 --list 看有哪些）")
    if args.loopback:
        data = serialport.loopback(args.port, args.baud)
        head = "回显一致" if data["echo"] else "回显不一致"
        lines = [f"端口     {data['port']} @ {data['baud']}", f"结论     {head}",
                 f"发出     {data['sent']!r}", f"收回     {data['received'][:64]!r}"]
        emit(args, lines, {"port": data["port"], "echo": data["echo"], "size": len(data["received"])})
        return 0 if data["echo"] else 1
    if args.send:
        data = serialport.exchange(args.port, args.baud, args.send, args.wait)
        lines = [f"发出     {data['sent']!r}", f"收回     {data['size']} 字节"]
        lines += serialport.hexdump(data["received"])
        if not data["size"]:
            lines.append("（没有收到任何字节）")
        emit(args, lines, {"sent": data["sent"].hex(), "received": data["received"].hex()})
        return 0
    if args.listen < 0:
        raise ReError(f"--listen 不能为负：{args.listen}")
    if args.send is not None and not args.send.strip():
        raise ReError("--send 是空的", hint="给 text:内容 或 hex:01 02")
    seconds = args.listen or 2.0
    data = serialport.listen(args.port, args.baud, seconds)
    lines = [f"端口     {args.port} @ {args.baud}，监听 {seconds:g}s", f"收到     {len(data)} 字节"]
    lines += serialport.hexdump(data)
    emit(args, lines, {"port": args.port, "size": len(data), "hex": data.hex()})
    return 0


def cmd_setup(args):
    names = []
    if args.all:
        names = ["java", "rizin", "ghidra"]
    else:
        for name in ("rizin", "ghidra", "java", "buildtools"):
            if getattr(args, name):
                names.append(name)
    if not names:
        raise ReError("没说装什么", hint="用 --rizin / --ghidra / --java / --buildtools / --all")
    code = engines.setup(names)
    if code == 0:
        print("装好了。运行 `re doctor` 复核。")
    return code


if __name__ == "__main__":
    sys.exit(main())
