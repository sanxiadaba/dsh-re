"""PE 补丁计划：改字节、加节、装跳板，全部数据化成可重放的 JSON。

一次 apply 只做三步：

1. 在一块内存镜像上按 ops 顺序执行；任何一条失败就整体放弃——绝不写半个文件；
2. 原子替换落盘；
3. 重新读回文件，逐条比对写入的字节，返回 verify。

计划是纯数据，所以能存盘、能 review、能重放，也能 ``dry_run=True`` 只看会改哪儿。
detour 只处理 x86/x64 的 ``E9 rel32`` 跳板：ARM64 的 B/BL 是 4 字节定长指令，
跳板布局与寻址范围完全不同，不在本模块范围内。

计划 schema（JSON）：:

    {
      "file": "target.exe",                  # 必需；相对路径按计划文件所在目录解析
      "ops": [
        # 二选一：offset（文件偏移）或 va（内存地址）；两个都给时按 offset
        {"kind": "patch", "offset": "0x43f766", "bytes": "ba 6a 57 00 00", "note": "改立即数"},
        {"kind": "patch", "va": "0x14001ebe0", "bytes": "b8 01 00 00 00 c3"},

        # bytes 与 file 二选一；characteristics 省略时用 0x60000020
        {"kind": "add_section", "name": ".zjj", "file": "cave.bin",
         "characteristics": "0x60000020"},

        # section 省略时自动建 .pwre 节；code 省略时只搬运原始指令再跳回
        {"kind": "detour", "at": "0x47986c", "section": ".zjj",
         "code": "53 50 52 51 ... c3", "note": "装 5 字节 E9 跳板"}
      ]
    }
"""

from __future__ import annotations

import json
import os
import re
import struct
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
from capstone.x86 import X86_OP_MEM, X86_REG_RIP

from .errors import ReError

JUMP_SIZE = 5                     # E9 rel32
MAX_RELOC = 16                    # 找指令边界时最多看多少字节
SECTION_HEADER_SIZE = 40
DEFAULT_CHARACTERISTICS = 0x60000020  # CODE | EXECUTE | READ
DEFAULT_CAVE = ".pwre"
MEM_EXECUTE = 0x20000000

# 节表项（40 字节定长）里几个要用到的字段偏移
SEC_VIRTUAL_SIZE = 8
SEC_RAW_SIZE = 16

_HEX_SEP = re.compile(r"[\s,_:;\-]")
_HEX_PREFIX = re.compile(r"(?:0[xX]|\\(?:x|X))")


# --------------------------------------------------------------------------
# 小工具
# --------------------------------------------------------------------------

def _align(value: int, alignment: int) -> int:
    if alignment <= 0:
        return value
    return (value + alignment - 1) // alignment * alignment


def _int(value, what: str) -> int:
    """接受 JSON 里的数字，也接受 "0x43f766" 这种字符串。"""
    if isinstance(value, bool):
        raise ReError(
            f"{what} 要整数，收到布尔值",
            hint="地址/偏移写成十进制或 0x 十六进制，例如 \"0x14001ebe0\"",
        )
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip(), 0)
        except ValueError:
            raise ReError(
                f"{what} 不是整数：{value!r}",
                hint="地址/偏移写成十进制或 0x 十六进制，例如 \"0x14001ebe0\"",
            ) from None
    raise ReError(
        f"{what} 要整数，收到 {type(value).__name__}",
        hint="地址/偏移写成十进制或 0x 十六进制，例如 \"0x14001ebe0\"",
    )


def _hex_bytes(value, what: str) -> bytes:
    """解析十六进制串：允许空格/逗号/冒号分隔，也允许 0x / \\x 前缀。"""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if value is None:
        return b""
    if not isinstance(value, str):
        raise ReError(
            f"{what} 要十六进制字符串，收到 {type(value).__name__}",
            hint="写成 \"ba 6a 57 00 00\" 或 \"b801000000c3\"",
        )
    text = _HEX_PREFIX.sub("", _HEX_SEP.sub("", value))
    if not text:
        return b""
    if len(text) % 2:
        raise ReError(
            f"{what} 的十六进制长度不符：{len(text)} 个字符（奇数）",
            hint="每个字节两位十六进制，例如 \"ba 6a 57 00 00\"",
        )
    try:
        return bytes.fromhex(text)
    except ValueError:
        raise ReError(
            f"{what} 里有非十六进制字符：{value.strip()[:60]!r}",
            hint="只接受 0-9 a-f；分隔符只能用空格/逗号；别把注释写进 bytes",
        ) from None


def _section_name(value, where: str) -> bytes:
    if not isinstance(value, str) or not value.strip():
        raise ReError(
            f"{where}.name 要一个非空节名",
            hint="节名最长 8 字节，例如 .zjj",
        )
    raw = value.encode("utf-8")
    if len(raw) > 8:
        raise ReError(
            f"{where}.name 太长：{len(raw)} 字节，PE 节名最多 8 字节",
            hint="换成短名字，例如 .zjj / .pwre",
        )
    return raw.ljust(8, b"\0")


def _change(kind, label, offset, before, after, note="", **extra) -> dict:
    row = {
        "kind": kind,
        "label": label,
        "offset": int(offset),
        "length": len(after),
        "before": bytes(before).hex(),
        "after": bytes(after).hex(),
        "note": note or "",
    }
    row.update(extra)
    return row


# --------------------------------------------------------------------------
# PE 视图：所有写入都落在一块 bytearray 上，结构性改动后重新解析
# --------------------------------------------------------------------------

def _parse_pe(data: bytes) -> pefile.PE:
    try:
        return pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        raise ReError(
            f"不是可解析的 PE：{exc}",
            hint="先用 re id 确认格式；ELF/固件/脚本没有 PE 节表，改不了",
        ) from exc
    except (ValueError, IndexError, KeyError, struct.error) as exc:
        raise ReError(
            f"PE 头解析失败（{type(exc).__name__}: {exc}）",
            hint="文件可能被截断或花过了头；换一份干净的原始文件再试",
        ) from exc


class _Image:
    """正在被改写的 PE：一张字节镜像 + 从镜像重新解析出来的 pefile 视图。"""

    def __init__(self, data: bytes):
        self.data = bytearray(data)
        self.pe = _parse_pe(bytes(self.data))

    # ---- 基本信息 ------------------------------------------------------
    def refresh(self) -> None:
        self.pe = _parse_pe(bytes(self.data))

    @property
    def bits(self) -> int:
        return 64 if self.pe.OPTIONAL_HEADER.Magic == 0x20B else 32

    @property
    def image_base(self) -> int:
        return self.pe.OPTIONAL_HEADER.ImageBase

    @property
    def section_alignment(self) -> int:
        return self.pe.OPTIONAL_HEADER.SectionAlignment

    @property
    def file_alignment(self) -> int:
        return self.pe.OPTIONAL_HEADER.FileAlignment

    @property
    def size_of_headers(self) -> int:
        return self.pe.OPTIONAL_HEADER.SizeOfHeaders

    @property
    def size_of_image(self) -> int:
        return self.pe.OPTIONAL_HEADER.SizeOfImage

    @property
    def size_of_image_offset(self) -> int:
        return self.pe.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfImage")

    @property
    def number_of_sections_offset(self) -> int:
        return self.pe.FILE_HEADER.get_field_absolute_offset("NumberOfSections")

    @property
    def section_table_offset(self) -> int:
        return self.pe.OPTIONAL_HEADER.get_file_offset() + self.pe.FILE_HEADER.SizeOfOptionalHeader

    def sections(self) -> list[dict]:
        rows = []
        for index, section in enumerate(self.pe.sections):
            rows.append({
                "index": index,
                "name": section.Name.rstrip(b"\0").decode("utf-8", "replace"),
                "va": self.image_base + section.VirtualAddress,
                "rva": section.VirtualAddress,
                "vsize": section.Misc_VirtualSize,
                "raw_offset": section.PointerToRawData,
                "raw_size": section.SizeOfRawData,
                "characteristics": section.Characteristics,
                "header_offset": section.get_file_offset(),
            })
        return rows

    def section(self, name: str) -> dict | None:
        for row in self.sections():
            if row["name"] == name:
                return row
        return None

    def section_by_va(self, va: int) -> dict | None:
        for row in self.sections():
            span = max(row["vsize"], row["raw_size"])
            if row["va"] <= va < row["va"] + span:
                return row
        return None

    # ---- VA -> 文件偏移 ------------------------------------------------
    def va_to_offset(self, va: int, length: int = 1) -> int:
        """VA 换算成文件偏移。换算本身交给 pefile，边界由节表把关。"""
        base = self.image_base
        if va < base:
            raise ReError(
                f"VA {va:#x} 比映像基址 {base:#x} 还小",
                hint="VA 是内存地址（ImageBase + RVA）；想按文件偏移改请用 offset",
            )
        rva = va - base
        section = self.pe.get_section_by_rva(rva)
        if section is None:
            raise ReError(
                f"VA {va:#x}（RVA {rva:#x}）不在任何节内",
                hint="用 re id 看节表；检查 --plan 里的 VA 是否落在 .text 内",
            )
        row = self.section(section.Name.rstrip(b"\0").decode("utf-8", "replace"))
        delta = rva - section.VirtualAddress
        # 节的末尾可能只有虚拟空间（VirtualSize > SizeOfRawData），那里没有字节可改
        limit = max(0, min(row["vsize"], row["raw_size"])) if row["vsize"] else row["raw_size"]
        if delta + length > limit:
            raise ReError(
                f"VA {va:#x} 的写入越出 {row['name']} 的已初始化数据："
                f"节内可用 {limit:#x} 字节，请求写到 {delta + length:#x}",
                hint="检查 VA 和字节数；补丁不能跨节，也不能写进只占虚拟空间的尾巴",
            )
        offset = self.pe.get_offset_from_rva(rva)
        if offset is None or offset < 0 or offset + length > len(self.data):
            raise ReError(
                f"VA {va:#x} 换算出的文件偏移 {offset} 落在文件外",
                hint="节表可能被改坏了；用 pefile 单独解析一遍核对 PointerToRawData",
            )
        return offset

    # ---- 写入与记录 ----------------------------------------------------
    def put(self, offset: int, payload: bytes) -> None:
        self.data[offset:offset + len(payload)] = payload

    def set_u16(self, offset: int, value: int, label: str, state: "_State", note: str = "") -> dict:
        before = bytes(self.data[offset:offset + 2])
        after = struct.pack("<H", value)
        self.put(offset, after)
        row = _change("header", label, offset, before, after, note)
        state.changes.append(row)
        return row

    def set_u32(self, offset: int, value: int, label: str, state: "_State", note: str = "") -> dict:
        before = bytes(self.data[offset:offset + 4])
        after = struct.pack("<I", value)
        self.put(offset, after)
        row = _change("header", label, offset, before, after, note)
        state.changes.append(row)
        return row

    # ---- 布局计算 ------------------------------------------------------
    def _next_va(self) -> int:
        end = self.image_base + _align(self.size_of_headers, self.section_alignment)
        for row in self.sections():
            span = max(row["vsize"], row["raw_size"])
            end = max(end, row["va"] + _align(span, self.section_alignment))
        return _align(end, self.section_alignment)

    def plan_section(self, name: bytes, payload: bytes, characteristics: int,
                     vsize: int | None = None, where: str = "add_section") -> dict:
        """算好新节的落点，不动文件。返回一个可以直接交给 commit_section 的布局。"""
        fa = self.file_alignment
        sa = self.section_alignment
        raw_size = _align(len(payload), fa)
        virtual_size = len(payload) if vsize is None else vsize
        raw_offset = _align(len(self.data), fa)
        va = self._next_va()
        entry = self.section_table_offset + len(self.pe.sections) * SECTION_HEADER_SIZE
        if entry + SECTION_HEADER_SIZE > self.size_of_headers:
            raise ReError(
                f"节表放不下第 {len(self.pe.sections) + 1} 个节：表项要写到 {entry + SECTION_HEADER_SIZE:#x}，"
                f"但 SizeOfHeaders 只有 {self.size_of_headers:#x}",
                hint="这个 PE 的头部空间不够；先减小 SizeOfHeaders 之前的对齐，或者用 patch 改现有节而不是加节",
            )
        if entry + SECTION_HEADER_SIZE > raw_offset:
            raise ReError(
                f"节表要写到 {entry + SECTION_HEADER_SIZE:#x}，会和第一个节的原始数据（{raw_offset:#x}）重叠",
                hint="文件头太挤；改用 patch，或先把 SizeOfHeaders 调大再重排节",
            )
        header = struct.pack(
            "<8sIIIIIIHHI",
            name, virtual_size, va - self.image_base, raw_size, raw_offset,
            0, 0, 0, 0, characteristics,
        )
        # SizeOfImage 是 RVA 口径，不能拿绝对 VA 去算
        size_of_image = max(self.size_of_image,
                            _align(va - self.image_base + virtual_size, sa))
        return {
            "name": name.rstrip(b"\0").decode("utf-8", "replace"),
            "va": va,
            "rva": va - self.image_base,
            "vsize": virtual_size,
            "raw_offset": raw_offset,
            "raw_size": raw_size,
            "characteristics": characteristics,
            "payload": payload,
            "header": header,
            "entry_offset": entry,
            "size_of_image": size_of_image,
            "where": where,
        }

    def commit_section(self, layout: dict, state: "_State", status: str = "added") -> dict:
        """把 plan_section 的布局真正写进镜像，并同步头部计数。"""
        need = layout["raw_offset"] + layout["raw_size"]
        if len(self.data) < need:
            self.data.extend(b"\0" * (need - len(self.data)))
        self.put(layout["raw_offset"], layout["payload"])
        before = bytes(self.data[layout["entry_offset"]:layout["entry_offset"] + SECTION_HEADER_SIZE])
        self.put(layout["entry_offset"], layout["header"])
        state.changes.append(_change(
            "add_section", f"section[{layout['name']}]", layout["entry_offset"],
            before, layout["header"],
            f"VA {layout['va']:#x} / raw {layout['raw_offset']:#x} / vsize {layout['vsize']:#x}",
            va=layout["va"],
        ))
        count = len(self.pe.sections) + 1
        self.set_u16(self.number_of_sections_offset, count, "NumberOfSections", state,
                     f"{count - 1} -> {count}")
        if layout["size_of_image"] != self.size_of_image:
            self.set_u32(self.size_of_image_offset, layout["size_of_image"], "SizeOfImage", state,
                         f"{self.size_of_image:#x} -> {layout['size_of_image']:#x}")
        self.refresh()
        row = {
            "name": layout["name"],
            "index": count - 1,
            "va": layout["va"],
            "vsize": layout["vsize"],
            "raw_offset": layout["raw_offset"],
            "raw_size": layout["raw_size"],
            "characteristics": layout["characteristics"],
            "status": status,
            "grew": False,
        }
        state.sections.append(row)
        return row

    # ---- 代码洞 --------------------------------------------------------
    def _extend_section(self, row: dict, end_needed: int, state: "_State") -> None:
        """把节在文件尾部的原始数据往后长（只允许长在文件末尾的那一节）。"""
        others = [r for r in self.sections()
                  if r["index"] != row["index"] and r["raw_offset"] > row["raw_offset"]]
        if others:
            raise ReError(
                f"节 {row['name']} 后面还有 {others[0]['name']} 的原始数据，没法就地加长",
                hint="把补丁节放到文件最后（先 add_section 建一个足够大的节），再让 detour 指过去",
            )
        tail = row["raw_offset"] + row["raw_size"]
        if tail < len(self.data):
            raise ReError(
                f"节 {row['name']} 之后还有 {len(self.data) - tail:#x} 字节附加数据（overlay），"
                "直接加长会把那段盖掉",
                hint="先把 overlay 挪到别处，或者用 add_section 在文件末尾新建一个节当代码洞",
            )
        if row["raw_size"] and end_needed <= row["raw_size"]:
            return
        new_raw = _align(end_needed, self.file_alignment)
        if new_raw < row["raw_size"]:
            new_raw = row["raw_size"]
        need = row["raw_offset"] + new_raw
        if len(self.data) < need:
            self.data.extend(b"\0" * (need - len(self.data)))
        self.set_u32(row["header_offset"] + SEC_RAW_SIZE, new_raw,
                     f"{row['name']}.SizeOfRawData", state,
                     f"{row['raw_size']:#x} -> {new_raw:#x}")

    def reserve_cave(self, name: str, need: int, state: "_State", where: str) -> dict:
        """在指定节里预留 need 字节的代码洞，返回 {va, offset, section, status}。"""
        row = self.section(name)
        if row is None:
            layout = self.plan_section(
                _section_name(name, where),
                b"\0" * _align(need, self.file_alignment),
                DEFAULT_CHARACTERISTICS,
                vsize=need,
                where=where,
            )
            self.commit_section(layout, state, status="added")
            return {"va": layout["va"], "offset": layout["raw_offset"],
                    "section": name, "status": "created"}

        if row["raw_size"] == 0 or row["raw_offset"] == 0:
            raise ReError(
                f"节 {name} 没有原始数据（PointerToRawData/SizeOfRawData 为 0），当不了代码洞",
                hint="用 add_section 新建一个带数据的节来放跳板",
            )
        if row["vsize"] > row["raw_size"]:
            raise ReError(
                f"节 {name} 的 VirtualSize（{row['vsize']:#x}）比 SizeOfRawData（{row['raw_size']:#x}）大，"
                "末尾没有落盘字节可以当代码洞",
                hint="换一个节名，或者用 add_section 新建一个节来放跳板",
            )
        used = row["vsize"] if 0 < row["vsize"] <= row["raw_size"] else row["raw_size"]
        if row["raw_size"] and used > row["raw_size"]:
            used = row["raw_size"]
        end_needed = used + need
        if end_needed > row["raw_size"]:
            self._extend_section(row, end_needed, state)
            row = self.section(name) or row
        new_vsize = max(row["vsize"], end_needed)
        if new_vsize != row["vsize"]:
            self.set_u32(row["header_offset"] + SEC_VIRTUAL_SIZE, new_vsize,
                         f"{name}.VirtualSize", state,
                         f"{row['vsize']:#x} -> {new_vsize:#x}")
        size_of_image = max(
            self.size_of_image,
            _align(row["va"] - self.image_base + new_vsize, self.section_alignment),
        )
        if size_of_image != self.size_of_image:
            self.set_u32(self.size_of_image_offset, size_of_image, "SizeOfImage", state,
                         f"{self.size_of_image:#x} -> {size_of_image:#x}")
        self.refresh()
        row = self.section(name) or row
        record = {
            "name": name,
            "index": row["index"],
            "va": row["va"],
            "vsize": new_vsize,
            "raw_offset": row["raw_offset"],
            "raw_size": row["raw_size"],
            "characteristics": row["characteristics"],
            "status": "grown",
            "grew": True,
        }
        # 同一份计划里先 add_section 再往里塞跳板：合成一行，别在报告里出现两次
        for existing in state.sections:
            if existing["name"] == name and existing["index"] == row["index"]:
                existing.update({key: value for key, value in record.items() if key != "status"})
                break
        else:
            state.sections.append(record)
        return {"va": row["va"] + used, "offset": row["raw_offset"] + used,
                "section": name, "status": "grown"}


# --------------------------------------------------------------------------
# 单条操作的实现
# --------------------------------------------------------------------------

class _State:
    def __init__(self, image: _Image):
        self.image = image
        self.changes: list[dict] = []
        self.sections: list[dict] = []
        self.warnings: list[str] = []

    def warn(self, text: str) -> None:
        if text not in self.warnings:
            self.warnings.append(text)


def _op_patch(state: _State, op: dict, where: str) -> None:
    image = state.image
    data = _hex_bytes(op.get("bytes"), f"{where}.bytes")
    if not data:
        raise ReError(
            f"{where}.bytes 是空的",
            hint="至少写一个字节，例如 \"90\"；空补丁没有意义",
        )
    note = str(op.get("note") or "")
    va = None
    if op.get("offset") is not None:
        offset = _int(op["offset"], f"{where}.offset")
        if op.get("va") is not None:
            state.warn(f"{where} 同时给了 offset 和 va，按 offset 处理（偏移优先）")
        if offset < 0 or offset + len(data) > len(image.data):
            raise ReError(
                f"{where} 越界：offset {offset:#x} + {len(data)} 字节超出文件大小 {len(image.data):#x}",
                hint="检查 offset 是否落在文件内；要在尾部加代码请用 add_section",
            )
    elif op.get("va") is not None:
        va = _int(op["va"], f"{where}.va")
        offset = image.va_to_offset(va, len(data))
        section = image.section_by_va(va)
        if section and not section["characteristics"] & MEM_EXECUTE:
            state.warn(f"{where} 的 VA {va:#x} 落在不可执行的节 {section['name']} 里")
    else:
        raise ReError(
            f"{where} 需要 offset 或 va 之一",
            hint="按文件偏移改写 \"offset\": \"0x43f766\"；按内存地址改写 \"va\": \"0x14001ebe0\"",
        )
    before = bytes(image.data[offset:offset + len(data)])
    image.put(offset, data)
    state.changes.append(_change("patch", "patch", offset, before, data, note, va=va))


def _section_payload(op: dict, where: str, state: _State) -> bytes:
    if op.get("bytes") is not None:
        if op.get("file") is not None:
            state.warn(f"{where} 同时给了 bytes 和 file，按 bytes 处理")
        payload = _hex_bytes(op["bytes"], f"{where}.bytes")
    elif op.get("file") is not None:
        source = Path(str(op["file"]))
        try:
            payload = source.read_bytes()
        except FileNotFoundError:
            raise ReError(
                f"{where}.file 不存在：{source}",
                hint="路径写错了；相对路径按计划文件所在目录解析，先确认 cave.bin 在哪",
            ) from None
        except OSError as exc:
            raise ReError(
                f"{where}.file 读不了：{exc}",
                hint="确认文件权限，或者把内容直接写进 bytes",
            ) from None
    else:
        raise ReError(
            f"{where} 需要 bytes 或 file 之一",
            hint="内容短就直接写 \"bytes\": \"...\"；长一点就放文件里用 \"file\": \"cave.bin\"",
        )
    if not payload:
        raise ReError(
            f"{where} 的内容是空的",
            hint="新节至少要有一个字节，否则加载器会当成空节",
        )
    return payload


def _op_add_section(state: _State, op: dict, where: str) -> None:
    image = state.image
    name = op.get("name")
    name_bytes = _section_name(name, where)
    text = name_bytes.rstrip(b"\0").decode("utf-8", "replace")
    if image.section(text):
        raise ReError(
            f"{where} 要加的节 {text} 已经存在",
            hint="节名重复会让加载器行为不确定；换一个名字，或者用 detour 往现有节里塞",
        )
    payload = _section_payload(op, where, state)
    characteristics = DEFAULT_CHARACTERISTICS
    raw_flags = op.get("characteristics")
    if raw_flags is None:
        raw_flags = op.get("section_characteristics")
    if raw_flags is not None:
        characteristics = _int(raw_flags, f"{where}.characteristics")
        if not 0 <= characteristics <= 0xFFFFFFFF:
            raise ReError(
                f"{where}.characteristics 超出 32 位：{characteristics}",
                hint="照规范写 0x60000020（代码可执行可读）之类的 32 位值",
            )
    if not characteristics & MEM_EXECUTE:
        state.warn(f"{where} 新建的节 {text} 没有执行权限（0x{characteristics:08x}），放代码不会被执行")
    layout = image.plan_section(name_bytes, payload, characteristics, where=where)
    image.commit_section(layout, state)


def _is_instruction_boundary(image: _Image, at_offset: int, at_va: int) -> bool:
    """at 是不是真实指令边界。

    做法：从 at-1..at-4 各解一条指令，只要有一条指令跨过 at（起点 < at < 起点+长度），
    就判"不是边界"——宁可让用户显式加 allow_unaligned，也不要静默产出会崩的二进制。
    """
    md = Cs(CS_ARCH_X86, CS_MODE_64 if image.bits == 64 else CS_MODE_32)
    for back in (1, 2, 3, 4):
        start = at_offset - back
        if start < 0:
            continue
        chunk = bytes(image.data[start:start + 16])
        if not chunk:
            continue
        for insn in md.disasm(chunk, at_va - back):
            if insn.address + insn.size > at_va:
                return False
            break
    return True


def _reloc_len(image: _Image, at_offset: int, at_va: int) -> tuple[int, list]:
    """从 at 开始找第一条使覆盖长度 ≥5 的指令边界，返回 (N, 指令列表)。"""
    chunk = bytes(image.data[at_offset:at_offset + MAX_RELOC])
    md = Cs(CS_ARCH_X86, CS_MODE_64 if image.bits == 64 else CS_MODE_32)
    md.detail = True
    total = 0
    insns = []
    for insn in md.disasm(chunk, at_va):
        insns.append(insn)
        total += insn.size
        if total >= JUMP_SIZE:
            break
    if total < JUMP_SIZE:
        raise ReError(
            f"{at_va:#x} 起 {MAX_RELOC} 字节内凑不出 {JUMP_SIZE} 字节的完整指令边界"
            f"（capstone 只认出 {total} 字节完整指令）",
            hint="换一个函数入口/指令边界当 detour 点；或者确认 at 是代码而不是数据",
        )
    return total, insns


def _rel32(instr_va: int, target_va: int, what: str) -> bytes:
    delta = target_va - (instr_va + JUMP_SIZE)
    if not -(1 << 31) <= delta < (1 << 31):
        raise ReError(
            f"{what} 的距离 {delta} 超出 rel32 范围",
            hint="跳板离得太远；把补丁节放在代码节附近，或改成两跳（先跳到中间洞再绝对跳）",
        )
    return struct.pack("<i", delta)


def _rel_branch(raw: bytearray) -> tuple[int, int] | None:
    """识别 x86 相对分支指令，返回 (位移字段宽度, 字段偏移)。"""
    if not raw:
        return None
    op = raw[0]
    if op in (0xE8, 0xE9):
        return (4, 1)
    if op == 0xEB or 0x70 <= op <= 0x7F or 0xE0 <= op <= 0xE3:
        return (1, 1)
    if op == 0x0F and len(raw) >= 2 and 0x80 <= raw[1] <= 0x8F:
        return (4, 2)
    return None


def _relocate(insns, dest_va: int, where: str, allow_unaligned: bool) -> bytes:
    """按新地址重写要搬运的指令：相对分支重算位移，RIP 相对寻址直接拒绝。

    今晚踩过的坑：把 `call rel32` 原样搬进洞，目标会指向洞里的错误位置，
    而 `自检 通过` 只证明磁盘字节和内存镜像一致，证不了语义没变。
    """
    out = bytearray()
    for insn in insns:
        raw = bytearray(insn.bytes)
        new_va = dest_va + len(out)
        if any(operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP
               for operand in insn.operands):
            if not allow_unaligned:
                raise ReError(
                    f"{where} 要搬的 {insn.address:#x}（{insn.mnemonic}）用了 RIP 相对寻址，"
                    "搬到代码洞后语义会变",
                    hint="换一个 detour 点，避开这种指令；"
                         "或者手工重写这条指令、把整段写成 op 的 code",
                )
            out += raw
            continue
        spec = _rel_branch(raw)
        if spec is None:
            out += raw
            continue
        width, field_off = spec
        old_rel = int.from_bytes(raw[field_off:field_off + width], "little", signed=True)
        target = insn.address + insn.size + old_rel
        new_rel = target - (new_va + insn.size)
        low, high = (-(1 << 7), 1 << 7) if width == 1 else (-(1 << 31), 1 << 31)
        if not low <= new_rel < high:
            raise ReError(
                f"{where} 要搬的 {insn.address:#x}（{insn.mnemonic}）是相对跳转，"
                f"搬到代码洞后位移 {new_rel} 超出 {width * 8} 位",
                hint="把补丁节放得离代码更近，或换一个不含 call/jmp/jcc 的 detour 点",
            )
        raw[field_off:field_off + width] = new_rel.to_bytes(width, "little", signed=True)
        out += raw
    return bytes(out)


def _op_detour(state: _State, op: dict, where: str) -> None:
    image = state.image
    at = _int(op.get("at"), f"{where}.at")
    raw_code = op.get("code")
    if raw_code is None:
        raw_code = op.get("bytes")       # 允许把补丁代码写成 bytes
    code = _hex_bytes(raw_code, f"{where}.code")
    note = str(op.get("note") or "")
    allow_unaligned = bool(op.get("allow_unaligned"))
    at_offset = image.va_to_offset(at, JUMP_SIZE)
    section = image.section_by_va(at)
    if section and not section["characteristics"] & MEM_EXECUTE:
        state.warn(f"{where} 的 at {at:#x} 落在不可执行的节 {section['name']} 里，跳板写进去也不会被执行")
    if not allow_unaligned and not _is_instruction_boundary(image, at_offset, at):
        raise ReError(
            f"{where} 的 at {at:#x} 不像指令边界（从 at-1..at-4 解码时有指令跨过它）",
            hint="换个落点：函数入口或 re dis 里看到的指令起始地址；"
                 "确实要从指令中间打，在 op 里加 \"allow_unaligned\": true",
        )
    n, insns = _reloc_len(image, at_offset, at)
    original = bytes(image.data[at_offset:at_offset + n])

    cave_name = op.get("section") or DEFAULT_CAVE
    cave_name = str(cave_name)
    stub_size = len(code) + n + JUMP_SIZE
    slot = image.reserve_cave(cave_name, stub_size, state, where)
    cave_va = slot["va"]
    back_va = at + n
    back_instr = cave_va + len(code) + n
    moved = _relocate(insns, cave_va + len(code), where, allow_unaligned)
    stub = code + moved + b"\xe9" + _rel32(back_instr, back_va, f"{where} 的回跳")

    if slot["offset"] < at_offset + n and at_offset < slot["offset"] + len(stub):
        raise ReError(
            f"{where} 的代码洞（{cave_va:#x}）和 detour 点（{at:#x}）重叠",
            hint="换一个补丁节，或者把 at 放到代码洞之前的别处",
        )

    before_stub = bytes(image.data[slot["offset"]:slot["offset"] + len(stub)])
    image.put(slot["offset"], stub)
    state.changes.append(_change(
        "detour", "detour.cave", slot["offset"], before_stub, stub,
        f"跳板：{len(code)} 字节补丁代码 + {n} 字节原始指令 + E9 回跳 {back_va:#x}",
        va=cave_va, cave_va=cave_va, n=n,
    ))

    if allow_unaligned:
        for insn in insns:
            if any(operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP
                   for operand in insn.operands):
                state.warn(
                    f"{where}：{insn.address:#x} 的 {insn.mnemonic} 用了 RIP 相对寻址，"
                    f"搬到 {cave_va:#x} 后语义会变；建议换 detour 点或手动修正这条指令"
                )

    before_at = bytes(image.data[at_offset:at_offset + n])
    jump = b"\xe9" + _rel32(at, cave_va, f"{where} 的前跳") + b"\x90" * (n - JUMP_SIZE)
    image.put(at_offset, jump)
    state.changes.append(_change(
        "detour", "detour.site", at_offset, before_at, jump,
        f"E9 跳到 {cave_va:#x}，at+5..at+{n} 填 NOP（N={n}）",
        va=at, cave_va=cave_va, n=n, target=back_va,
    ))


# --------------------------------------------------------------------------
# 计划与落盘
# --------------------------------------------------------------------------

def _plan_parts(plan) -> tuple[Path, list]:
    if not isinstance(plan, dict):
        raise ReError(
            "补丁计划要是一个 JSON 对象",
            hint='形如 {"file": "target.exe", "ops": [...]}',
        )
    target = plan.get("file")
    if not target:
        raise ReError(
            "计划里缺 file",
            hint='加一行 "file": "target.exe"；相对路径按计划文件所在目录解析',
        )
    ops = plan.get("ops")
    if ops is None:
        raise ReError(
            "计划里缺 ops",
            hint='加一行 "ops": [...]；空数组表示什么都不做',
        )
    if not isinstance(ops, list):
        raise ReError(
            f"ops 要数组，收到 {type(ops).__name__}",
            hint='写成 "ops": [{"kind": "patch", ...}]',
        )
    return Path(str(target)), ops


def _read_target(target: Path) -> bytes:
    if not target.exists():
        raise ReError(
            f"目标文件不存在：{target}",
            hint="检查 --plan 里的 file 路径；相对路径按计划文件所在目录解析",
        )
    if target.is_dir():
        raise ReError(
            f"目标是目录，不是文件：{target}",
            hint="指向具体的 exe/dll，不要指目录",
        )
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise ReError(
            f"读不了目标文件：{exc}",
            hint="确认权限；被调试器/杀软占用时先关掉",
        ) from exc
    if len(raw) < 0x40:
        raise ReError(
            f"{target.name} 只有 {len(raw)} 字节，连 DOS 头都不够",
            hint="先用 re id 认格式；这不是 PE",
        )
    return raw


def _write_atomic(target: Path, payload: bytes) -> None:
    tmp = target.with_name(target.name + ".pwre-tmp")
    try:
        tmp.write_bytes(payload)
        os.replace(tmp, target)
    except OSError as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise ReError(
            f"写回失败：{exc}",
            hint="确认文件没被调试器/杀软占用；改一份副本更稳妥",
        ) from exc


def _verify(target: Path, expected: bytes, changes: list[dict]) -> tuple[bool, list[str]]:
    """重新读回文件，逐条断言写入的字节确实落地。"""
    try:
        actual = target.read_bytes()
    except OSError as exc:
        return False, [f"自检读不回 {target}：{exc}"]
    problems: list[str] = []
    if actual != expected:
        problems.append(
            f"回读的文件与内存镜像不一致（磁盘 {len(actual)} 字节 / 预期 {len(expected)} 字节）"
        )
    for row in changes:
        offset = row["offset"]
        after = bytes.fromhex(row["after"])
        if expected[offset:offset + len(after)] != after:
            # 被后面的操作覆盖了：按最终镜像算，不拿它当失败
            row["superseded"] = True
            continue
        if actual[offset:offset + len(after)] != after:
            problems.append(f"{row['label']} @ {offset:#x} 写进去的字节和预期不符")
    return not problems, problems


def load_plan(path: Path) -> dict:
    """读一份补丁计划；相对路径按计划文件所在目录解析成绝对路径。"""
    source = Path(path)
    try:
        text = source.read_text(encoding="utf-8-sig")
    except FileNotFoundError:
        raise ReError(
            f"计划文件不存在：{source}",
            hint="先写一个 plan.json；内容形如 {\"file\": \"target.exe\", \"ops\": [...]}",
        ) from None
    except OSError as exc:
        raise ReError(
            f"读不了计划文件：{exc}",
            hint="确认路径和读权限",
        ) from None
    try:
        plan = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ReError(
            f"计划不是合法 JSON：第 {exc.lineno} 行 {exc.msg}",
            hint="JSON 不允许注释和尾逗号；用 python -m json.tool 验一遍",
        ) from None
    if not isinstance(plan, dict):
        raise ReError(
            "计划要是一个 JSON 对象",
            hint='形如 {"file": "target.exe", "ops": [...]}',
        )
    base = source.parent
    plan = dict(plan)
    if plan.get("file"):
        plan["file"] = str(_resolve(base, plan["file"]))
    ops = plan.get("ops")
    if isinstance(ops, list):
        plan["ops"] = [
            _resolve_op(base, op) if isinstance(op, dict) else op
            for op in ops
        ]
    return plan


def _resolve(base: Path, value) -> Path:
    candidate = Path(str(value))
    if candidate.is_absolute():
        return candidate
    return base / candidate


def _resolve_op(base: Path, op: dict) -> dict:
    if op.get("file"):
        row = dict(op)
        row["file"] = str(_resolve(base, row["file"]))
        return row
    return op


def _elf_va_to_offset(raw: bytes, va: int, size: int) -> int:
    """ELF 的 VA → 文件偏移（按 PT_LOAD 的 p_vaddr/p_filesz/p_offset 映射）。"""
    import io

    from elftools.elf.elffile import ELFFile

    with ELFFile(io.BytesIO(raw)) as elf:
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            start = int(segment["p_vaddr"])
            if start <= va and va + size <= start + int(segment["p_filesz"]):
                return int(segment["p_offset"]) + (va - start)
    raise ReError(
        f"VA {va:#x}（{size} 字节）不在任何 PT_LOAD 段里",
        hint="ELF 的地址要落在有文件内容的段内；先 re elf 看段的 vaddr/file size，"
             "或者干脆用 offset（文件偏移）写",
    )


def _apply_elf(target: Path, raw: bytes, ops: list, dry_run: bool) -> dict:
    """ELF（含 Android 的 .so）只支持按 offset/va 改字节。

    APK 里的补丁绝大多数是这种：在 libapp.so / libxxx.so 里把某个函数改成
    mov w0,#1; ret（ARM64 是 `20 00 80 52 c0 03 5f d6`）。PE 那套加节/跳板对
    ELF 不适用——没有节表、也不能随便挪段。
    """
    data = bytearray(raw)
    changes: list[dict] = []
    warnings: list[str] = []
    for index, op in enumerate(ops):
        where = f"ops[{index}]"
        if not isinstance(op, dict):
            raise ReError(
                f"{where} 不是对象",
                hint='每条操作是一个 JSON 对象，形如 {"kind": "patch", "offset": "0x100", "bytes": "90"}',
            )
        kind = op.get("kind")
        if kind != "patch":
            raise ReError(
                f"{where} 的 kind 是 {kind!r}，ELF 只支持 patch",
                hint="ELF 没有 PE 节表；要加节/装跳板请对 PE 用 add_section/detour",
            )
        payload = _hex_bytes(op.get("bytes"), f"{where}.bytes")
        if not payload:
            raise ReError(
                f"{where}.bytes 是空的",
                hint="至少写一个字节，例如 \"c0035fd6\"（ret）",
            )
        va = None
        if op.get("offset") is not None:
            offset = _int(op["offset"], f"{where}.offset")
            if op.get("va") is not None:
                warnings.append(f"{where} 同时给了 offset 和 va，按 offset 处理（偏移优先）")
        elif op.get("va") is not None:
            va = _int(op["va"], f"{where}.va")
            offset = _elf_va_to_offset(raw, va, len(payload))
        else:
            raise ReError(
                f"{where} 需要 offset 或 va 之一",
                hint="写文件偏移用 \"offset\"；写虚拟地址用 \"va\"（先 re elf 看段表）",
            )
        if offset < 0 or offset + len(payload) > len(data):
            raise ReError(
                f"{where} 越界：offset {offset:#x} + {len(payload)} 字节超出文件大小 {len(data):#x}",
                hint="检查 offset：ELF 的文件偏移和虚拟地址通常不相等（差一个段偏移）",
            )
        before = bytes(data[offset:offset + len(payload)])
        data[offset:offset + len(payload)] = payload
        changes.append(_change("patch", "patch", offset, before, payload,
                               str(op.get("note") or ""), va=va))

    result = {
        "ok": True,
        "file": str(target),
        "dry_run": bool(dry_run),
        "format": "elf",
        "size_before": len(raw),
        "size_after": len(data),
        "changes": changes,
        "sections": [],
        "warnings": warnings,
        "verify": True,
    }
    if dry_run:
        return result
    _write_atomic(target, bytes(data))
    verify, problems = _verify(target, bytes(data), changes)
    result["verify"] = verify
    result["ok"] = verify
    if not verify:
        result["errors"] = problems
        result["hint"] = "文件已写入但自检不一致：先用备份恢复，再逐条查 plan"
    return result


def apply_plan(plan: dict, dry_run: bool = False) -> dict:
    """执行一份补丁计划。

    ``dry_run=True`` 时只算不写，返回的 changes 就是"将要做什么"。

    返回 ``{"ok", "file", "dry_run", "changes", "sections", "warnings", "verify", ...}``；
    计划本身有问题一律抛 ReError，不会留下改了一半的文件。
    """
    target, ops = _plan_parts(plan)
    raw = _read_target(target)
    if raw[:4] == b"\x7fELF":
        return _apply_elf(target, raw, ops, dry_run)
    image = _Image(raw)
    state = _State(image)
    for index, op in enumerate(ops):
        where = f"ops[{index}]"
        if not isinstance(op, dict):
            raise ReError(
                f"{where} 不是对象",
                hint='每条操作是一个 JSON 对象，形如 {"kind": "patch", "offset": "0x100", "bytes": "90"}',
            )
        kind = op.get("kind")
        if kind == "patch":
            _op_patch(state, op, where)
        elif kind == "add_section":
            _op_add_section(state, op, where)
        elif kind == "detour":
            _op_detour(state, op, where)
        else:
            raise ReError(
                f"{where} 的 kind 不认识：{kind!r}",
                hint="只支持 patch / add_section / detour 三种",
            )

    result = {
        "ok": True,
        "file": str(target),
        "dry_run": bool(dry_run),
        "size_before": len(raw),
        "size_after": len(image.data),
        "changes": state.changes,
        "sections": state.sections,
        "warnings": state.warnings,
        "verify": True,
    }
    if dry_run:
        return result
    _write_atomic(target, bytes(image.data))
    verify, problems = _verify(target, bytes(image.data), state.changes)
    result["verify"] = verify
    result["ok"] = verify
    if not verify:
        result["errors"] = problems
        result["hint"] = "文件已写入但自检不一致：先用备份恢复，再逐条查 plan"
    return result


def patch_file(target: Path, ops: list, dry_run: bool = False) -> dict:
    """便捷入口：直接给目标文件和 ops 列表。"""
    if not isinstance(ops, list):
        raise ReError(
            f"ops 要数组，收到 {type(ops).__name__}",
            hint='写成 [{"kind": "patch", "offset": "0x100", "bytes": "90"}]',
        )
    return apply_plan({"file": str(target), "ops": ops}, dry_run=dry_run)
