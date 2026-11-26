"""Android 二进制 XML（AXML）解析：只取逆向需要的东西。

APK 里的 AndroidManifest.xml 是编译过的二进制 XML：字符串池 + 资源映射 + 元素块。
这里不追求完整还原（那是 apktool 的活），只把"包名、版本、权限、组件、属性"
这些每次逆向都要先看的信息读出来。
"""

import struct
from dataclasses import dataclass, field

from .errors import ReError

RES_STRING_POOL = 0x0001
RES_XML_START_ELEMENT = 0x0102
RES_XML_END_ELEMENT = 0x0103
RES_XML_RESOURCE_MAP = 0x0180

TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12


@dataclass
class Element:
    tag: str
    attrs: dict = field(default_factory=dict)
    depth: int = 0


def _string_pool(data: bytes, offset: int) -> list[str]:
    header = struct.unpack_from("<HHI", data, offset)
    size = header[2]
    count, _styles, flags, strings_start = struct.unpack_from("<IIII", data, offset + 8)
    offsets_at = offset + header[1]
    utf8 = bool(flags & 0x100)
    base = offset + strings_start
    out = []
    for index in range(count):
        pos = base + struct.unpack_from("<I", data, offsets_at + index * 4)[0]
        try:
            if utf8:
                # 两段可变长长度（UTF-16 码元数、字节数），首位带 0x80 表示两字节
                length = data[pos]
                pos += 1
                if length & 0x80:
                    pos += 1
                raw_len = data[pos]
                pos += 1
                if raw_len & 0x80:
                    raw_len = ((raw_len & 0x7F) << 8) | data[pos]
                    pos += 1
                out.append(data[pos: pos + raw_len].decode("utf-8", "replace"))
            else:
                length = struct.unpack_from("<H", data, pos)[0]
                pos += 2
                if length & 0x8000:
                    length = ((length & 0x7FFF) << 16) | struct.unpack_from("<H", data, pos)[0]
                    pos += 2
                out.append(data[pos: pos + length * 2].decode("utf-16-le", "replace"))
        except (IndexError, struct.error):
            out.append("")
    end = offset + size
    if end > len(data):
        raise ReError("字符串池越界，文件可能截断")
    return out


def _typed_value(data: bytes, pos: int, strings: list[str]):
    raw = struct.unpack_from("<I", data, pos + 8)[0]
    dtype = data[pos + 15]
    value = struct.unpack_from("<I", data, pos + 16)[0]
    if dtype == TYPE_STRING:
        return strings[value] if value < len(strings) else ""
    if dtype == TYPE_INT_BOOLEAN:
        return bool(value)
    if dtype == TYPE_INT_HEX:
        return f"0x{value:x}"
    if dtype == TYPE_INT_DEC:
        return value
    if raw and raw < len(strings) and strings[raw]:
        return strings[raw]
    return value


def parse(data: bytes) -> list[Element]:
    """返回按出现顺序排列的起始元素（带属性）。"""
    if len(data) < 8:
        raise ReError("二进制 XML 太短")
    kind, header_size, total = struct.unpack_from("<HHI", data, 0)
    if kind != 0x0003:
        raise ReError(f"不是二进制 XML（首块类型 0x{kind:04x}）")
    if total > len(data):
        raise ReError(f"XML 声明长度 {total} 超过实际 {len(data)}，文件可能截断")
    strings: list[str] = []
    elements: list[Element] = []
    offset = header_size
    depth = 0
    while offset + 8 <= total:
        ctype, chsize, csize = struct.unpack_from("<HHI", data, offset)
        if csize < 8 or offset + csize > total:
            break
        if ctype == RES_STRING_POOL:
            strings = _string_pool(data, offset)
        elif ctype == RES_XML_START_ELEMENT:
            ns, name = struct.unpack_from("<II", data, offset + 16)
            attr_start, attr_size, attr_count = struct.unpack_from("<HHH", data, offset + 24)
            attrs = {}
            for index in range(attr_count):
                at = offset + 16 + attr_start + index * attr_size
                _, aname, araw = struct.unpack_from("<III", data, at)
                key = strings[aname] if aname < len(strings) else f"attr{aname}"
                attrs[key] = _typed_value(data, at, strings)
            tag = strings[name] if name < len(strings) else f"tag{name}"
            elements.append(Element(tag, attrs, depth))
            depth += 1
        elif ctype == RES_XML_END_ELEMENT:
            depth = max(0, depth - 1)
        offset += csize
    if not elements:
        raise ReError("二进制 XML 里没有元素，文件可能已加密/损坏")
    return elements


def manifest_summary(elements: list[Element]) -> dict:
    """把 AndroidManifest 的元素序列压成逆向第一眼要看的东西。"""
    root = next((item for item in elements if item.tag == "manifest"), None)
    if root is None:
        raise ReError("找不到 <manifest>，这不是 AndroidManifest.xml")
    app = next((item for item in elements if item.tag == "application"), None)
    permissions = [
        str(item.attrs.get("name", "")).replace("android.permission.", "")
        for item in elements
        if item.tag == "uses-permission" and item.attrs.get("name")
    ]
    components = {}
    for item in elements:
        if item.tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            components.setdefault(item.tag, []).append(item.attrs)
    uses_sdk = next((item for item in elements if item.tag == "uses-sdk"), None)
    meta = {}
    if app is not None:
        for item in elements:
            if item.tag == "meta-data" and item.attrs.get("name"):
                meta[str(item.attrs["name"])] = item.attrs.get("value", item.attrs.get("resource"))
    return {
        "package": root.attrs.get("package", ""),
        "version_name": root.attrs.get("versionName", ""),
        "version_code": root.attrs.get("versionCode", ""),
        "compile_sdk": root.attrs.get("compileSdkVersion", ""),
        "min_sdk": (uses_sdk.attrs.get("minSdkVersion") if uses_sdk else "") or root.attrs.get("minSdkVersion", ""),
        "target_sdk": (uses_sdk.attrs.get("targetSdkVersion") if uses_sdk else "") or root.attrs.get("targetSdkVersion", ""),
        "app_name": app.attrs.get("name", "") if app else "",
        "app_label": app.attrs.get("label", "") if app else "",
        "app_component_factory": app.attrs.get("appComponentFactory", "") if app else "",
        "debuggable": bool(app.attrs.get("debuggable")) if app else False,
        "allow_backup": app.attrs.get("allowBackup") if app else None,
        "permissions": sorted(set(permissions)),
        "components": {key: len(value) for key, value in components.items()},
        "component_names": {key: [str(a.get("name", "")) for a in value] for key, value in components.items()},
        "meta": meta,
    }
