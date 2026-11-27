"""patch 模块的回归测试。

样本全部用 struct 现造（最小 PE32+ 与 PE32），不读本机任何真实 PE 文件。
"""

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

from pwre import patch
from pwre.errors import ReError

FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000
IMAGE_BASE_64 = 0x140000000
IMAGE_BASE_32 = 0x400000

# push rbp / mov ebp,esp / sub esp,0x20 / leave / ret —— 前三条正好 6 字节，
# 5 字节跳转要吃掉这三条（N=6），用来验证"完整指令边界"。
DETOUR_BYTES = bytes.fromhex("55 8b ec 83 ec 20 c9 c3")
DETOUR_N = 6
SITE = 0x20
CAVE_CODE = bytes.fromhex("b8 2a 00 00 00 c3")   # mov eax,42; ret


def align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def text_data(size=0x30, site=SITE, code=DETOUR_BYTES):
    data = bytearray(b"\x90" * size)
    data[site:site + len(code)] = code
    return bytes(data)


def build_pe(bits=64, sections=()):
    """拼一个 pefile 认的最小 PE。

    sections: [{"name", "data", 可选 vsize / raw_pad / characteristics}]
    raw_pad 把 SizeOfRawData 撑大，造出"节内还有 raw 空白"的样本。
    """
    base = IMAGE_BASE_64 if bits == 64 else IMAGE_BASE_32
    optional_size = 0xF0 if bits == 64 else 0xE0
    e_lfanew = 0x40
    count = len(sections)
    size_of_headers = align(e_lfanew + 4 + 20 + optional_size + count * 40, FILE_ALIGN)

    placed = []
    cursor = size_of_headers
    for definition in sections:
        raw_size = align(len(definition["data"]), FILE_ALIGN)
        if definition.get("raw_pad"):
            raw_size = max(raw_size, definition["raw_pad"])
        placed.append({
            "raw_offset": cursor,
            "raw_size": raw_size,
            "data": definition["data"],
            "vsize": definition.get("vsize", len(definition["data"])),
            "characteristics": definition.get("characteristics", 0x60000020),
        })
        cursor += raw_size

    va = align(size_of_headers, SECTION_ALIGN)
    for item in placed:
        item["va"] = base + va
        va = align(va + max(item["vsize"], item["raw_size"]), SECTION_ALIGN)

    size_of_image = align(max(item["va"] + item["vsize"] - base for item in placed), SECTION_ALIGN)
    raw = bytearray(cursor)

    raw[0:2] = b"MZ"
    struct.pack_into("<I", raw, 0x3C, e_lfanew)
    raw[e_lfanew:e_lfanew + 4] = b"PE\0\0"

    file_header = e_lfanew + 4
    struct.pack_into("<HHIIIHH", raw, file_header,
                     0x8664 if bits == 64 else 0x14C, count, 0, 0, 0,
                     optional_size, 0x22)

    opt = file_header + 20
    entry = placed[0]["va"] - base if placed else 0
    struct.pack_into("<HBBIII", raw, opt, 0x20B if bits == 64 else 0x10B, 14, 0,
                     placed[0]["raw_size"] if placed else 0, 0, 0)
    if bits == 64:
        struct.pack_into("<IIQ", raw, opt + 16, entry, placed[0]["va"] - base if placed else 0, base)
    else:
        struct.pack_into("<IIII", raw, opt + 16, entry,
                         placed[0]["va"] - base if placed else 0, 0, base)
    struct.pack_into("<II", raw, opt + 32, SECTION_ALIGN, FILE_ALIGN)
    struct.pack_into("<HHHHHH", raw, opt + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<III", raw, opt + 52, 0, size_of_image, size_of_headers)
    struct.pack_into("<IHH", raw, opt + 64, 0, 3, 0x8160)
    if bits == 64:
        struct.pack_into("<QQQQII", raw, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    else:
        struct.pack_into("<IIIIII", raw, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)

    for index, item in enumerate(placed):
        header = opt + optional_size + index * 40
        raw[header:header + 8] = sections[index]["name"].encode().ljust(8, b"\0")
        struct.pack_into("<IIIIIIHHI", raw, header + 8,
                         item["vsize"], item["va"] - base, item["raw_size"],
                         item["raw_offset"], 0, 0, 0, 0, item["characteristics"])
        raw[item["raw_offset"]:item["raw_offset"] + len(item["data"])] = item["data"]

    return bytes(raw)


def plain_pe(bits=64):
    return build_pe(bits, [
        {"name": ".text", "data": text_data()},
        {"name": ".data", "data": b"\x11" * 0x40, "characteristics": 0xC0000040},
    ])


def open_pe(path):
    return pefile.PE(data=Path(path).read_bytes(), fast_load=True)


def section_of(path, name):
    pe = open_pe(path)
    base = pe.OPTIONAL_HEADER.ImageBase
    for sec in pe.sections:
        if sec.Name.rstrip(b"\0") == name.encode():
            return {
                "va": base + sec.VirtualAddress,
                "rva": sec.VirtualAddress,
                "raw": sec.PointerToRawData,
                "raw_size": sec.SizeOfRawData,
                "vsize": sec.Misc_VirtualSize,
                "characteristics": sec.Characteristics,
            }
    raise AssertionError(f"没找到节 {name}")


class PatchTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def make(self, name="target.exe", bits=64, sections=None):
        path = self.root / name
        path.write_bytes(plain_pe(bits) if sections is None else build_pe(bits, sections))
        return path

    def assert_ok(self, result):
        self.assertTrue(result["verify"], result.get("errors"))
        self.assertTrue(result["ok"], result.get("errors"))


class PatchTests(PatchTestCase):
    def test_patch_by_offset_and_va_agree(self):
        one = self.make("by-offset.exe")
        two = self.make("by-va.exe")
        text = section_of(one, ".text")
        offset = text["raw"] + 0x10
        va = text["va"] + 0x10
        payload = "ba 6a 57 00 00"

        first = patch.patch_file(one, [{"kind": "patch", "offset": hex(offset), "bytes": payload}])
        second = patch.patch_file(two, [{"kind": "patch", "va": hex(va), "bytes": payload}])

        self.assert_ok(first)
        self.assert_ok(second)
        self.assertEqual(one.read_bytes(), two.read_bytes())
        self.assertEqual(one.read_bytes()[offset:offset + 5], bytes.fromhex("ba6a570000"))
        self.assertEqual(first["changes"][0]["offset"], second["changes"][0]["offset"])
        self.assertEqual(first["changes"][0]["after"], "ba6a570000")

    def test_patch_change_records_before_and_after(self):
        path = self.make()
        text = section_of(path, ".text")
        offset = text["raw"] + 0x10
        original = path.read_bytes()[offset:offset + 2]

        result = patch.patch_file(
            path, [{"kind": "patch", "offset": offset, "bytes": "90 90", "note": "清零"}])

        self.assert_ok(result)
        row = result["changes"][0]
        self.assertEqual(row["kind"], "patch")
        self.assertEqual(row["offset"], offset)
        self.assertEqual(row["length"], 2)
        self.assertEqual(row["before"], original.hex())
        self.assertEqual(row["after"], "9090")
        self.assertEqual(row["note"], "清零")
        self.assertEqual(path.read_bytes()[offset:offset + 2], b"\x90\x90")

    def test_offset_wins_when_both_given(self):
        path = self.make()
        text = section_of(path, ".text")
        offset = text["raw"] + 0x18
        other_va = text["va"] + 0x28

        result = patch.patch_file(path, [{
            "kind": "patch", "offset": offset, "va": other_va, "bytes": "cc",
        }])

        self.assert_ok(result)
        self.assertEqual(path.read_bytes()[offset], 0xCC)
        self.assertEqual(path.read_bytes()[text["raw"] + 0x28], 0x90)
        self.assertTrue(any("offset" in warning for warning in result["warnings"]))

    def test_add_section_updates_headers_and_content(self):
        path = self.make()
        before = open_pe(path)
        payload = b"\xde\xad\xbe\xef" * 4

        result = patch.patch_file(path, [{
            "kind": "add_section",
            "name": ".zjj",
            "bytes": payload.hex(" "),
            "characteristics": "0x60000020",
        }])

        self.assert_ok(result)
        self.assertEqual(result["sections"][0]["name"], ".zjj")
        self.assertEqual(result["sections"][0]["status"], "added")

        after = open_pe(path)
        self.assertEqual(len(after.sections), len(before.sections) + 1)
        new = after.sections[-1]
        self.assertEqual(new.Name.rstrip(b"\0"), b".zjj")
        self.assertEqual(new.SizeOfRawData % FILE_ALIGN, 0)
        self.assertEqual(new.PointerToRawData % FILE_ALIGN, 0)
        self.assertEqual(new.Characteristics, 0x60000020)
        self.assertEqual(new.Misc_VirtualSize, len(payload))
        data = path.read_bytes()
        self.assertEqual(data[new.PointerToRawData:new.PointerToRawData + len(payload)], payload)

        expect_image = align(new.VirtualAddress + new.Misc_VirtualSize, SECTION_ALIGN)
        self.assertEqual(after.OPTIONAL_HEADER.SizeOfImage, expect_image)
        self.assertEqual(after.OPTIONAL_HEADER.SizeOfImage % SECTION_ALIGN, 0)
        self.assertEqual(after.FILE_HEADER.NumberOfSections, len(after.sections))
        self.assertEqual(result["size_after"], len(data))

    def test_add_section_rejects_bad_names(self):
        path = self.make()
        for name in (".toolongname", ""):
            with self.subTest(name=name):
                with self.assertRaises(ReError) as caught:
                    patch.patch_file(path, [{"kind": "add_section", "name": name, "bytes": "90"}])
                self.assertTrue(caught.exception.hint)

        with self.assertRaises(ReError) as caught:
            patch.patch_file(path, [{"kind": "add_section", "name": ".zjj", "bytes": ""}])
        self.assertTrue(caught.exception.hint)

        patch.patch_file(path, [{"kind": "add_section", "name": ".zjj", "bytes": "90"}])
        with self.assertRaises(ReError) as caught:
            patch.patch_file(path, [{"kind": "add_section", "name": ".zjj", "bytes": "90"}])
        self.assertIn("已经存在", caught.exception.message)

    def test_add_section_from_file_with_relative_plan(self):
        target = self.make("target.exe")
        (self.root / "cave.bin").write_bytes(b"\xc3" * 12)
        plan_path = self.root / "plan.json"
        plan_path.write_text(json.dumps({
            "file": "target.exe",
            "ops": [{"kind": "add_section", "name": ".zjj", "file": "cave.bin"}],
        }), encoding="utf-8")

        plan = patch.load_plan(plan_path)
        self.assertTrue(Path(plan["file"]).is_absolute())
        self.assertTrue(Path(plan["ops"][0]["file"]).is_absolute())
        result = patch.apply_plan(plan)

        self.assert_ok(result)
        new = section_of(target, ".zjj")
        self.assertEqual(new["vsize"], 12)
        self.assertEqual(target.read_bytes()[new["raw"]:new["raw"] + 12], b"\xc3" * 12)

    def test_detour_forward(self):
        path = self.make("forward.exe")
        text = section_of(path, ".text")
        plain = path.read_bytes()
        result = patch.patch_file(path, [
            {"kind": "add_section", "name": ".zjj", "bytes": b"\x90" * 4},
            {"kind": "detour", "at": hex(text["va"] + SITE), "section": ".zjj", "code": CAVE_CODE.hex()},
        ])
        self.assert_ok(result)

        row = next(c for c in result["changes"] if c["label"] == "detour.site")
        n = row["n"]
        cave_va = row["cave_va"]
        self.assertGreaterEqual(n, 5)
        self.assertEqual(n, DETOUR_N)
        # add_section + detour 落在同一个节，报告里只应该出现一行
        self.assertEqual([item["name"] for item in result["sections"]], [".zjj"])
        self.assertTrue(result["sections"][0]["grew"])

        # 被覆盖的原始字节是完整指令：capstone 从头走正好走满 N 字节
        original = DETOUR_BYTES[:n]
        self.assertEqual(row["before"], original.hex())
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        decoded = list(md.disasm(original, text["va"] + SITE))
        self.assertEqual(sum(insn.size for insn in decoded), n)
        self.assertEqual(decoded[-1].address + decoded[-1].size, text["va"] + SITE + n)

        data = path.read_bytes()
        site_offset = text["raw"] + SITE
        self.assertEqual(data[site_offset], 0xE9)
        rel = struct.unpack_from("<i", data, site_offset + 1)[0]
        self.assertEqual(text["va"] + SITE + 5 + rel, cave_va)
        self.assertGreater(rel, 0)
        self.assertEqual(data[site_offset + 5:site_offset + n], b"\x90" * (n - 5))
        self.assertEqual(data[site_offset - 1], plain[site_offset - 1])
        self.assertEqual(data[site_offset + n:site_offset + n + 2], DETOUR_BYTES[n:n + 2])

        # 洞的布局：code → 原始指令 → E9 回跳
        pe = open_pe(path)
        cave_offset = pe.get_offset_from_rva(cave_va - pe.OPTIONAL_HEADER.ImageBase)
        zjj = section_of(path, ".zjj")
        self.assertTrue(zjj["raw"] <= cave_offset < zjj["raw"] + zjj["raw_size"])
        stub = data[cave_offset:cave_offset + len(CAVE_CODE) + n + 5]
        self.assertEqual(stub[:len(CAVE_CODE)], CAVE_CODE)
        self.assertEqual(stub[len(CAVE_CODE):len(CAVE_CODE) + n], original)
        back = stub[len(CAVE_CODE) + n:]
        self.assertEqual(back[0], 0xE9)
        rel_back = struct.unpack_from("<i", back, 1)[0]
        self.assertEqual(cave_va + len(CAVE_CODE) + n + 5 + rel_back, text["va"] + SITE + n)

    def test_detour_backward_rel32(self):
        path = self.make("backward.exe", sections=[
            {"name": ".text", "data": b"\x90" * 0x100, "vsize": 0x100,
             "raw_pad": 0x400, "characteristics": 0x60000020},
            {"name": ".text2", "data": text_data(site=0x10), "characteristics": 0x60000020},
        ])
        text = section_of(path, ".text")
        text2 = section_of(path, ".text2")
        self.assertGreater(text2["va"], text["va"])

        result = patch.patch_file(path, [
            {"kind": "detour", "at": hex(text2["va"] + 0x10), "section": ".text", "code": "31 c0 c3"},
        ])
        self.assert_ok(result)

        row = next(c for c in result["changes"] if c["label"] == "detour.site")
        n, cave_va = row["n"], row["cave_va"]
        self.assertEqual(n, DETOUR_N)
        self.assertLess(cave_va, text2["va"])
        data = path.read_bytes()
        site_offset = text2["raw"] + 0x10
        rel = struct.unpack_from("<i", data, site_offset + 1)[0]
        self.assertLess(rel, 0)     # 反向跳：从高地址跳回低地址的节
        self.assertEqual(text2["va"] + 0x10 + 5 + rel, cave_va)

        # 洞在 .text 的 raw 空白里，节被原地加长（SizeOfRawData 不用变）
        self.assertEqual(cave_va, text["va"] + 0x100)
        grown = section_of(path, ".text")
        self.assertEqual(grown["raw_size"], 0x400)
        self.assertEqual(grown["vsize"], 0x100 + 3 + n + 5)
        cave_offset = grown["raw"] + 0x100
        back = data[cave_offset + 3 + n:cave_offset + 3 + n + 5]
        self.assertEqual(back[0], 0xE9)
        rel_back = struct.unpack_from("<i", back, 1)[0]
        self.assertEqual(cave_va + 3 + n + 5 + rel_back, text2["va"] + 0x10 + n)

    def test_detour_auto_creates_cave_section(self):
        path = self.make("auto.exe")
        text = section_of(path, ".text")
        result = patch.patch_file(path, [
            {"kind": "detour", "at": hex(text["va"] + SITE), "code": "c3"},
        ])
        self.assert_ok(result)
        self.assertEqual(result["sections"][0]["name"], patch.DEFAULT_CAVE)
        self.assertIsNotNone(section_of(path, patch.DEFAULT_CAVE))

    def test_dry_run_changes_nothing(self):
        path = self.make("dry.exe")
        text = section_of(path, ".text")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        ops = [
            {"kind": "patch", "offset": hex(text["raw"] + 0x18), "bytes": "cc cc"},
            {"kind": "add_section", "name": ".zjj", "bytes": "90 90 90 90"},
            {"kind": "detour", "at": hex(text["va"] + SITE), "section": ".zjj", "code": CAVE_CODE.hex()},
        ]

        dry = patch.patch_file(path, ops, dry_run=True)

        self.assertTrue(dry["dry_run"])
        self.assertTrue(dry["verify"])
        labels = {row["label"] for row in dry["changes"]}
        for expected in ("patch", "section[.zjj]", "NumberOfSections",
                         "detour.cave", "detour.site"):
            self.assertIn(expected, labels)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

        real = patch.patch_file(path, ops)
        self.assert_ok(real)
        self.assertNotEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        self.assertEqual([c["after"] for c in dry["changes"]], [c["after"] for c in real["changes"]])
        self.assertEqual([c["offset"] for c in dry["changes"]], [c["offset"] for c in real["changes"]])

    def test_pe32_patch_add_section_and_detour(self):
        path = self.make("tiny32.exe", bits=32)
        text = section_of(path, ".text")
        result = patch.patch_file(path, [
            {"kind": "patch", "va": hex(text["va"] + 0x10), "bytes": "90 90"},
            {"kind": "add_section", "name": ".zjj", "bytes": "c3 c3 c3 c3"},
            {"kind": "detour", "at": hex(text["va"] + SITE), "section": ".zjj", "code": "31 c0 c3"},
        ])
        self.assert_ok(result)
        pe = open_pe(path)
        self.assertEqual(len(pe.sections), 3)
        self.assertEqual(pe.OPTIONAL_HEADER.Magic, 0x10B)
        new = section_of(path, ".zjj")
        self.assertEqual(pe.OPTIONAL_HEADER.SizeOfImage,
                         align(new["va"] - IMAGE_BASE_32 + new["vsize"], SECTION_ALIGN))
        row = next(c for c in result["changes"] if c["label"] == "detour.site")
        data = path.read_bytes()
        site_offset = text["raw"] + SITE
        rel = struct.unpack_from("<i", data, site_offset + 1)[0]
        self.assertEqual(text["va"] + SITE + 5 + rel, row["cave_va"])
        # PE32 下也是完整指令边界
        original = DETOUR_BYTES[:row["n"]]
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        self.assertEqual(sum(i.size for i in md.disasm(original, text["va"] + SITE)), row["n"])

    def test_failed_plan_leaves_file_untouched(self):
        path = self.make()
        text = section_of(path, ".text")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaises(ReError):
            patch.patch_file(path, [
                {"kind": "patch", "offset": hex(text["raw"] + 0x10), "bytes": "cc"},
                {"kind": "patch", "offset": "0x7fffffff", "bytes": "cc"},
            ])
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)


class PlanTests(PatchTestCase):
    def test_load_plan_resolves_relative_paths(self):
        plan_path = self.root / "plan.json"
        plan_path.write_text(json.dumps({
            "file": "sub/target.exe",
            "ops": [{"kind": "patch", "offset": "0x100", "bytes": "90"}],
        }), encoding="utf-8")
        plan = patch.load_plan(plan_path)
        self.assertEqual(Path(plan["file"]), self.root / "sub" / "target.exe")
        self.assertEqual(plan["ops"][0]["offset"], "0x100")

    def test_load_plan_rejects_bad_json(self):
        plan_path = self.root / "bad.json"
        plan_path.write_text("{ops: []}", encoding="utf-8")
        with self.assertRaises(ReError) as caught:
            patch.load_plan(plan_path)
        self.assertTrue(caught.exception.hint)

    def test_load_plan_missing(self):
        with self.assertRaises(ReError) as caught:
            patch.load_plan(self.root / "nope.json")
        self.assertTrue(caught.exception.hint)

    def test_apply_plan_needs_file_and_ops(self):
        for plan in ({}, {"file": "x.exe"}, {"file": "x.exe", "ops": {}}):
            with self.subTest(plan=plan):
                with self.assertRaises(ReError) as caught:
                    patch.apply_plan(plan)
                self.assertTrue(caught.exception.hint)


class ErrorTests(PatchTestCase):
    def test_offset_out_of_range(self):
        path = self.make()
        with self.assertRaises(ReError) as caught:
            patch.patch_file(path, [{"kind": "patch", "offset": "0x7fffffff", "bytes": "90"}])
        self.assertIn("越界", caught.exception.message)
        self.assertTrue(caught.exception.hint)

    def test_length_overruns_end_of_file(self):
        path = self.make()
        size = path.stat().st_size
        with self.assertRaises(ReError) as caught:
            patch.patch_file(path, [{"kind": "patch", "offset": size - 2, "bytes": "90 90 90"}])
        self.assertIn("越界", caught.exception.message)
        self.assertTrue(caught.exception.hint)

    def test_va_not_in_any_section(self):
        path = self.make()
        pe = open_pe(path)
        stray = pe.OPTIONAL_HEADER.ImageBase + 0x5000
        with self.assertRaises(ReError) as caught:
            patch.patch_file(path, [{"kind": "patch", "va": hex(stray), "bytes": "90"}])
        self.assertIn("不在任何节内", caught.exception.message)
        self.assertTrue(caught.exception.hint)

    def test_va_below_image_base(self):
        path = self.make()
        with self.assertRaises(ReError) as caught:
            patch.patch_file(path, [{"kind": "patch", "va": "0x1000", "bytes": "90"}])
        self.assertIn("基址", caught.exception.message)
        self.assertTrue(caught.exception.hint)

    def test_va_write_crosses_section_tail(self):
        path = self.make()
        data_section = section_of(path, ".data")
        va = data_section["va"] + data_section["vsize"] - 2
        with self.assertRaises(ReError) as caught:
            patch.patch_file(path, [{"kind": "patch", "va": hex(va), "bytes": "90 90 90 90"}])
        self.assertIn("已初始化数据", caught.exception.message)
        self.assertTrue(caught.exception.hint)

    def test_bad_hex_and_odd_length(self):
        path = self.make()
        for payload in ("zz", "9", "0x9"):
            with self.subTest(payload=payload):
                with self.assertRaises(ReError) as caught:
                    patch.patch_file(path, [{"kind": "patch", "offset": "0x200", "bytes": payload}])
                self.assertTrue(caught.exception.hint)

    def test_unknown_kind(self):
        path = self.make()
        with self.assertRaises(ReError) as caught:
            patch.patch_file(path, [{"kind": "nop"}])
        self.assertIn("kind", caught.exception.message)
        self.assertTrue(caught.exception.hint)

    def test_missing_target(self):
        with self.assertRaises(ReError) as caught:
            patch.patch_file(self.root / "not-here.exe", [{"kind": "patch", "offset": 0, "bytes": "90"}])
        self.assertIn("不存在", caught.exception.message)
        self.assertTrue(caught.exception.hint)

    def test_detour_without_instruction_boundary(self):
        path = self.make("bad-code.exe", sections=[
            # 0x62 在 64 位下是 EVEX 前缀，单独重复凑不出完整指令
            {"name": ".text", "data": b"\x62" * 0x20, "characteristics": 0x60000020},
        ])
        text = section_of(path, ".text")
        with self.assertRaises(ReError) as caught:
            patch.patch_file(path, [{"kind": "detour", "at": hex(text["va"]), "code": "c3"}])
        self.assertTrue(caught.exception.hint)

    def test_detour_at_section_tail_without_room(self):
        path = self.make("tight.exe", sections=[
            {"name": ".text", "data": b"\x90" * 8, "characteristics": 0x60000020},
        ])
        text = section_of(path, ".text")
        with self.assertRaises(ReError) as caught:
            patch.patch_file(path, [{"kind": "detour", "at": hex(text["va"] + 6), "code": "c3"}])
        self.assertTrue(caught.exception.hint)


if __name__ == "__main__":
    unittest.main()
