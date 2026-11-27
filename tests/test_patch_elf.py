"""ELF（Android .so）补丁的单元测试：只支持按 offset/va 改字节。

样本用 struct 现造一个最小 ELF64（一个 PT_LOAD 段），不依赖本机任何文件。
"""

import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pwre import patch  # noqa: E402
from pwre.errors import ReError  # noqa: E402

PAYLOAD_OFFSET = 0x1000
PAYLOAD_VADDR = 0x2000
CODE = bytes.fromhex("ff4303d1fd7b07a9")   # sub sp, sp, #0xd0 ; stp x29, x30, [sp, #0x70]
PATCH = bytes.fromhex("20008052c0035fd6")  # mov w0, #1 ; ret


def build_elf() -> bytes:
    """最小 ELF64：ELF 头 + 一个 PT_LOAD，代码放在 0x1000，映射到 VA 0x2000。"""
    payload = CODE + b"\x00" * 8
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2          # ELFCLASS64
    header[5] = 1          # ELFDATA2LSB
    header[6] = 1          # EV_CURRENT
    struct.pack_into("<HHI", header, 16, 2, 0xB7, 1)      # e_type / e_machine(AArch64) / e_version
    struct.pack_into("<QQQ", header, 24, PAYLOAD_VADDR, 64, 0)  # e_entry / e_phoff / e_shoff
    struct.pack_into("<IHHHHHH", header, 48, 0, 64, 56, 1, 64, 0, 0)
    program = struct.pack(
        "<IIQQQQQQ",
        1,               # PT_LOAD
        5,               # R+X
        PAYLOAD_OFFSET,
        PAYLOAD_VADDR,
        PAYLOAD_VADDR,
        len(payload),
        len(payload),
        0x1000,
    )
    blob = bytearray(header) + program
    blob += b"\x00" * (PAYLOAD_OFFSET - len(blob))
    blob += payload
    return bytes(blob)


class ElfPatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "libtest.so"
        self.path.write_bytes(build_elf())

    def tearDown(self):
        self.tmp.cleanup()

    def test_offset_patch_writes_expected_bytes(self):
        result = patch.patch_file(self.path, [
            {"kind": "patch", "offset": hex(PAYLOAD_OFFSET), "bytes": PATCH.hex()},
        ])
        self.assertTrue(result["ok"])
        self.assertTrue(result["verify"])
        self.assertEqual(result["format"], "elf")
        self.assertEqual(result["changes"][0]["before"], CODE.hex())
        self.assertEqual(self.path.read_bytes()[PAYLOAD_OFFSET:PAYLOAD_OFFSET + len(PATCH)], PATCH)

    def test_va_patch_maps_to_same_offset_as_offset_patch(self):
        by_va = patch.patch_file(self.path, [
            {"kind": "patch", "va": hex(PAYLOAD_VADDR), "bytes": PATCH.hex()},
        ])
        self.assertTrue(by_va["ok"])
        self.assertEqual(by_va["changes"][0]["offset"], PAYLOAD_OFFSET)
        self.assertEqual(self.path.read_bytes()[PAYLOAD_OFFSET:PAYLOAD_OFFSET + len(PATCH)], PATCH)

    def test_va_outside_segments_is_rejected(self):
        with self.assertRaises(ReError) as ctx:
            patch.patch_file(self.path, [
                {"kind": "patch", "va": "0x9000", "bytes": "c0035fd6"},
            ])
        self.assertIn("PT_LOAD", ctx.exception.message)
        self.assertTrue(ctx.exception.hint)
        # 拒绝时一个字节都不写
        self.assertEqual(self.path.read_bytes(), build_elf())

    def test_add_section_on_elf_is_rejected_with_hint(self):
        with self.assertRaises(ReError) as ctx:
            patch.patch_file(self.path, [
                {"kind": "add_section", "name": ".x", "bytes": "90"},
            ])
        self.assertIn("ELF", ctx.exception.message)
        self.assertIn("add_section", ctx.exception.hint)
        self.assertEqual(self.path.read_bytes(), build_elf())

    def test_detour_on_elf_is_rejected(self):
        with self.assertRaises(ReError) as ctx:
            patch.patch_file(self.path, [
                {"kind": "detour", "at": hex(PAYLOAD_VADDR), "code": "c0035fd6"},
            ])
        self.assertIn("ELF", ctx.exception.message)

    def test_out_of_range_offset_is_rejected_without_writing(self):
        with self.assertRaises(ReError) as ctx:
            patch.patch_file(self.path, [
                {"kind": "patch", "offset": hex(PAYLOAD_OFFSET + 4096), "bytes": "90"},
            ])
        self.assertIn("越界", ctx.exception.message)
        self.assertEqual(self.path.read_bytes(), build_elf())

    def test_dry_run_does_not_touch_file(self):
        before = self.path.read_bytes()
        result = patch.patch_file(self.path, [
            {"kind": "patch", "offset": hex(PAYLOAD_OFFSET), "bytes": PATCH.hex()},
        ], dry_run=True)
        self.assertTrue(result["dry_run"])
        self.assertEqual(result["changes"][0]["after"], PATCH.hex())
        self.assertEqual(self.path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
