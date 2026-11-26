"""固件链路的回归测试：向量表、HEX 记录类型、映像合并。

这些用例都来自实战里真出过的问题（PY32 的 IRQ 保留槽、类型 03 的 CS:IP、
带 BOM 的 HEX、超大空洞），不是为了凑覆盖率。
"""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pwre import armvec, hexfile  # noqa: E402
from pwre.image import Image, Segment  # noqa: E402


def _record(payload: bytes) -> str:
    return ":" + (payload + bytes([(-sum(payload)) & 0xFF])).hex().upper()


def _iwrite(addr: int, data: bytes) -> str:
    lines = []
    if addr > 0xFFFF:
        lines.append(_record(bytes([2, 0, 0, 4]) + ((addr >> 16) & 0xFFFF).to_bytes(2, "big")))
        addr &= 0xFFFF
    lines.append(_record(bytes([len(data), (addr >> 8) & 0xFF, addr & 0xFF, 0]) + data))
    return "\n".join(lines)


def _image(entries: list[int], size: int = 256, base: int = 0x08000000) -> Image:
    raw = bytearray(size)
    for index, value in enumerate(entries):
        struct.pack_into("<I", raw, index * 4, value)
    return Image([Segment(base, bytes(raw))])


class VectorTableTests(unittest.TestCase):
    def test_irq_after_reserved_zero_is_kept(self):
        """PY32 的 IRQ8 是保留槽（0），真处理函数在 IRQ16——不能被第一个 0 截断。"""
        entries = [0x20001000, 0x08000021] + [0] * 14
        entries += [0x08000021] * 8 + [0]        # IRQ0..7 默认处理，IRQ8 保留
        entries += [0] * 7 + [0x08000031]        # IRQ9..15 保留，IRQ16 真处理
        table = armvec.find_table(_image(entries))
        irqs = dict((index - 16, value) for index, value in table.irq_handlers)
        self.assertIn(16, irqs)
        self.assertEqual(irqs[16] & ~1, 0x08000030)

    def test_table_stops_at_code(self):
        """表后面紧跟代码：第一个"非 0 又不像向量"的字就是表尾。"""
        entries = [0x20001000, 0x08000021] + [0x08000021] * 30 + [0x46854803]
        table = armvec.find_table(_image(entries))
        self.assertEqual(max(index for index, _ in table.entries), 31)

    def test_common_handler_counted(self):
        entries = [0x20001000, 0x08000021] + [0x08000021] * 10 + [0] * 6 + [0x08000031]
        table = armvec.find_table(_image(entries))
        self.assertEqual(table.common_handler[0], 0x08000020)
        self.assertGreater(table.common_handler[1], 1)

    def test_reset_must_be_inside_a_segment(self):
        with self.assertRaises(Exception):
            armvec.find_table(_image([0x20001000, 0x08000801]))


class IhexTypeTests(unittest.TestCase):
    def test_type03_is_cs_ip(self):
        text = _record(bytes([4, 0, 0, 3, 0x10, 0x00, 0x01, 0x00])) + "\n:00000001FF"
        image = hexfile.parse_ihex(text)
        self.assertEqual(image.start, 0x00010100)

    def test_type05_is_linear(self):
        text = _record(bytes([4, 0, 0, 5, 0x08, 0x00, 0x00, 0xC1])) + "\n:00000001FF"
        self.assertEqual(hexfile.parse_ihex(text).start, 0x080000C1)

    def test_wrong_length_for_type_is_an_error(self):
        text = _record(bytes([4, 0, 0, 2, 0x08, 0x00, 0x00, 0x00])) + "\n:00000001FF"
        image = hexfile.parse_ihex(text)
        self.assertTrue(any("0x02" in message for message in image.errors))

    def test_extra_bytes_on_a_record_are_rejected(self):
        text = _record(bytes([1, 0, 0, 0, 0x41, 0x42])) + "\n:00000001FF"
        image = hexfile.parse_ihex(text)
        self.assertTrue(image.errors)

    def test_bom_is_tolerated(self):
        text = "\ufeff" + _iwrite(0x08000000, b"\x01\x02") + "\n:00000001FF"
        image = hexfile.parse_ihex(text)
        self.assertEqual(image.errors, [])
        self.assertEqual(image.total, 2)


class ImageMergeTests(unittest.TestCase):
    def test_contiguous_records_merge_into_one_segment(self):
        image = Image([Segment(0x08000000, b"\x01\x02"), Segment(0x08000002, b"\x03\x04")])
        self.assertEqual(len(image.segments), 1)
        self.assertEqual(image.total, 4)

    def test_conflict_keeps_first_and_records_error(self):
        image = Image([Segment(0x1000, b"AAAA"), Segment(0x1002, b"BBBB")])
        self.assertTrue(image.errors)
        # 重叠部分保留先出现的段，后面不重叠的尾巴照收
        self.assertEqual(image.read(0x1000, 4), b"AAAA")
        self.assertTrue(image.to_flat()[1].startswith(b"AAAA"))

    def test_huge_hole_is_refused(self):
        image = Image([Segment(0x08000000, b"\x01"), Segment(0x20000000, b"\x02")])
        with self.assertRaises(Exception):
            image.to_flat()

    def test_gap_small_enough_is_filled(self):
        image = Image([Segment(0x1000, b"\x01"), Segment(0x1002, b"\x02")])
        self.assertEqual(image.to_flat(fill=0xEE)[1], b"\x01\xee\x02")


if __name__ == "__main__":
    unittest.main()
