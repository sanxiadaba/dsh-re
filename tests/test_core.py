"""不依赖硬件的单元测试：解析器、映像模型、向量表、剥包。

跑法：.venv\\Scripts\\python -m unittest discover -s tests -v
"""

import json
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pwre import armvec, diff, hexfile, image as imagelib, scan, unpack  # noqa: E402
from pwre.detect import sniff  # noqa: E402


def _record(payload: bytes) -> str:
    return ":" + (payload + bytes([(-sum(payload)) & 0xFF])).hex().upper()


def ihex_record(addr: int, data: bytes) -> str:
    """按需加一条 04 扩展线性地址记录，再写数据记录。"""
    lines = []
    if addr > 0xFFFF:
        lines.append(_record(bytes([2, 0, 0, 4]) + ((addr >> 16) & 0xFFFF).to_bytes(2, "big")))
        addr &= 0xFFFF
    lines.append(_record(bytes([len(data), (addr >> 8) & 0xFF, addr & 0xFF, 0]) + data))
    return "\n".join(lines)


def srec_record(kind: str, addr: int, data: bytes, width: int) -> str:
    body = bytes([0]) + addr.to_bytes(width, "big") + data
    count = len(body)
    checksum = (~(count + sum(body))) & 0xFF
    return f"S{kind}{count:02X}" + body[1:].hex().upper() + f"{checksum:02X}"


class IhexTests(unittest.TestCase):
    def test_parse_and_merge(self):
        text = "\n".join(
            [
                ihex_record(0x0800_0000, bytes(range(16))),
                ihex_record(0x0800_0010, bytes(range(16, 32))),
                ":00000001FF",
            ]
        )
        parsed = hexfile.parse_ihex(text)
        self.assertEqual(len(parsed.segments), 1)
        self.assertEqual(parsed.segments[0].addr, 0x0800_0000)
        self.assertEqual(parsed.total, 32)
        self.assertEqual(parsed.errors, [])

    def test_bad_checksum_is_reported(self):
        record = ihex_record(0x0800_0000, b"\x01\x02\x03\x04")
        broken = record[:-2] + "00"
        parsed = hexfile.parse_ihex(broken)
        self.assertEqual(parsed.segments, [])
        self.assertTrue(any("校验" in message for message in parsed.errors))

    def test_roundtrip(self):
        parsed = hexfile.parse_ihex(ihex_record(0x0800_0000, b"\xde\xad\xbe\xef") + "\n:00000001FF")
        text = hexfile.write_ihex(parsed)
        again = hexfile.parse_ihex(text)
        self.assertEqual(again.total, 4)
        self.assertEqual(again.segments[0].data, b"\xde\xad\xbe\xef")


class SrecTests(unittest.TestCase):
    def test_parse(self):
        text = "\n".join(
            [
                srec_record("0", 0, b"header", 2),
                srec_record("3", 0x0800_0000, bytes(range(8)), 4),
                srec_record("7", 0x0800_0001, b"", 4),
            ]
        )
        parsed = hexfile.parse_srec(text)
        self.assertEqual(parsed.total, 8)
        self.assertEqual(parsed.start, 0x0800_0001)
        self.assertEqual(parsed.errors, [])


class ImageTests(unittest.TestCase):
    def test_overlap_conflict_is_an_error(self):
        merged = imagelib.Image(
            [imagelib.Segment(0x1000, b"AAAA"), imagelib.Segment(0x1002, b"BBBB")]
        )
        self.assertTrue(merged.errors)
        self.assertIsNone(merged.read(0x1000, 8))

    def test_overlap_identical_is_merged(self):
        merged = imagelib.Image(
            [imagelib.Segment(0x1000, b"AAAA"), imagelib.Segment(0x1002, b"AA")]
        )
        self.assertEqual(merged.errors, [])
        self.assertEqual(merged.total, 4)

    def test_flat_fills_holes(self):
        img = imagelib.Image([imagelib.Segment(0x1000, b"\x01"), imagelib.Segment(0x1002, b"\x02")])
        base, flat = img.to_flat(fill=0xFF)
        self.assertEqual(base, 0x1000)
        self.assertEqual(flat, b"\x01\xff\x02")


class ArmVecTests(unittest.TestCase):
    def build(self):
        raw = bytearray(64)
        struct.pack_into("<I", raw, 0, 0x2000_1000)   # SP
        struct.pack_into("<I", raw, 4, 0x0800_0021)   # Reset（Thumb，落在映像里）
        struct.pack_into("<I", raw, 8, 0x0800_0025)   # NMI
        struct.pack_into("<I", raw, 12, 0x0800_0029)  # HardFault
        return imagelib.Image([imagelib.Segment(0x0800_0000, bytes(raw))])

    def test_find_table(self):
        table = armvec.find_table(self.build())
        self.assertEqual(table.sp, 0x2000_1000)
        self.assertEqual(table.reset, 0x0800_0021)

    def test_describe_exceptions(self):
        table = armvec.find_table(self.build())
        described = armvec.describe(table, self.build())
        names = {item["name"] for item in described["exceptions"]}
        self.assertIn("HardFault", names)
        self.assertNotIn("MemManage", names)

    def test_missing_table_raises(self):
        from pwre.errors import ReError

        bad = imagelib.Image([imagelib.Segment(0x0800_0000, b"\x00" * 64)])
        with self.assertRaises(ReError):
            armvec.find_table(bad)


class SniffTests(unittest.TestCase):
    def test_ihex_by_content_not_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "weird.dat"
            path.write_text(ihex_record(0x0800_0000, b"\x00\x01") + "\n")
            self.assertEqual(sniff(path).kind, "ihex")

    def test_zip_classified(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.zip"
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("AndroidManifest.xml", b"x")
            self.assertEqual(sniff(path).kind, "apk")

    def test_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "blob.bin"
            path.write_bytes(bytes(range(256)) * 4)
            self.assertEqual(sniff(path).kind, "unknown")


class ScanTests(unittest.TestCase):
    def test_ascii_and_utf16(self):
        data = b"\x00\x00https://example.test/x\x00\x00" + "secret".encode("utf-16-le") + b"\x00"
        rows = scan.scan(data, min_len=4)
        texts = [text for _, _, text in rows]
        self.assertTrue(any(text.startswith("https://") for text in texts))
        self.assertIn("secret", texts)

    def test_min_length_respected(self):
        rows = scan.scan(b"\x00ab\x00abcd\x00", min_len=4)
        self.assertEqual([text for _, _, text in rows], ["abcd"])


class DiffTests(unittest.TestCase):
    def test_block_ranges(self):
        a = b"A" * 4096 * 2
        b = b"A" * 4096 + b"B" * 4096
        ranges = diff._blocks(a, b)
        self.assertEqual(ranges, [(4096, 8192)])

    def test_identical(self):
        self.assertEqual(diff._blocks(b"x" * 100, b"x" * 100), [])


class AsarTests(unittest.TestCase):
    def test_extract_and_verify(self):
        import hashlib

        payload = b"console.log(1)\n"
        header = {
            "files": {
                "main.js": {
                    "size": len(payload),
                    "offset": "0",
                    "integrity": {"algorithm": "sha256", "hash": hashlib.sha256(payload).hexdigest()},
                }
            }
        }
        blob = json.dumps(header).encode()
        blob += b"\x00" * ((4 - len(blob) % 4) % 4)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.asar"
            path.write_bytes(struct.pack("<II", len(blob) + 8, len(blob)) + blob + payload)
            dest = Path(tmp) / "out"
            items, kind = unpack.unpack(path, dest)
            self.assertEqual(kind, "asar")
            self.assertEqual((dest / "main.js").read_bytes(), payload)


if __name__ == "__main__":
    unittest.main()
