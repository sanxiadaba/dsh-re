"""周边能力的回归测试：编码识别、壳名、APK 结构、引擎版本解析、J-Link 输出解析。

都是纯函数，不依赖引擎、网络、硬件。
"""

import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pwre import apk, axml, chip, engines, scan  # noqa: E402
from pwre.detect import FileInfo, packer_name  # noqa: E402


class ScanEncodingTests(unittest.TestCase):
    def test_gbk_chinese_is_found(self):
        data = b"\x00\x00" + "请先切换到串口通信面板".encode("gbk") + b"\x00"
        rows = scan.scan(data, min_len=4)
        self.assertTrue(any(encoding == "gbk" for _, encoding, _ in rows))
        self.assertTrue(any("串口" in text for _, _, text in rows))

    def test_gbk_can_be_turned_off(self):
        data = "串口调试".encode("gbk")
        self.assertEqual(scan.scan(data, min_len=2, encodings=("ascii",)), [])

    def test_utf16be_is_found(self):
        data = "hello".encode("utf-16-be")
        rows = scan.scan(data, min_len=4)
        self.assertTrue(any(encoding == "utf16be" for _, encoding, _ in rows))


class PackerTests(unittest.TestCase):
    def _info(self, names):
        return FileInfo(
            Path("x.exe"), 10, "pe", "PE32",
            extra={"sections": [{"name": name, "raw": 1, "vsize": 1, "entropy": 7.9} for name in names],
                   "entry_section": names[0]},
        )

    def test_upx_from_section_names(self):
        self.assertEqual(packer_name(self._info(["UPX0", "UPX1", ".rsrc"])), "UPX")

    def test_vmprotect(self):
        self.assertEqual(packer_name(self._info([".vmp0", ".vmp1"])), "VMProtect")

    def test_plain_pe_has_no_packer(self):
        self.assertEqual(packer_name(self._info([".text", ".data"])), "")


class AxmlTests(unittest.TestCase):
    def test_text_xml_is_rejected(self):
        with self.assertRaises(Exception):
            axml.parse(b"<?xml version='1.0'?><manifest/>")

    def test_truncated_is_rejected(self):
        with self.assertRaises(Exception):
            axml.parse(b"\x03\x00\x08\x00" + struct.pack("<I", 4096) + b"\x00" * 8)


class ApkFrameworkTests(unittest.TestCase):
    def test_flutter_and_xamarin_detection(self):
        self.assertEqual(apk._framework({"lib/arm64-v8a/libflutter.so"})[0], "Flutter")
        self.assertEqual(apk._framework({"assemblies/Foo.dll"})[0], "Xamarin")
        self.assertEqual(apk._framework({"classes.dex"})[0], "")

    def test_packer_by_known_library(self):
        manifest = {"app_component_factory": ""}
        self.assertIn("360", apk._packer({"lib/armeabi-v7a/libjiagu.so"}, manifest, [1000], 10 << 20))


class EngineVersionTests(unittest.TestCase):
    def _version(self, text):
        done = mock.Mock(returncode=0, stdout="", stderr=text)
        with mock.patch.object(engines.subprocess, "run", return_value=done), \
             mock.patch.object(engines, "java_path", return_value="java"):
            return engines.java_version()

    def test_java8_is_normalised(self):
        self.assertEqual(self._version('java version "1.8.0_411"'), 8)

    def test_modern_version_without_dot(self):
        self.assertEqual(self._version('openjdk version "25" 2025-09-16'), 25)

    def test_version_with_patch(self):
        self.assertEqual(self._version('java version "21.0.5" 2024-10-15'), 21)

    def test_unparseable_is_zero(self):
        self.assertEqual(self._version("whatever"), 0)


class JLinkParseTests(unittest.TestCase):
    def test_mem_lines_become_words(self):
        text = (
            "J-Link>mem 0x08000000, 0x10\n"
            "08000000 = 00 20 00 20 55 41 00 08  C5 41 00 08 AF 05 00 08  . . UA...A......\n"
        )
        words = chip._words(text)
        self.assertEqual(words[0x08000000], 0x20002000)
        self.assertEqual(words[0x08000004], 0x08004155)

    def test_garbage_gives_empty(self):
        self.assertEqual(chip._words("no memory here"), {})


class UnpackUpuxTests(unittest.TestCase):
    def test_upx_dispatch_uses_engines(self):
        """UPX 壳的 PE 会走到 extract_upx，而不是被当成"不是可剥的包"。"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "packed.exe"
            path.write_bytes(b"MZ" + b"\x00" * 200)
            info = FileInfo(path, path.stat().st_size, "pe", "PE32",
                            extra={"sections": [{"name": "UPX0", "raw": 0, "vsize": 4096, "entropy": 0.0},
                                                {"name": "UPX1", "raw": 100, "vsize": 4096, "entropy": 7.9}],
                                   "entry_section": "UPX1"})
            with mock.patch("pwre.unpack.sniff", return_value=info), \
                 mock.patch("pwre.engines.upx_path", return_value=None):
                from pwre.errors import ReError

                with self.assertRaises(ReError) as ctx:
                    apk_path = path
                    import pwre.unpack as unpack_mod
                    unpack_mod.unpack(apk_path, Path(tmp) / "out")
                self.assertIn("upx", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
