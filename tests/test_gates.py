"""格式门 / 契约门的回归测试：认出来的东西不许当固件切，JSON 必须带版本。

这些不是凑覆盖率：`re hex LICENSE --base 0x08000000` 以前真的 exit 0，把 1067
字节的许可证摊成 0x08000000 的固件；`re proto LICENSE` 照切 66 帧。违反「不猜」。
"""

import argparse
import contextlib
import importlib.util
import io
import json
import random
import sys
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from pwre import cli, decompile, detect, out  # noqa: E402
from pwre.errors import ReError  # noqa: E402

LICENSE = ROOT / "LICENSE"

# 校验和自洽的 Intel HEX 片段：4 字节落在 0x08000000
HEX_SAMPLE = ":020000040800F2\n:0400000001020304F2\n:00000001FF\n"


def run(*argv):
    """进程内跑一遍 CLI，返回 (退出码, stdout, stderr)。"""
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = cli.main([str(item) for item in argv])
    return code, stdout.getvalue(), stderr.getvalue()


def bare_blob() -> bytes:
    """确定性伪随机 64 字节：没有 magic，也不是文本，只能认成 unknown。"""
    return bytes(random.Random(20261128).randrange(256) for _ in range(64))


def optional_module(name: str) -> str:
    """子命令名对应的模块名（dev→device、net→netcap）；没映射时同名。"""
    return cli._OPTIONAL_MODULES.get(name, name)


def module_present(name: str) -> bool:
    """簇模块是否已经合入当前分支。合入后骨架断言就不适用了。"""
    return importlib.util.find_spec(f"pwre.{optional_module(name)}") is not None


class FormatGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.blob = self.dir / "blob.bin"
        self.blob.write_bytes(bare_blob())

    def tearDown(self):
        self.tmp.cleanup()

    def test_hex_refuses_license_with_base(self):
        code, _out, err = run("hex", LICENSE, "--base", "0x08000000")
        self.assertEqual(code, 2, err)
        self.assertIn("不是固件", err)
        self.assertIn("--base", err)

    def test_proto_refuses_license_frames(self):
        code, _out, err = run("proto", LICENSE, "--frame", "16")
        self.assertEqual(code, 2, err)
        self.assertIn("不是裸帧数据", err)

    def test_hex_refuses_zip_with_base(self):
        archive = self.dir / "pkg.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("a.txt", "hello")
        code, _out, err = run("hex", archive, "--base", "0x08000000")
        self.assertEqual(code, 2, err)
        self.assertIn("不是固件", err)

    def test_bare_binary_with_base_is_still_accepted(self):
        self.assertEqual(detect.sniff(self.blob).kind, "unknown")
        code, out_text, err = run("hex", self.blob, "--base", "0x08000000")
        self.assertEqual(code, 0, err)
        self.assertIn("64 字节", out_text)

    def test_bare_binary_frames_are_still_accepted(self):
        code, out_text, err = run("proto", self.blob, "--frame", "16")
        self.assertEqual(code, 0, err)
        self.assertIn("4 帧", out_text)

    def test_real_ihex_is_accepted(self):
        fw = self.dir / "fw.hex"
        fw.write_text(HEX_SAMPLE, encoding="utf-8")
        self.assertEqual(detect.sniff(fw).kind, "ihex")
        code, out_text, err = run("hex", fw)
        self.assertEqual(code, 0, err)
        self.assertIn("0x08000000", out_text)

    def test_fw_on_a_text_file_refuses_the_base_shortcut(self):
        notes = self.dir / "notes.txt"
        notes.write_text("hello, this is text\n", encoding="utf-8")
        code, _out, err = run("fw", notes, "--base", "0x08000000")
        self.assertEqual(code, 2, err)
        self.assertIn("不是固件", err)


class JsonContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.blob = self.dir / "blob.bin"
        self.blob.write_bytes(bare_blob())

    def tearDown(self):
        self.tmp.cleanup()

    def test_id_json_carries_schema_and_packer_fields(self):
        code, out_text, err = run("id", self.blob, "--json")
        self.assertEqual(code, 0, err)
        payload = json.loads(out_text)
        self.assertEqual(payload["schema"], 1)
        self.assertIn("packer", payload)
        self.assertIn("packed_reasons", payload)
        self.assertEqual(payload["packer"], "")
        self.assertEqual(payload["packed_reasons"], [])

    def test_emit_copies_the_payload(self):
        class Args:
            json = True

        payload = {"path": "x", "size": 1}
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            out.emit(Args(), ["ignored"], payload)
        printed = json.loads(stdout.getvalue())
        self.assertEqual(printed["schema"], 1)
        self.assertEqual(printed["path"], "x")
        # 原 dict 不能被污染：调用方常常复用同一个 payload
        self.assertEqual(payload, {"path": "x", "size": 1})
        self.assertEqual(out.SCHEMA, 1)

    def test_emit_without_json_stays_text(self):
        class Args:
            json = False

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            out.emit(Args(), ["一行文本"], {"path": "x"})
        self.assertEqual(stdout.getvalue().strip(), "一行文本")


class OptionalModuleMapTests(unittest.TestCase):
    def test_subcommand_names_map_to_real_module_names(self):
        # R-01 的模块叫 device、R-03 的叫 netcap；映射错了合入后也永远只有骨架
        self.assertEqual(cli._OPTIONAL_MODULES["dev"], "device")
        self.assertEqual(cli._OPTIONAL_MODULES["net"], "netcap")
        self.assertEqual(cli._OPTIONAL_MODULES["dyn"], "dyn")
        self.assertEqual(cli._OPTIONAL_MODULES["case"], "case")
        self.assertEqual(optional_module("dev"), "device")
        self.assertEqual(optional_module("net"), "netcap")

    def test_add_optional_imports_the_mapped_module(self):
        imported = []
        fake = types.SimpleNamespace(add_parser=lambda subparsers: None)

        def fake_import(dotted):
            imported.append(dotted)
            return fake

        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="cmd")
        with mock.patch.object(cli.importlib, "import_module", fake_import):
            cli._add_optional(sub, "dev", "设备/模拟器生命周期")
            cli._add_optional(sub, "net", "抓包与 flow")
        self.assertEqual(imported, ["pwre.device", "pwre.netcap"])
        # 有 add_parser 的模块自己注册，不该再挂骨架
        self.assertNotIn("dev", sub.choices)
        self.assertNotIn("net", sub.choices)


class StubRegistrationTests(unittest.TestCase):
    def test_unmerged_cluster_is_exit_3_not_usage_error(self):
        pending = [name for name in ("dev", "dyn", "net", "case") if not module_present(name)]
        if not pending:
            self.skipTest("四簇模块都已合入，骨架不再生效")
        for name in pending:
            with self.subTest(name=name):
                code, _out, err = run(name, "list")
                self.assertEqual(code, 3, err)
                self.assertIn("尚未实现", err)

    def test_stub_accepts_trailing_arguments(self):
        if module_present("dev"):
            self.skipTest("pwre.device 已合入，dev 不再是骨架")
        # argparse 先报 invalid choice 的话，调用方看到的是 2，不是"尚未实现"
        code, _out, err = run("dev", "start", "pixel", "--headless")
        self.assertEqual(code, 3, err)
        self.assertIn("re dev 尚未实现", err)


class HeadReadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.blob = self.dir / "blob.bin"
        self.blob.write_bytes(bare_blob())

    def tearDown(self):
        self.tmp.cleanup()

    def test_id_does_not_read_the_whole_file(self):
        reads = []
        original = Path.read_bytes

        def spy(path_self, *args, **kwargs):
            reads.append(str(path_self))
            return original(path_self, *args, **kwargs)

        with mock.patch.object(Path, "read_bytes", spy):
            code, out_text, err = run("id", self.blob)
        self.assertEqual(code, 0, err)
        self.assertEqual(reads, [], f"id 还在整读文件：{reads}")

    def test_head_read_is_bounded(self):
        big = self.dir / "big.bin"
        big.write_bytes(b"\x00" * (3 << 20))
        self.assertEqual(len(cli._head_bytes(big, 16)), 16)


class EntryScriptTests(unittest.TestCase):
    def test_re_cmd_is_crlf_and_targets_the_console_script(self):
        raw = (ROOT / "re.cmd").read_bytes()
        cr, lf = raw.count(b"\r"), raw.count(b"\n")
        self.assertGreater(lf, 0)
        # cmd.exe 逐行解析；CR 少于「行数-1」时整行会被当成一条命令
        self.assertGreaterEqual(cr, lf - 1)
        self.assertNotIn(b"\n", raw.replace(b"\r\n", b""), "还有裸 LF")
        self.assertIn(b"re.exe", raw)
        self.assertIn(b"-m pwre", raw)


class JdkGateTests(unittest.TestCase):
    def _check(self, need, have):
        with mock.patch.object(decompile.engines, "ghidra_java_min", return_value=need), \
                mock.patch.object(decompile.engines, "java_version", return_value=have):
            decompile._require_jdk("java.exe")

    def test_old_jdk_is_refused_with_code_3(self):
        with self.assertRaises(ReError) as caught:
            self._check(25, 8)
        self.assertEqual(caught.exception.code, 3)
        self.assertIn("JDK 25", caught.exception.message)

    def test_matching_jdk_passes(self):
        self._check(25, 25)
        self._check(17, 21)

    def test_unknown_version_is_not_a_failure(self):
        # 版本探测失败（0）是探测问题，不是版本不够；不凭空判死
        self._check(25, 0)


if __name__ == "__main__":
    unittest.main()
