"""CLI 冒烟测试：这些路径以前只在手测里跑，坏了没人发现。"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(*args, cwd=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    env["PYTHONUTF8"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "pwre", *args],
        capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, cwd=cwd,
    )


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.blob = self.dir / "fw.bin"
        self.blob.write_bytes(bytes([0x00, 0x10, 0x00, 0x20, 0x01, 0x01, 0x08, 0x00]))
        self.text = self.dir / "notes.txt"
        self.text.write_text("hello world, this is text\n", encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_id_on_unknown_binary_does_not_crash(self):
        done = run("id", str(self.blob))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("SHA256", done.stdout)
        self.assertNotIn("Traceback", done.stderr)

    def test_dis_refuses_text(self):
        done = run("dis", str(self.text))
        self.assertEqual(done.returncode, 1)
        self.assertIn("文本文件", done.stderr)

    def test_dis_refuses_raw_binary_without_base(self):
        done = run("dis", str(self.blob))
        self.assertEqual(done.returncode, 1)
        self.assertIn("加载地址", done.stderr)

    def test_json_after_subcommand(self):
        done = run("id", str(self.blob), "--json")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout)["path"], str(self.blob))

    def test_fw_on_plain_binary_asks_for_a_base(self):
        done = run("fw", str(self.blob))
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("--base", done.stderr)


if __name__ == "__main__":
    unittest.main()
