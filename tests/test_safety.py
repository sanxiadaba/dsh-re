"""路径安全与 diff 尾部的回归测试。"""

import io
import unittest
import zipfile
from pathlib import Path
import tempfile

from pwre import diff
from pwre.errors import ReError
from pwre.unpack import _safe_name, extract_zip


class SafeNameTests(unittest.TestCase):
    def test_normal_paths_pass(self):
        self.assertEqual(_safe_name("a/b.txt"), "a/b.txt")
        self.assertEqual(_safe_name("a\\b.txt"), "a/b.txt")
        self.assertEqual(_safe_name("./a/b.txt"), "a/b.txt")

    def test_escape_attempts_are_rejected(self):
        for name in ("C:evil.txt", "C:/evil.txt", "/abs/x", "../x", "a/../../b"):
            with self.subTest(name=name):
                with self.assertRaises(ReError):
                    _safe_name(name)

    def test_zip_traversal_writes_nothing_outside(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "evil.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("good.txt", "ok")
                zf.writestr("../escape.txt", "no")
            dest = root / "out"
            dest.mkdir()
            with self.assertRaises(ReError):
                extract_zip(archive, dest)
            self.assertFalse((root / "escape.txt").exists())


class DiffTailTests(unittest.TestCase):
    def test_appended_bytes_count_as_difference(self):
        ranges = diff._blocks(b"a" * 4096, b"a" * 4096 + b"tail")
        self.assertTrue(ranges)
        self.assertEqual(ranges[-1][1], 4100)

    def test_equal_files_have_no_ranges(self):
        self.assertEqual(diff._blocks(b"abc", b"abc"), [])


if __name__ == "__main__":
    unittest.main()
