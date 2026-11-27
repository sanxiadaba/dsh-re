"""重打包链路的回归测试：合成 APK + 真实 apksigner（可用时）。

合成 APK 里的 AndroidManifest.xml 对 repack 来说只是普通字节；但 apksigner
签名前会解析它取 minSdkVersion，所以集成用例单独造一个最小的合法二进制 XML
（`_minimal_manifest()`），避免被 apksigner 以 "No XML chunk in file" 拒绝。

apksigner 缺失的分支用 mock 把 ANDROID_HOME/ANDROID_SDK_ROOT/PATH 全清空，
让探测真的返回 None；本机有 C:\\Android\\Sdk 时，集成用例临时把
ANDROID_SDK_ROOT 指向它，所以默认环境也能跑真签名。
"""

import os
import struct
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pwre import repack  # noqa: E402
from pwre.errors import ReError  # noqa: E402

LOCAL_SDK = Path(r"C:\Android\Sdk")
STORED = zipfile.ZIP_STORED
DEFLATED = zipfile.ZIP_DEFLATED


# ---------------------------------------------------------------- 合成样本


def _minimal_manifest() -> bytes:
    """一个只含 <manifest/> 的 AXML：apksigner 能解析，minSdk 按默认值处理。"""
    strings = ["manifest"]
    data = bytearray()
    offsets = []
    for text in strings:
        offsets.append(len(data))
        encoded = text.encode("utf-8")
        data += bytes([len(text), len(encoded)]) + encoded + b"\x00"
    while len(data) % 4:
        data += b"\x00"
    strings_start = 28 + 4 * len(strings)
    pool_size = strings_start + len(data)
    pool = struct.pack(
        "<HHIIIIII", 0x0001, 28, pool_size, len(strings), 0, 0x100, strings_start, 0
    )
    pool += b"".join(struct.pack("<I", offset) for offset in offsets) + bytes(data)

    def node(kind: int, body: bytes, size: int) -> bytes:
        return struct.pack("<HHIII", kind, 16, size, 1, 0xFFFFFFFF) + body

    start_element = node(
        0x0102, struct.pack("<IIHHHHHH", 0xFFFFFFFF, 0, 20, 20, 0, 0, 0, 0), 36
    )
    end_element = node(0x0103, struct.pack("<II", 0xFFFFFFFF, 0), 24)
    total = 8 + len(pool) + len(start_element) + len(end_element)
    return struct.pack("<HHI", 0x0003, 8, total) + pool + start_element + end_element


def _make_apk(path: Path, manifest: bytes | None = None) -> dict[str, bytes]:
    """最小 APK：manifest/dex/assets/so；manifest 与 so 用 STORED，其余 DEFLATED。"""
    files = {
        "AndroidManifest.xml": manifest if manifest is not None else b"\x03\x00\x08\x00repack-test",
        "classes.dex": b"dex\n035\x00" + bytes(range(64)),
        "assets/x.txt": b"hello asset\n",
        "lib/arm64-v8a/libapp.so": os.urandom(4096),
    }
    stored = {"AndroidManifest.xml", "lib/arm64-v8a/libapp.so"}
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in files.items():
            info = zipfile.ZipInfo(name, (2024, 1, 1, 0, 0, 0))
            info.compress_type = STORED if name in stored else DEFLATED
            info.external_attr = 0o100644 << 16
            zf.writestr(info, data)
    return files


def _local_header(path: Path, name: str) -> tuple[zipfile.ZipInfo, int, int]:
    """返回 (ZipInfo, 数据区起点, local extra 长度)。"""
    with zipfile.ZipFile(path) as zf:
        info = zf.getinfo(name)
        with open(path, "rb") as fh:
            fh.seek(info.header_offset)
            head = fh.read(30)
            if len(head) != 30 or head[:4] != b"PK\x03\x04":
                raise AssertionError(f"{name} 的 local header 坏了")
            name_len, extra_len = struct.unpack("<HH", head[26:30])
    return info, info.header_offset + 30 + name_len + extra_len, extra_len


# ---------------------------------------------------------------- repack


class RepackTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.src = self.root / "app.apk"
        self.files = _make_apk(self.src)

    def tearDown(self):
        self._tmp.cleanup()

    def test_entries_methods_and_attributes_are_preserved(self):
        dst = self.root / "out.apk"
        with mock.patch.object(repack, "zipalign_path", return_value=None):
            result = repack.repack(self.src, dst)

        self.assertEqual(result["entries"], len(self.files))
        self.assertEqual(result["alignment"], "builtin")
        self.assertEqual(result["replaced"], [])
        self.assertEqual(result["unmatched"], [])
        self.assertEqual(result["duplicates"], [])

        with zipfile.ZipFile(self.src) as before, zipfile.ZipFile(dst) as after:
            self.assertEqual(before.namelist(), after.namelist())
            self.assertEqual(len(after.namelist()), len(set(after.namelist())))
            for name in before.namelist():
                self.assertEqual(after.read(name), before.read(name), name)
                old = before.getinfo(name)
                new = after.getinfo(name)
                self.assertEqual(new.compress_type, old.compress_type, name)
                self.assertEqual(new.external_attr, old.external_attr, name)

    def test_stored_entries_are_four_byte_aligned(self):
        dst = self.root / "aligned.apk"
        with mock.patch.object(repack, "zipalign_path", return_value=None):
            result = repack.repack(self.src, dst)
        self.assertEqual(result["alignment"], "builtin")

        with zipfile.ZipFile(dst) as zf:
            stored = [info for info in zf.infolist() if info.compress_type == STORED]
        self.assertTrue(stored)
        extra_lengths = []
        for info in stored:
            # header_offset 是 local header 起点；zipalign 判定的是数据区起点，
            # 也就是 header_offset + 30 + 文件名长度 + extra 长度。
            _, data_offset, extra_len = _local_header(dst, info.filename)
            self.assertEqual(data_offset % 4, 0, f"{info.filename} 数据区未对齐：{data_offset}")
            extra_lengths.append(extra_len)
        # manifest 是第一个 STORED，未填充时数据区在 49；填充后必然有 extra。
        self.assertTrue(any(length > 0 for length in extra_lengths), "对齐没有真正插 padding")

    def test_replace_hit_and_unmatched(self):
        replace_dir = self.root / "replace"
        target = replace_dir / "lib" / "arm64-v8a" / "libapp.so"
        target.parent.mkdir(parents=True)
        new_so = b"patched libapp" + os.urandom(128)
        target.write_bytes(new_so)
        (replace_dir / "assets").mkdir()
        (replace_dir / "assets" / "not-in-apk.txt").write_bytes(b"extra")

        dst = self.root / "replaced.apk"
        with mock.patch.object(repack, "zipalign_path", return_value=None):
            result = repack.repack(self.src, dst, replace_dir=replace_dir)

        self.assertEqual(result["replaced"], ["lib/arm64-v8a/libapp.so"])
        self.assertEqual(result["unmatched"], ["assets/not-in-apk.txt"])
        with zipfile.ZipFile(self.src) as before, zipfile.ZipFile(dst) as after:
            self.assertEqual(after.read("lib/arm64-v8a/libapp.so"), new_so)
            self.assertEqual(
                after.getinfo("lib/arm64-v8a/libapp.so").compress_type,
                before.getinfo("lib/arm64-v8a/libapp.so").compress_type,
            )
            self.assertEqual(
                after.getinfo("lib/arm64-v8a/libapp.so").external_attr,
                before.getinfo("lib/arm64-v8a/libapp.so").external_attr,
            )
            self.assertNotIn("assets/not-in-apk.txt", after.namelist())

    def test_duplicate_source_entries_are_written_once(self):
        duplicate = self.root / "duplicate.apk"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(duplicate, "w") as zf:
                zf.writestr("assets/x.txt", b"first")
                zf.writestr("assets/x.txt", b"second")
        dst = self.root / "deduped.apk"
        with mock.patch.object(repack, "zipalign_path", return_value=None):
            result = repack.repack(duplicate, dst)

        with zipfile.ZipFile(dst) as after:
            self.assertEqual(after.namelist(), ["assets/x.txt"])
            self.assertEqual(after.read("assets/x.txt"), b"first")
        self.assertEqual(result["entries"], 1)
        self.assertEqual(result["duplicates"], ["assets/x.txt"])

    def test_bad_zip_becomes_reerror(self):
        bad = self.root / "broken.apk"
        bad.write_bytes(b"this is definitely not a zip")
        with self.assertRaises(ReError) as caught:
            repack.repack(bad, self.root / "out.apk")
        self.assertTrue(caught.exception.hint)

    def test_crc_error_becomes_reerror(self):
        _, offset, _ = _local_header(self.src, "assets/x.txt")
        raw = bytearray(self.src.read_bytes())
        raw[offset] ^= 0xFF
        self.src.write_bytes(raw)

        with self.assertRaises(ReError) as caught:
            repack.repack(self.src, self.root / "out.apk")
        self.assertTrue(caught.exception.hint)


# ---------------------------------------------------------------- 工具探测 / 参数


class ToolTests(unittest.TestCase):
    def test_detection_order_and_highest_build_tools_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            engines_buildtools = root / "engines" / "buildtools"
            engines_buildtools.mkdir(parents=True)
            (engines_buildtools / "apksigner.bat").write_bytes(b"")
            sdk = root / "sdk"
            for version in ("33.0.9", "34.0.2"):
                folder = sdk / "build-tools" / version
                folder.mkdir(parents=True)
                (folder / "apksigner.bat").write_bytes(b"")
            with mock.patch.object(repack.engines, "engines_dir", return_value=root / "engines"), \
                 mock.patch.dict(os.environ, {"ANDROID_HOME": str(sdk), "ANDROID_SDK_ROOT": ""}), \
                 mock.patch.object(repack.shutil, "which", return_value=None):
                # 1) engines/buildtools 优先
                self.assertEqual(repack.apksigner_path(), engines_buildtools / "apksigner.bat")
                # 2) 去掉它之后，从 SDK 里取版本号最大的
                (engines_buildtools / "apksigner.bat").unlink()
                self.assertEqual(
                    repack.apksigner_path(),
                    sdk / "build-tools" / "34.0.2" / "apksigner.bat",
                )

    def test_sign_without_apksigner_raises_with_hint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with mock.patch.object(repack.engines, "engines_dir", return_value=root / "engines"), \
                 mock.patch.dict(os.environ, {"ANDROID_HOME": "", "ANDROID_SDK_ROOT": ""}), \
                 mock.patch.object(repack.shutil, "which", return_value=None):
                self.assertIsNone(repack.apksigner_path())
                with self.assertRaises(ReError) as caught:
                    repack.sign(root / "app.apk", root / "key.jks", "pass1234", "re")
        self.assertEqual(str(caught.exception), "找不到 apksigner")
        self.assertEqual(caught.exception.hint, "装 Android build-tools，或把 build-tools 放进 PATH")

    def test_sign_argv_keeps_special_password_in_one_element(self):
        argv = repack._sign_argv(
            Path("in.apk"),
            Path("key.jks"),
            'p a&s"s%1',
            "alias",
            "k&p",
            True,
            True,
            False,
            Path("out.apk"),
        )
        self.assertIsInstance(argv, list)
        self.assertEqual(argv[0], "sign")
        self.assertIn('pass:p a&s"s%1', argv)
        self.assertIn("pass:k&p", argv)
        self.assertEqual(argv[argv.index("--v2-signing-enabled") + 1], "true")
        self.assertEqual(argv[argv.index("--v3-signing-enabled") + 1], "false")
        self.assertEqual(argv[argv.index("--out") + 1], "out.apk")
        self.assertEqual(argv[-1], "in.apk")

    @unittest.skipUnless(os.name == "nt", "这条只在 Windows 的 .bat 转发上生效")
    def test_bat_is_bypassed_with_jar_so_special_passwords_survive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tool = root / "apksigner.bat"
            tool.write_bytes(b"")
            jar = root / "lib" / "apksigner.jar"
            jar.parent.mkdir()
            jar.write_bytes(b"")
            password = 'pass:a b"c%d^e'
            with mock.patch.object(repack, "_java_path", return_value=Path("java.exe")):
                argv = repack._apksigner_command(tool, ["sign", password])
        self.assertEqual(argv[:3], ["java.exe", "-jar", str(jar)])
        self.assertEqual(argv[-1], password)


# ---------------------------------------------------------------- 真签名集成


def _local_apksigner() -> Path | None:
    build_tools = LOCAL_SDK / "build-tools"
    if not build_tools.is_dir():
        return None
    for child in sorted(build_tools.iterdir(), reverse=True):
        if not child.is_dir():
            continue
        for name in ("apksigner.bat", "apksigner.exe"):
            candidate = child / name
            if candidate.is_file():
                return candidate
    return None


@unittest.skipUnless(
    repack.apksigner_path() is not None or _local_apksigner() is not None,
    "apksigner 不可用（需要 Android build-tools）",
)
class SignIntegrationTests(unittest.TestCase):
    def test_gen_key_sign_verify(self):
        if repack._keytool_path() is None:
            self.skipTest("keytool 不可用（需要 JDK/JRE 的 bin）")

        env = {}
        if repack.apksigner_path() is None:
            env["ANDROID_SDK_ROOT"] = str(LOCAL_SDK)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, env):
            root = Path(tmp)
            src = root / "app.apk"
            _make_apk(src, manifest=_minimal_manifest())
            packed = root / "aligned.apk"
            result = repack.repack(src, packed)
            if repack.zipalign_path() is not None:
                self.assertEqual(result["alignment"], "zipalign")

            keystore = root / "test.jks"
            key = repack.gen_key(keystore, "re", "pass1234")
            self.assertTrue(keystore.is_file())
            self.assertEqual(key["alias"], "re")

            signed = repack.sign(packed, keystore, "pass1234", "re")
            self.assertEqual(signed["path"], str(packed))
            self.assertTrue(signed["v1"] and signed["v2"] and signed["v3"])

            checked = repack.verify(packed)
            self.assertTrue(checked["ok"], checked["raw"])
            self.assertIn("v2", checked["schemes"])
            self.assertIn("CN=re", checked["dn"])
            self.assertEqual(len(checked["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
