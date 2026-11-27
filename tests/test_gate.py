"""gate 的回归测试：假 APK + 本地 HTTP 探测，全程不联网。

覆盖三种静态判定、probe 的加密/明文翻转、连不上不抛异常，以及返回结构稳定。
"""

import json
import socket
import sys
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from itertools import count
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pwre.gate import gate  # noqa: E402

TOP_KEYS = {"verdict", "confidence", "target", "signals", "probe", "next_steps"}
TARGET_KEYS = {"kind", "path", "size"}
SIGNAL_KEYS = {"name", "weight", "evidence"}
PROBE_KEYS = {
    "url", "ok", "status", "content_type", "error", "bytes", "note", "signals", "weight",
}


_FILE_SEQ = count(1)


def make_apk(directory: str, extra: dict[str, bytes]) -> Path:
    path = Path(directory) / f"sample-{next(_FILE_SEQ)}.apk"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 32)
        for name, data in extra.items():
            zf.writestr(name, data)
    return path


def server_apk(directory: str) -> Path:
    return make_apk(directory, {
        "classes.dex": b"dex\n035\x00" + b"\x00" * 32
        + b"getApkContentsSigners\x00paywall\x00isVip\x00",
        "lib/armeabi-v7a/libjiagu.so": b"\x7fELF" + b"\x00" * 32
        + b"getPackageInfo\x00signatures\x00",
    })


def client_apk(directory: str) -> Path:
    return make_apk(directory, {
        "classes.dex": b"dex\n035\x00" + b"\x00" * 32 + b"com.example.app\x00",
        "lib/arm64-v8a/libflutter.so": b"\x7fELF" + b"\x00" * 32,
        "lib/arm64-v8a/libapp.so": b"\x00" * 32 + b"dart aot snapshot",
    })


def inconclusive_apk(directory: str) -> Path:
    return make_apk(directory, {"assets/x.txt": b"just a note, nothing interesting"})


class _JsonHandler(BaseHTTPRequestHandler):
    last_accept = None
    hits = 0

    def do_GET(self):
        type(self).hits += 1
        type(self).last_accept = self.headers.get("Accept")
        if self.path.startswith("/encrypted"):
            self._send_json(200, {"hash": True, "encrypted": "1", "payload": "A" * 300})
        elif self.path.startswith("/plain"):
            self._send_json(200, {"items": [{"id": 1}], "data": [{"id": 2}]})
        elif self.path.startswith("/denied"):
            self._send_json(401, {"error": "unauthorized"})
        elif self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "/plain")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        else:
            self._send_json(404, {"error": "not found"})

    def _send_json(self, status: int, payload: dict):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class StaticVerdictTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def test_packed_apk_is_server_authoritative(self):
        result = gate(server_apk(self._tmp.name))
        self.assertEqual(result["verdict"], "server_authoritative")
        self.assertEqual(result["confidence"], "high")
        names = {item["name"] for item in result["signals"]}
        self.assertIn("packer", names)
        self.assertIn("local_integrity", names)
        self.assertEqual(result["target"]["kind"], "apk")
        self.assertGreater(result["target"]["size"], 0)

    def test_flutter_apk_is_client_patchable(self):
        result = gate(client_apk(self._tmp.name))
        self.assertEqual(result["verdict"], "client_patchable")
        names = {item["name"] for item in result["signals"]}
        self.assertIn("framework", names)
        self.assertNotIn("packer", names)

    def test_plain_apk_is_inconclusive(self):
        result = gate(inconclusive_apk(self._tmp.name))
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertEqual(result["signals"], [])

    def test_api_hosts_are_deduped_in_evidence(self):
        path = make_apk(self._tmp.name, {
            "classes.dex": b"dex\n035\x00" + b"\x00" * 16
            + b"https://api.example.com/v1\x00https://api.example.com/v2\x00"
            + b"https://cdn.example.com/a\x00",
        })
        result = gate(path)
        signal = next(item for item in result["signals"] if item["name"] == "api_hosts")
        self.assertEqual(signal["weight"], 0)
        self.assertEqual(signal["evidence"].count("https://api.example.com"), 1)
        self.assertIn("https://cdn.example.com", signal["evidence"])
        self.assertEqual(result["verdict"], "inconclusive")

    def test_result_shape_is_stable(self):
        for path in (
            server_apk(self._tmp.name),
            client_apk(self._tmp.name),
            inconclusive_apk(self._tmp.name),
        ):
            result = gate(path)
            self.assertEqual(set(result), TOP_KEYS)
            self.assertEqual(set(result["target"]), TARGET_KEYS)
            self.assertEqual(result["target"]["path"], str(path))
            self.assertEqual(result["target"]["size"], path.stat().st_size)
            self.assertIn(result["verdict"], {"client_patchable", "server_authoritative", "inconclusive"})
            self.assertIn(result["confidence"], {"high", "medium", "low"})
            self.assertIsNone(result["probe"])
            self.assertGreaterEqual(len(result["next_steps"]), 3)
            for step in result["next_steps"]:
                self.assertIsInstance(step, str)
                self.assertTrue(step.strip())
            for item in result["signals"]:
                self.assertEqual(set(item), SIGNAL_KEYS)
                self.assertIsInstance(item["weight"], int)


class BinaryVerdictTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def test_pe_with_public_key_and_verifier_is_server(self):
        path = Path(self._tmp.name) / "licensed.exe"
        path.write_bytes(
            b"MZ" + b"\x00" * 256
            + b"-----BEGIN PUBLIC KEY-----\x00RSA_public_decrypt\x00license\x00"
        )
        result = gate(path)
        self.assertEqual(result["target"]["kind"], "pe")
        self.assertEqual(result["verdict"], "server_authoritative")

    def test_pe_with_local_flag_only_is_client(self):
        path = Path(self._tmp.name) / "local.exe"
        path.write_bytes(
            b"MZ" + b"\x00" * 256
            + b"activation\x00trial\x00isLicensed\x00registered\x00"
        )
        result = gate(path)
        names = {item["name"] for item in result["signals"]}
        self.assertIn("local_flag_check", names)
        # 纯字符串共现只算线索：没有结构性证据（壳/框架/完整性/验签/探测）不下结论。
        # 实战教训：curl.exe 里有 "not registered"、winlogon.exe 里有 "licensestatus"。
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertTrue(result["next_steps"])

    def test_pe_with_signature_and_two_local_markers_is_client(self):
        path = Path(self._tmp.name) / "licensed.exe"
        path.write_bytes(
            b"MZ" + b"\x00" * 256
            + b"-----BEGIN PUBLIC KEY-----\x00RSA_public_decrypt\x00"
            + b"isLicensed\x00registered\x00trial\x00"
        )
        result = gate(path)
        names = {item["name"] for item in result["signals"]}
        self.assertIn("signed_license_check", names)
        self.assertIn("flag_overrides_signature", names)
        self.assertEqual(result["verdict"], "client_patchable")

    def test_elf_kind_is_detected(self):
        path = Path(self._tmp.name) / "license.elf"
        path.write_bytes(b"\x7fELF" + b"\x00" * 64 + b"license\x00")
        result = gate(path)
        self.assertEqual(result["target"]["kind"], "elf")


class ProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _JsonHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.apk = inconclusive_apk(self._tmp.name)
        self.assertEqual(gate(self.apk)["verdict"], "inconclusive")

    def test_encrypted_envelope_flips_to_server(self):
        result = gate(self.apk, probe_url=f"{self.base}/encrypted", timeout=2.0)
        probe = result["probe"]
        self.assertIsNotNone(probe)
        self.assertEqual(set(probe), PROBE_KEYS)
        self.assertTrue(probe["ok"])
        self.assertEqual(probe["status"], 200)
        self.assertIsNone(probe["error"])
        self.assertEqual(probe["weight"], 3)
        self.assertEqual(result["verdict"], "server_authoritative")
        self.assertEqual(_JsonHandler.last_accept, "application/json")
        self.assertIn("probe_encrypted_envelope", {item["name"] for item in result["signals"]})

    def test_plaintext_items_flips_to_client(self):
        result = gate(self.apk, probe_url=f"{self.base}/plain", timeout=2.0)
        probe = result["probe"]
        self.assertTrue(probe["ok"])
        self.assertEqual(probe["weight"], -2)
        self.assertEqual(result["verdict"], "client_patchable")
        signal = next(item for item in probe["signals"] if item["name"] == "probe_plaintext_json")
        self.assertEqual(signal["weight"], -2)

    def test_probe_results_change_verdict(self):
        encrypted = gate(self.apk, probe_url=f"{self.base}/encrypted", timeout=2.0)
        plain = gate(self.apk, probe_url=f"{self.base}/plain", timeout=2.0)
        self.assertNotEqual(encrypted["verdict"], plain["verdict"])
        self.assertEqual(encrypted["verdict"], "server_authoritative")
        self.assertEqual(plain["verdict"], "client_patchable")

    def test_401_requires_auth(self):
        result = gate(self.apk, probe_url=f"{self.base}/denied", timeout=2.0)
        probe = result["probe"]
        self.assertEqual(probe["status"], 401)
        self.assertIsNone(probe["error"])
        self.assertEqual(probe["weight"], 2)
        self.assertIn("probe_auth_required", {item["name"] for item in probe["signals"]})

    def test_unreachable_probe_records_error_without_raising(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        result = gate(self.apk, probe_url=f"http://127.0.0.1:{port}/", timeout=1.0)
        probe = result["probe"]
        self.assertEqual(set(probe), PROBE_KEYS)
        self.assertFalse(probe["ok"])
        self.assertTrue(probe["error"])
        self.assertEqual(probe["weight"], 0)
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertIn("probe_unreachable", {item["name"] for item in probe["signals"]})
        self.assertGreaterEqual(len(result["next_steps"]), 3)

    def test_redirect_is_not_followed(self):
        before = _JsonHandler.hits
        result = gate(self.apk, probe_url=f"{self.base}/redirect", timeout=2.0)
        self.assertEqual(_JsonHandler.hits - before, 1)
        self.assertEqual(result["probe"]["status"], 302)
        self.assertEqual(result["probe"]["weight"], 0)


if __name__ == "__main__":
    unittest.main()
