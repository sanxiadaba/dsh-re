"""客户端可改还是服务端权威：把"改这里有没有用"变成可复算的信号清单。

实战里最贵的错误不是补丁写错，而是花几个小时改客户端，最后发现
"能不能看 / 能不能用"是服务端判的。这里只做两件事：静态看包并按信号打分；
给了 probe_url 就再探一次接口。结论是启发式，不替代实际抓包。

评分：score = sum(signal["weight"])，正=偏服务端，负=偏客户端。
    score >= +3 -> server_authoritative
    score <= -2 -> client_patchable
    其它        -> inconclusive
置信度：|score| >= 6 high，>= 3 medium，否则 low。
"""

from __future__ import annotations

import json
import re
import zipfile
import zlib
from pathlib import Path
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlsplit

try:  # 复用 APK 模块的壳库表；单独拷一份迟早会漂
    from .apk import PACKERS as _APK_PACKERS
except Exception:  # pragma: no cover - 只在 apk 模块被拆走时走到
    _APK_PACKERS = {}

# apk.py 不可用时的兜底，覆盖国内常见加固壳
_FALLBACK_PACKERS = {
    "libjiagu.so": "360 加固",
    "libjiagu_art.so": "360 加固",
    "libsgmain.so": "阿里聚安全",
    "libshell.so": "腾讯乐固",
    "libDexHelper.so": "梆梆加固",
    "libnesec.so": "网易易盾",
    "libexec.so": "爱加密",
    "libmobisec.so": "阿里加固",
    "libbaiduprotect.so": "百度加固",
    "libprotectClass.so": "盛大加固",
}
PACKERS = dict(_APK_PACKERS) if _APK_PACKERS else dict(_FALLBACK_PACKERS)

FRAMEWORKS = (
    ("Flutter（Dart AOT）", ("libflutter.so", "libapp.so"), "Dart AOT 快照随包，逻辑主要在 libapp.so"),
    ("React Native（JS bundle）", ("libreactnativejni.so", "assets/index.android.bundle"), "JS bundle 随包，可直接读改"),
    ("Unity（IL2CPP/Mono）", ("libunity.so", "assets/bin/Data/"), "托管逻辑/资源随包，可在本地改"),
)

INTEGRITY_MARKERS = (
    "getPackageInfo",
    "signatures",
    "getApkContentsSigners",
    "nativeVerifyIntegrity",
    "ensureVerified",
    "isTampered",
    "integrity",
)
PAYWALL_MARKERS = (
    "paywall",
    "isVip",
    "vipLevel",
    "is_vip",
    "need_pay",
    "DramaPaywall",
    "buy_vip",
    "subscribe",
    "entitlement",
)
PAYMENT_MARKERS = ("alipay", "wechatpay", "/order", "/pay", "/vip/")

LICENSE_MARKERS = (
    "license",
    "activation",
    "activation code",
    "serial",
    "trial",
    "rsa_public_decrypt",
    "begin public key",
    "rsa public key",
)
VERIFY_MARKERS = (
    "rsa_public_decrypt",
    "evp_digestverify",
    "cryptverifysignature",
    "verify_signature",
    "verify_license",
    "verifylicense",
    "validatelicense",
    "check_license",
    "checklicense",
)
LOCAL_FLAG_MARKERS = (
    "islicensed",
    "is_licensed",
    "isactivated",
    "is_activated",
    "registered",
    "licensed",
    "trial_days",
    "trialdays",
    "activationstatus",
    "licensestatus",
    "expired",
)

_APK_ENTRY_LIMIT = 8 << 20
_APK_TOTAL_LIMIT = 24 << 20
_BINARY_LIMIT = 8 << 20
_PROBE_LIMIT = 4096
_PROBE_ACCEPT = "application/json"

_ASCII_STRINGS = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16LE_STRINGS = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_UTF16BE_STRINGS = re.compile(rb"(?:\x00[\x20-\x7e]){4,}")
_URL_RE = re.compile(r"https?://[A-Za-z0-9._~:%\[\]@!$&'()*+,;=/?-]+", re.IGNORECASE)
_LONG_B64_RE = re.compile(r"[A-Za-z0-9+/]{200,}={0,2}")
_HASH_TRUE_RE = re.compile(r'"hash"\s*:\s*true', re.IGNORECASE)

# 这些条目里不会有代码字符串，读了只会挤占扫描预算
_SCAN_SKIP_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp", ".ico",
    ".mp3", ".mp4", ".m4a", ".aac", ".ogg", ".wav", ".flac",
    ".ttf", ".otf", ".woff", ".woff2",
    ".zip", ".gz", ".xz", ".bz2", ".7z", ".rar", ".apk", ".jar",
}
_ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def _signal(name: str, weight: int, evidence: str) -> dict:
    return {"name": name, "weight": int(weight), "evidence": evidence}


def _matched(blob: str, markers: tuple[str, ...]) -> list[str]:
    found = []
    for marker in markers:
        if marker.lower() in blob and marker not in found:
            found.append(marker)
    return found


def _found_text(found: list[str], limit: int = 6) -> str:
    shown = "、".join(found[:limit])
    if len(found) > limit:
        shown += f" …（共 {len(found)} 个）"
    return shown


def _strings(data: bytes) -> list[str]:
    """ASCII / UTF-16LE / UTF-16BE 的粗字符串，够匹配英文标识符即可。"""
    out = [m.group().decode("ascii", "replace") for m in _ASCII_STRINGS.finditer(data)]
    out.extend(m.group().decode("utf-16-le", "replace") for m in _UTF16LE_STRINGS.finditer(data))
    out.extend(m.group().decode("utf-16-be", "replace") for m in _UTF16BE_STRINGS.finditer(data))
    return out


def _kind(path: Path) -> str:
    with open(path, "rb") as fh:
        head = fh.read(8)
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] in _ZIP_MAGIC:
        try:
            with zipfile.ZipFile(path) as zf:
                names = set(zf.namelist())
        except (OSError, zipfile.BadZipFile):
            return "zip"
        # 自制/截断的样本可能没带 manifest，扩展名兜底仍按 APK 分析
        if "AndroidManifest.xml" in names or path.suffix.lower() == ".apk":
            return "apk"
        return "zip"
    return "unknown"


def _wants_apk_entry(name: str) -> bool:
    if name.startswith("META-INF/"):  # 证书/签名块，不参与代码字符串判定
        return False
    return Path(name).suffix.lower() not in _SCAN_SKIP_SUFFIXES


def _apk_priority(name: str) -> int:
    suffix = Path(name).suffix.lower()
    if name.startswith("classes") and suffix == ".dex":
        return 0
    if name == "AndroidManifest.xml":
        return 1
    if name.startswith("lib/") and suffix == ".so":
        return 2
    if name.startswith("assets/"):
        return 3
    if name == "resources.arsc":
        return 4
    return 5


def _apk_material(path: Path) -> tuple[set[str], str, list[str]]:
    with zipfile.ZipFile(path) as zf:
        names = {info.filename for info in zf.infolist() if not info.is_dir()}
        strings: list[str] = []
        budget = _APK_TOTAL_LIMIT
        for name in sorted(names, key=lambda item: (_apk_priority(item), item)):
            if budget <= 0:
                break
            if not _wants_apk_entry(name):
                continue
            try:
                with zf.open(name) as fh:
                    data = fh.read(min(_APK_ENTRY_LIMIT, budget))
            except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError,
                    EOFError, zlib.error):
                # 单个条目坏不该让整条判定崩：跳过，结论仍然给
                continue
            budget -= len(data)
            strings.extend(_strings(data))
    return names, "\n".join(strings).lower(), strings


def _api_hosts(strings: list[str]) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    for text in strings:
        for match in _URL_RE.finditer(text):
            raw = match.group().rstrip(".,;:)]}\"'")
            try:
                parts = urlsplit(raw)
            except ValueError:
                continue
            if not parts.hostname:
                continue
            host = f"{parts.scheme.lower()}://{parts.netloc.lower()}"
            if host not in seen:
                seen.add(host)
                hosts.append(host)
            if len(hosts) >= 10:
                return hosts
    return hosts


def _apk_signals(path: Path) -> list[dict]:
    names, blob, strings = _apk_material(path)
    signals = []

    basenames = {Path(name).name for name in names}
    lib_basenames = {Path(name).name for name in names if name.startswith("lib/")}
    packed = [(lib, label) for lib, label in PACKERS.items() if lib in lib_basenames]
    if packed:
        detail = "、".join(f"{lib}（{label}）" for lib, label in packed[:4])
        signals.append(_signal(
            "packer",
            3,
            f"命中加固/壳：{detail}；壳会拦截改包并做自校验，客户端侧校验通常更强",
        ))

    frameworks = []
    for label, marks, why in FRAMEWORKS:
        hit = None
        for mark in marks:
            if mark.endswith("/"):
                if any(name.startswith(mark) for name in names):
                    hit = mark
                    break
            elif mark in names or mark in basenames:
                hit = mark
                break
        if hit:
            frameworks.append((label, hit, why))
    if frameworks:
        detail = "；".join(f"{label}（{hit}）：{why}" for label, hit, why in frameworks)
        signals.append(_signal(
            "framework",
            -2,
            f"命中可改框架：{detail}。逻辑/资源随包下发，客户端侧有落点",
        ))

    integrity = _matched(blob, INTEGRITY_MARKERS)
    if integrity:
        signals.append(_signal(
            "local_integrity",
            2,
            f"命中本地完整性/签名校验串：{_found_text(integrity)}；改包可能被客户端自己发现"
            "（signatures 也可能只是权限声明，需结合调用点确认）",
        ))

    paywall = _matched(blob, PAYWALL_MARKERS)
    if paywall:
        signals.append(_signal(
            "paywall_model",
            1,
            f"命中付费墙/会员模型字段：{_found_text(paywall)}；权益判定很可能最终由服务端确认",
        ))

    payment = _matched(blob, PAYMENT_MARKERS)
    if payment:
        signals.append(_signal(
            "payment_server_order",
            2,
            f"命中支付/服务端订单串：{_found_text(payment)}；订单与权益通常服务端落库",
        ))

    hosts = _api_hosts(strings)
    if hosts:
        signals.append(_signal(
            "api_hosts",
            0,
            f"明文 API 主机（去重，最多 10 个）：{', '.join(hosts)}；下一步优先 probe 这些主机",
        ))
    return signals


def _binary_blob(path: Path) -> str:
    with open(path, "rb") as fh:
        data = fh.read(_BINARY_LIMIT)
    return "\n".join(_strings(data)).lower()


def _binary_signals(path: Path) -> list[dict]:
    blob = _binary_blob(path)
    signals = []

    license_hits = _matched(blob, LICENSE_MARKERS)
    verify_hits = _matched(blob, VERIFY_MARKERS)
    local_hits = _matched(blob, LOCAL_FLAG_MARKERS)
    has_key = "begin public key" in blob or "rsa public key" in blob

    if has_key and verify_hits:
        signals.append(_signal(
            "signed_license_check",
            3,
            "有硬编码公钥且命中验签函数（"
            f"{_found_text(verify_hits)}）：离线伪造不了签名，授权结论偏服务端",
        ))
    elif has_key:
        signals.append(_signal(
            "hardcoded_public_key",
            1,
            "有硬编码公钥/证书串，但没找到明确验签函数名（可能内联或间接调用）：需跟到调用点",
        ))
    elif verify_hits:
        signals.append(_signal(
            "license_verifier",
            2,
            f"命中授权/验签函数串：{_found_text(verify_hits)}；授权结论可能不只看本地标志位",
        ))
    elif license_hits:
        signals.append(_signal(
            "license_strings",
            1,
            f"命中授权/许可痕迹：{_found_text(license_hits)}；可能联网校验，也可能只是本地判断",
        ))

    if local_hits:
        signals.append(_signal(
            "local_flag_check",
            -3,
            f"命中本地授权标志位比较痕迹：{_found_text(local_hits)}；"
            "如果授权只比标志位，客户端侧可直接改（仍需确认资源/服务端约束）",
        ))

    # 验签 + 本地标志位同时存在：验签结果最后落在本地标志上，改标志即可绕过
    # （VOFA+ 与 UartAssist 都是这个形状：RSA 验签失败会清标志，但标志本身可被改写）
    if has_key and verify_hits and local_hits:
        signals.append(_signal(
            "flag_overrides_signature",
            -2,
            "既有验签又有本地标志位：授权结论最终落在本地标志上，"
            "改标志即可绕过验签结果（改的是判定，不是签名）",
        ))
    return signals


def _probe_signals(status: int | None, content_type: str, body: bytes) -> list[dict]:
    if status in (401, 403):
        return [_signal(
            "probe_auth_required",
            2,
            f"HTTP {status}：接口需要鉴权，结果由服务端把关，客户端不能单方面决定",
        )]

    text = body.decode("utf-8", "replace")
    parsed = None
    try:
        parsed = json.loads(text)
    except (ValueError, UnicodeDecodeError):
        parsed = None
    is_json = "json" in (content_type or "").lower() or parsed is not None

    encrypted_hits = []
    if is_json:
        if _HASH_TRUE_RE.search(text):
            encrypted_hits.append('"hash": true')
        if '"encrypted"' in text:
            encrypted_hits.append('"encrypted" 字段')
        if _LONG_B64_RE.search(text):
            encrypted_hits.append("200+ 字符的 base64 块")
    if encrypted_hits:
        return [_signal(
            "probe_encrypted_envelope",
            3,
            "响应是 JSON 且像加密信封：命中 " + "、".join(encrypted_hits)
            + "；内容不是直接可读，服务端掌握明文",
        )]

    if isinstance(parsed, dict):
        list_keys = [key for key in ("items", "data") if isinstance(parsed.get(key), list)]
        if list_keys:
            return [_signal(
                "probe_plaintext_json",
                -2,
                "响应是明文 JSON，含 " + "/".join(list_keys)
                + " 列表：内容可直接读，客户端侧有操作空间（仍需确认权益字段是否服务端下发）",
            )]

    if is_json:
        return [_signal(
            "probe_json_no_verdict",
            0,
            "响应是 JSON，但既没有加密信封特征，也没有 items/data 列表，证据不足",
        )]
    return [_signal(
        "probe_non_json",
        0,
        f"响应 Content-Type={content_type or '未知'}，不是 JSON，未按接口语义加分",
    )]


def _safe_probe_signals(status: int | None, content_type: str, body: bytes) -> list[dict]:
    try:
        return _probe_signals(status, content_type, body)
    except Exception as exc:  # 解析异常也不能把 gate 拖崩
        return [_signal(
            "probe_parse_error",
            0,
            f"响应解析失败（{type(exc).__name__}: {exc}）：未加分，结论退回静态信号",
        )]


class _NoRedirect(urlrequest.HTTPRedirectHandler):
    """探测只发一次请求：3xx 交给 HTTPError 记录，不自动跟下去。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _probe(url: str, timeout: float) -> dict:
    result = {
        "url": url,
        "ok": False,
        "status": None,
        "content_type": "",
        "error": None,
        "bytes": 0,
        "note": "",
        "signals": [],
        "weight": 0,
    }
    try:
        request = urlrequest.Request(url, headers={"Accept": _PROBE_ACCEPT}, method="GET")
        opener = urlrequest.build_opener(_NoRedirect)
        with opener.open(request, timeout=timeout) as response:
            body = response.read(_PROBE_LIMIT)
            result.update(
                ok=200 <= int(getattr(response, "status", 0) or 0) < 300,
                status=getattr(response, "status", None),
                content_type=response.headers.get("Content-Type", ""),
                bytes=len(body),
            )
            result["signals"] = _safe_probe_signals(result["status"], result["content_type"], body)
            result["note"] = f"GET 成功，读入 {len(body)} 字节（上限 {_PROBE_LIMIT}）"
    except urlerror.HTTPError as exc:
        body = b""
        try:
            body = exc.read(_PROBE_LIMIT)
        except Exception:
            pass
        result.update(
            status=exc.code,
            content_type=(exc.headers.get("Content-Type", "") if exc.headers else ""),
            bytes=len(body),
            note=f"HTTP {exc.code}，按响应状态/响应体判断（不跟随 3xx）",
        )
        result["signals"] = _safe_probe_signals(exc.code, result["content_type"], body)
    except Exception as exc:  # 探测失败绝不能把整个 gate 拖崩
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["note"] = "请求没发出去或没收到响应，未加分；只探这一次，不重试"
        result["signals"] = [_signal(
            "probe_unreachable",
            0,
            f"探测失败（{result['error']}）：未加分，结论退回静态信号",
        )]
    result["weight"] = sum(item["weight"] for item in result["signals"])
    return result


def _next_steps(verdict: str) -> list[str]:
    if verdict == "server_authoritative":
        return [
            "先用 --probe（gate(path, probe_url=...)）确认真实接口是不是加密信封/带签请求，别只信静态字符串",
            "定位服务端权威字段（权益/清晰度/播放地址/订单状态）的客户端解析点；改本地只改展示，不改结果",
            "不要先改 isVip/付费墙/授权标志位；先对比有权益与无权益账号的响应差异，再决定改哪里",
            "检查证书绑定、请求签名、设备指纹：这些决定补丁能否重放，必要时先做流量层分析",
        ]
    if verdict == "client_patchable":
        return [
            "先确认关键逻辑确实随包下发：Flutter 看 libapp.so 的 AOT 快照，RN 看 index.android.bundle，Unity 看 assets/bin/Data",
            "找付费墙/会员模型字段的解析点，先定位字段再改判断；保留原包和 patch diff，方便回滚",
            "用 --probe 验一次接口：若播放地址/权益仍由服务端下发，客户端补丁只能改 UI",
            "改完做回归：登录、购买、播放三条主链路都要走一遍，确认没有本地完整性校验触发",
        ]
    return [
        "先 --probe 看接口是不是加密信封；一个 URL 不够就补登录/播放/详情三类请求",
        "对 APK 跑现有 apk 分析看加固与框架；有壳时先脱壳，再谈改哪里",
        "找付费墙模型字段的解析点，并确认权益/播放地址是否服务端下发",
        "证据不足时不要承诺可改；先补抓包、运行时日志和调用栈，再下结论",
    ]


def gate(path: Path, probe_url: str | None = None, timeout: float = 8.0) -> dict:
    """静态给判定；probe_url 非空时只发一次 GET。

    返回 key 固定为 verdict/confidence/target/signals/probe/next_steps。
    signals 的 weight 正=偏服务端、负=偏客户端，score 可由 weights 复算。
    """
    path = Path(path)
    size = path.stat().st_size
    kind = _kind(path)

    if kind == "apk":
        signals = _apk_signals(path)
    elif kind in ("pe", "elf"):
        signals = _binary_signals(path)
    else:
        signals = []

    probe = None
    if probe_url:
        probe = _probe(probe_url, timeout)
        signals.extend(probe["signals"])

    score = sum(item["weight"] for item in signals)
    if score >= 3:
        verdict = "server_authoritative"
    elif score <= -2:
        verdict = "client_patchable"
    else:
        verdict = "inconclusive"

    magnitude = abs(score)
    if magnitude >= 6:
        confidence = "high"
    elif magnitude >= 3:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "verdict": verdict,
        "confidence": confidence,
        "target": {"kind": kind, "path": str(path), "size": size},
        "signals": signals,
        "probe": probe,
        "next_steps": _next_steps(verdict),
    }
