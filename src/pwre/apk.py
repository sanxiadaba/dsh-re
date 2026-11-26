"""APK 结构：壳、框架、权限、原生库、SDK 线索。

`re unpack` 只把 APK 当 zip 摊开，拿不到"这是什么 App、有没有壳、逻辑在哪"。
这个模块补的就是第一眼要看的结论：包名/版本、框架（Flutter/RN/Unity…）、
加固特征、原生库与资产清单、以及能对上的第三方 SDK。
"""

import zipfile
import zlib
from collections import Counter
from pathlib import Path

from . import axml
from .detect import entropy
from .errors import ReError
from .out import human_size

FRAMEWORKS = [
    ("Flutter", ("libflutter.so", "libapp.so", "assets/flutter_assets/")),
    ("React Native", ("libreactnativejni.so", "assets/index.android.bundle")),
    ("Unity", ("libunity.so", "assets/bin/Data/")),
    ("Cocos", ("libcocos2djs.so", "libcocos2d.so", "assets/src/cocos2d-jsb.js")),
    ("Xamarin", ("assemblies/", "libmonodroid.so")),
    ("Cordova", ("assets/www/cordova.js",)),
    ("Capacitor", ("assets/public/capacitor.config.json",)),
    ("Kotlin Multiplatform", ("libshared.so",)),
]

PACKERS = {
    "libjiagu.so": "360 加固",
    "libjiagu_art.so": "360 加固",
    "libjiagu_x86.so": "360 加固",
    "libsgmain.so": "阿里聚安全",
    "libsgsecuritybody.so": "阿里聚安全",
    "libshell.so": "腾讯乐固",
    "libshellx.so": "腾讯乐固",
    "libDexHelper.so": "梆梆加固",
    "libDexHelper-x86.so": "梆梆加固",
    "libnesec.so": "网易易盾",
    "libnsaferonly.so": "网易易盾",
    "libexec.so": "爱加密",
    "libexecmain.so": "爱加密",
    "libmobisec.so": "阿里加固",
    "libbaiduprotect.so": "百度加固",
    "libprotectClass.so": "盛大加固",
}

SDK_HINTS = [
    ("华为 Ads-Identifier（OAID）", "ads-identifier"),
    ("MSA OAID", "com.bun.miitmdid"),
    ("Google AdMob", "com.google.android.gms.ads"),
    ("穿山甲 Pangle", "com.bytedance.sdk.openadsdk"),
    ("腾讯优量汇 GDT", "com.qq.e"),
    ("快手广告", "com.kwad"),
    ("Sigmob", "com.sigmob"),
    ("Mintegral", "com.mbridge"),
    ("友盟统计", "com.umeng"),
    ("Bugly", "com.tencent.bugly"),
    ("极光推送", "cn.jpush"),
    ("支付宝支付", "com.alipay"),
    ("微信开放 SDK", "com.tencent.mm.opensdk"),
    ("MMKV 存储", "com.tencent.mmkv"),
    ("ffmpeg-kit", "com.arthenica.ffmpegkit"),
    ("InAppWebView", "com.pichillilorenzo.flutter_inappwebview"),
]

# 只扫这些样本，避免把 30MB 的 so 全读进内存
SCAN_LIMIT = 4 << 20


def _read_sample(zf: zipfile.ZipFile, name: str, limit: int = SCAN_LIMIT) -> bytes:
    with zf.open(name) as fh:
        return fh.read(limit)


def _framework(names: set[str]) -> tuple[str, str]:
    basenames = {Path(name).name for name in names}
    for label, marks in FRAMEWORKS:
        for mark in marks:
            if mark.endswith("/"):
                hit = mark if any(name.startswith(mark) for name in names) else None
            else:
                hit = mark if (mark in names or mark in basenames) else None
            if hit:
                return label, mark
    return "", ""


def _packer(names: set[str], manifest: dict, dex_sizes: list[int], total: int) -> str:
    libs = {Path(name).name for name in names if name.startswith("lib/")}
    for lib, label in PACKERS.items():
        if lib in libs:
            return label
    factory = str(manifest.get("app_component_factory") or "")
    # 标准 AndroidX 工厂是正常配置，不是壳
    if factory and "androidx.core.app.CoreComponentFactory" not in factory:
        return f"自定义壳（appComponentFactory={factory}）"
    if dex_sizes and max(dex_sizes) < 64 << 10 and total > 8 << 20:
        return f"疑似壳（classes.dex 只有 {human_size(max(dex_sizes))}，包却有 {human_size(total)}）"
    return ""


def analyze(path: Path) -> dict:
    path = Path(path)
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise ReError(f"{path.name} 读不了（{exc}）", hint="包可能截断或损坏；换个来源重下")
    with zf:
        infos = [info for info in zf.infolist() if not info.is_dir()]
        names = {info.filename for info in infos}
        sizes = {info.filename: info.file_size for info in infos}
        if "AndroidManifest.xml" not in names:
            raise ReError(f"{path.name} 里没有 AndroidManifest.xml，不是 APK")

        try:
            raw = _read_sample(zf, "AndroidManifest.xml", 8 << 20)
        except (zipfile.BadZipFile, OSError, RuntimeError, zlib.error) as exc:
            raise ReError(f"AndroidManifest.xml 读不出来：{exc}", hint="压缩数据损坏，可能是被改坏的包")
        manifest = axml.manifest_summary(axml.parse(raw))

        dex = sorted(
            ((name, sizes[name]) for name in names if name.startswith("classes") and name.endswith(".dex")),
            key=lambda item: item[0],
        )
        libs = {}
        for name in names:
            if name.startswith("lib/"):
                parts = name.split("/")
                if len(parts) >= 3:
                    libs.setdefault(parts[1], []).append(parts[2])

        assets = []
        for name in names:
            if name.startswith("assets/") and name.count("/") == 1:
                assets.append((name, sizes[name]))

        blobs = []
        for name in list(names):
            if not name.startswith("assets/") or name.endswith((".txt", ".json", ".xml", ".png", ".webp")):
                continue
            if sizes.get(name, 0) < 256 << 10:
                continue
            try:
                data = _read_sample(zf, name, 1 << 20)
            except (zipfile.BadZipFile, OSError, zlib.error):
                continue
            level = entropy(data)
            if level > 7.5:
                blobs.append({"name": name, "size": sizes[name], "entropy": round(level, 2)})
        blobs.sort(key=lambda item: -item["size"])

        sample = b""
        pick = [n for n in sorted(names) if n.startswith("classes") and n.endswith(".dex")][:1]
        app_so = next((n for n in sorted(names) if n.endswith("libapp.so")), None)
        for name in pick + ([app_so] if app_so else []):
            try:
                sample += _read_sample(zf, name, 4 << 20)
            except (zipfile.BadZipFile, OSError, RuntimeError, zlib.error):
                # 单个条目坏不该让整条命令崩：跳过它，结论仍然给
                continue

    text = sample.decode("latin-1", "replace")

    sdks = []
    for label, mark in SDK_HINTS:
        if mark in text or mark.replace(".", "/") in text:
            sdks.append(label)

    framework, mark = _framework(names)
    return {
        "path": str(path),
        "size": path.stat().st_size,
        "entries": len(infos),
        "manifest": manifest,
        "framework": framework,
        "framework_mark": mark,
        "packer": _packer(names, manifest, [size for _, size in dex], path.stat().st_size),
        "dex": [{"name": name, "size": size} for name, size in dex],
        "abis": {abi: sorted(files) for abi, files in libs.items()},
        "assets": sorted(assets, key=lambda item: -item[1])[:8],
        "blobs": blobs,
        "sdks": sdks,
    }


def report(path: Path) -> tuple[list[str], dict]:
    data = analyze(path)
    manifest = data["manifest"]
    lines = [f"文件     {path.name}  {human_size(data['size'])}  {data['entries']} 条目"]
    lines.append(
        f"包名     {manifest['package']}  版本 {manifest['version_name']} ({manifest['version_code']})  "
        f"minSdk {manifest['min_sdk']} / targetSdk {manifest['target_sdk']}"
    )
    if manifest.get("app_label"):
        lines.append(f"应用名   {manifest['app_label']}")
    if data["framework"]:
        lines.append(f"框架     {data['framework']}（{data['framework_mark']}）")
    if data["packer"]:
        lines.append(f"加固     {data['packer']}")
    perms = manifest["permissions"]
    if perms:
        lines.append(f"权限     {len(perms)} 个：{', '.join(perms[:8])}{' …' if len(perms) > 8 else ''}")
    comps = manifest["components"]
    if comps:
        lines.append("组件     " + " / ".join(f"{name} {count}" for name, count in sorted(comps.items())))
    dex = data["dex"]
    if dex:
        total = sum(item["size"] for item in dex)
        lines.append(f"dex      {len(dex)} 个，共 {human_size(total)}" + (
            f"（最大的 {dex[0]['name']} 只有 {human_size(dex[0]['size'])}，逻辑多半不在 Java 层）"
            if dex[0]["size"] < 128 << 10 else ""))
    for abi, files in data["abis"].items():
        lines.append(f"原生库   {abi}：{len(files)} 个 — {', '.join(files[:6])}{' …' if len(files) > 6 else ''}")
    if data["sdks"]:
        lines.append(f"SDK      {', '.join(data['sdks'])}")
    for blob in data["blobs"][:3]:
        lines.append(f"可疑资产 {blob['name']}  {human_size(blob['size'])}  熵 {blob['entropy']}（高熵：加密或压缩）")
    return lines, data
