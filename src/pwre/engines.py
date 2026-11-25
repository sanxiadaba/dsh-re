"""引擎：查找、下载、安装。

原则：能力优先。该有的引擎没有就硬报错，并给出确切的一条安装命令，
绝不悄悄换成弱一档的实现。
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from urllib.request import Request, build_opener, ProxyHandler

from .errors import ReError

APP = "dsh-re"
UA = "dsh-re/0.1 (+https://github.com/sanxiadaba/dsh-re)"

# 需要的引擎。按“缺了会退化成什么”排序，doctor 里原样展示。
ENGINES = {
    "rizin": "反汇编 / 函数识别 / 交叉引用（缺了 re dis、re funcs、re xref 不可用）",
    "ghidra": "反编译（缺了 re decompile 不可用）",
    "java": "Ghidra 需要 JDK（版本由 Ghidra 自己声明的最低版本决定）",
    "jadx": "APK / DEX 反编译（缺了 re unpack 的 dex 分支不可用）",
    "ilspycmd": ".NET 反编译",
    "frida": "运行时插桩与内存抓取",
}


def data_dir() -> Path:
    """引擎和缓存放这里，不进仓库，不进 PATH。"""
    env = os.environ.get("DSH_RE_DATA")
    if env:
        path = Path(env)
    elif os.name == "nt":
        path = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / APP
    elif sys.platform == "darwin":
        path = Path.home() / "Library" / "Application Support" / APP
    else:
        path = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / APP
    path.mkdir(parents=True, exist_ok=True)
    return path


def engines_dir() -> Path:
    path = data_dir() / "engines"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _which(name: str) -> str | None:
    found = shutil.which(name)
    return found


def _exe(name: str) -> str:
    return f"{name}.exe" if os.name == "nt" else name


def rizin_path() -> str | None:
    local = engines_dir() / "rizin" / "bin" / _exe("rizin")
    if local.is_file():
        return str(local)
    return _which("rizin")


def rz_bin_path() -> str | None:
    local = engines_dir() / "rizin" / "bin" / _exe("rz-bin")
    if local.is_file():
        return str(local)
    return _which("rz-bin")


def ghidra_headless() -> str | None:
    for child in sorted((engines_dir()).glob("ghidra*")):
        for candidate in (child / "support" / "analyzeHeadless.bat", child / "support" / "analyzeHeadless"):
            if candidate.is_file():
                return str(candidate)
    return _which("analyzeHeadless")


def java_path() -> str | None:
    local = engines_dir() / "jdk" / "bin" / _exe("java")
    if local.is_file():
        return str(local)
    return _which("java")


def tool_path(name: str) -> str | None:
    """已安装的外部工具。"""
    return {
        "rizin": rizin_path(),
        "ghidra": ghidra_headless(),
        "java": java_path(),
        "jadx": _which("jadx"),
        "ilspycmd": _which("ilspycmd"),
        "frida": _which("frida"),
    }.get(name)


def require(name: str) -> str:
    """拿不到就报错，不给降级方案。"""
    path = tool_path(name)
    if path:
        return path
    raise ReError(
        f"缺少引擎 {name}：{ENGINES[name]}",
        hint=f"运行 `re setup --{name}` 装上（会下载到 {engines_dir()}），装好后重跑本条命令",
    )


# ---------------------------------------------------------------- 下载


def _proxy_url() -> str | None:
    """环境变量优先，其次 Windows 注册表（DSH 进程常常拿不到最新的环境变量）。"""
    for key in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY"):
        value = os.environ.get(key)
        if value:
            return value
    if os.name == "nt":
        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment") as key:
                enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                if enabled:
                    server, _ = winreg.QueryValueEx(key, "ProxyServer")
                    if server:
                        return server if "://" in server else f"http://{server}"
        except OSError:
            pass
    return None


def _opener():
    proxy = _proxy_url()
    if proxy:
        return build_opener(ProxyHandler({"http": proxy, "https": proxy}))
    return build_opener()


def _request(url: str, accept: str | None = None) -> Request:
    headers = {"User-Agent": UA}
    if accept:
        headers["Accept"] = accept
    token = os.environ.get("GITHUB_TOKEN")
    if token and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {token}"
    return Request(url, headers=headers)


def github_asset(repo: str, pattern: str) -> tuple[str, str]:
    """返回 (tag, 下载地址)。只查 latest release。"""
    return github_asset_any(repo, [pattern])


def github_asset_any(repo: str, patterns: list[str]) -> tuple[str, str]:
    """按顺序试多个文件名模式，命中第一个就用。"""
    import re

    api = f"https://api.github.com/repos/{repo}/releases/latest"
    with _opener().open(_request(api), timeout=20) as response:
        data = json.load(response)
    tag = data.get("tag_name", "?")
    assets = data.get("assets", [])
    for pattern in patterns:
        regex = re.compile(pattern)
        for asset in assets:
            if regex.search(asset["name"]):
                return tag, asset["browser_download_url"]
    names = ", ".join(a["name"] for a in assets) or "无"
    raise ReError(
        f"{repo} 的 {tag} 里没有匹配 {' / '.join(patterns)} 的文件",
        hint=f"可用文件：{names}",
    )


def download(url: str, dest: Path, label: str) -> Path:
    """流式下载，进度打到 stderr（--json 时 stdout 仍干净）。"""
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_suffix(dest.suffix + ".part")
    print(f"下载 {label}：{url}", file=sys.stderr)
    with _opener().open(_request(url), timeout=30) as response:
        total = int(response.headers.get("Content-Length") or 0)
        done = 0
        step = max(total // 20, 1 << 20) if total else 8 << 20
        next_mark = step
        with open(part, "wb") as fh:
            while True:
                chunk = response.read(1 << 20)
                if not chunk:
                    break
                fh.write(chunk)
                done += len(chunk)
                if done >= next_mark:
                    pct = f" {done * 100 // total}%" if total else ""
                    print(f"  {done / (1 << 20):.0f} MB{pct}", file=sys.stderr)
                    next_mark += step
    part.replace(dest)
    print(f"  -> {dest}", file=sys.stderr)
    return dest


def _extract_zip(archive: Path, target: Path) -> None:
    """解压并把唯一的顶层目录提升到 target。"""
    tmp = Path(tempfile.mkdtemp(prefix="re-extract-", dir=str(target.parent)))
    try:
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(tmp)
        entries = [e for e in tmp.iterdir() if e.name not in ("__MACOSX",)]
        source = entries[0] if len(entries) == 1 and entries[0].is_dir() else tmp
        if target.exists():
            shutil.rmtree(target)
        if source == tmp:
            shutil.move(str(tmp), str(target))
            tmp = None
        else:
            shutil.move(str(source), str(target))
    finally:
        if tmp is not None and tmp.exists():
            shutil.rmtree(tmp, ignore_errors=True)


def _install_zip(name: str, url: str, label: str) -> Path:
    target = engines_dir() / name
    with tempfile.TemporaryDirectory(dir=str(data_dir())) as work:
        archive = download(url, Path(work) / f"{name}.zip", label)
        _extract_zip(archive, target)
    return target


def install_rizin() -> Path:
    tag, url = github_asset_any(
        "rizinorg/rizin",
        [r"rizin-windows-static-v.*\.zip$", r"rizin-windows-shared64-v.*\.zip$"],
    )
    print(f"rizin {tag}", file=sys.stderr)
    path = _install_zip("rizin", url, "rizin")
    if not (path / "bin" / "rizin.exe").is_file():
        raise ReError(f"rizin 解压后没有 bin/rizin.exe：{path}", hint="删掉该目录后重试")
    return path


def install_ghidra() -> Path:
    tag, url = github_asset("NationalSecurityAgency/ghidra", r"ghidra_.*_PUBLIC_.*\.zip$")
    print(f"ghidra {tag}（约 400 MB，慢慢下）", file=sys.stderr)
    return _install_zip("ghidra", url, "ghidra")


def ghidra_java_min() -> int:
    """Ghidra 自己声明的 JDK 最低版本；读不到就按 25（当前 Ghidra 12 的要求）。"""
    root = ghidra_headless()
    if not root:
        return 25
    props = Path(root).parent / "Ghidra" / "application.properties"
    try:
        for line in props.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("application.java.min="):
                return int(line.split("=", 1)[1])
    except (OSError, ValueError):
        pass
    return 25


def java_version(java: str | None = None) -> int:
    """主版本号；拿不到返回 0。"""
    exe = java or java_path()
    if not exe:
        return 0
    try:
        result = subprocess.run([exe, "-version"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return 0
    text = (result.stderr or "") + (result.stdout or "")
    for token in text.replace('"', " ").split():
        if token[:1].isdigit() and "." in token:
            try:
                return int(token.split(".")[0])
            except ValueError:
                continue
    return 0


def install_java(version: int | None = None) -> Path:
    version = version or ghidra_java_min()
    platform = "windows/x64" if os.name == "nt" else "linux/x64"
    url = f"https://api.adoptium.net/v3/binary/latest/{version}/ga/{platform}/jdk/hotspot/normal/eclipse"
    return _install_zip("jdk", url, f"Temurin JDK {version}")


def setup(names) -> int:
    failed = 0
    for name in names:
        try:
            if name == "rizin":
                if rizin_path():
                    print(f"rizin 已就位：{rizin_path()}", file=sys.stderr)
                else:
                    install_rizin()
            elif name == "ghidra":
                if ghidra_headless():
                    print(f"ghidra 已就位：{ghidra_headless()}", file=sys.stderr)
                else:
                    install_ghidra()
                needed = ghidra_java_min()
                if java_version() < needed:
                    print(f"Ghidra 要 JDK {needed}，当前 {java_version() or '无'}", file=sys.stderr)
                    install_java(needed)
            elif name == "java":
                install_java()
            else:
                raise ReError(f"不认识的引擎：{name}", hint="可用：rizin、ghidra、java")
        except ReError as exc:
            failed += 1
            print(f"re: {exc.message}", file=sys.stderr)
            if exc.hint:
                print(f"    {exc.hint}", file=sys.stderr)
        except Exception as exc:  # 网络、解压、权限
            failed += 1
            print(f"re: 安装 {name} 失败：{exc}", file=sys.stderr)
    return 1 if failed else 0


def status() -> list[dict]:
    rows = []
    for name, purpose in ENGINES.items():
        path = tool_path(name)
        rows.append({"name": name, "path": path, "ok": bool(path), "purpose": purpose})
    return rows


def run(cmd, timeout=120, cwd=None, env=None) -> subprocess.CompletedProcess:
    """统一的子进程调用：不让任何外部工具把 DSH 挂死。"""
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
            errors="replace",
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        raise ReError(f"命令超时（{timeout}s）：{' '.join(map(str, cmd))}", hint="加大超时或缩小分析范围")
