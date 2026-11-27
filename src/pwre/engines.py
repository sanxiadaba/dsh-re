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
    }.get(name)


# 可选工具：缺了不影响 doctor 通过，但相关命令会明确告诉你缺什么。
OPTIONAL = {
    "upx": "UPX 脱壳（re unpack 对 UPX 壳的 PE 直接调用它）",
    "apktool": "APK 反编译/回编译（re apk unpack 用，需要 java）",
    "jadx": "dex → Java 源码（re apk java 用）",
    "buildtools": "APK 重签（apksigner/zipalign，re repack --sign 用）",
}


def tools_dir() -> Path:
    path = data_dir() / "tools"
    path.mkdir(parents=True, exist_ok=True)
    return path


def upx_path() -> str | None:
    for candidate in (tools_dir() / "upx" / _exe("upx"), tools_dir() / "upx" / "upx.exe"):
        if candidate.is_file():
            return str(candidate)
    return _which("upx")


def apktool_path() -> str | None:
    jar = tools_dir() / "apktool" / "apktool.jar"
    if jar.is_file():
        return str(jar)
    return _which("apktool")


def jadx_path() -> str | None:
    base = tools_dir() / "jadx"
    for candidate in (base / "bin" / "jadx.bat", base / "bin" / "jadx", tools_dir() / "jadx" / "jadx.bat"):
        if candidate.is_file():
            return str(candidate)
    return _which("jadx")


def buildtools_path() -> str | None:
    """apksigner 的位置：engines/buildtools → 本机 build-tools → PATH。

    repack 自己也会探测 ANDROID_HOME，这里只负责 doctor 展示与 re setup。
    """
    base = engines_dir() / "buildtools"
    for name in ("apksigner.bat", "apksigner.exe", "apksigner"):
        candidate = base / name
        if candidate.is_file():
            return str(candidate)
    return _which("apksigner")


def optional_status() -> list[dict]:
    return [
        {"name": name, "path": globals()[f"{name}_path"](), "purpose": purpose}
        for name, purpose in OPTIONAL.items()
    ]


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
    try:
        with _opener().open(_request(api), timeout=60) as response:
            data = json.load(response)
    except Exception as exc:
        raise ReError(
            f"查 {repo} 的最新版本失败：{exc}",
            hint="GitHub API 限流时设 GITHUB_TOKEN；慢网设 HTTPS_PROXY；也可以手动下载后放进 engines 目录",
        )
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


def download(url: str, dest: Path, label: str, retries: int = 5) -> Path:
    """带 Range 续传与重试的下载，进度打到 stderr（--json 时 stdout 仍干净）。

    慢网/断流的现实：单连接 + 固定 30s 超时必然失败（现场实测过两次）。
    这里保留 .part，断开就用 Range 从断点继续；只有拿到完整字节数才算成功。
    """
    import time

    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_suffix(dest.suffix + ".part")
    print(f"下载 {label}：{url}", file=sys.stderr)
    total = 0
    for attempt in range(1, retries + 1):
        have = part.stat().st_size if part.is_file() else 0
        if total and have >= total:
            break
        headers = {"Range": f"bytes={have}-"} if have else {}
        request = _request(url)
        for key, value in headers.items():
            request.add_header(key, value)
        try:
            with _opener().open(request, timeout=120) as response:
                if response.status == 200 and have:
                    # 服务端不认 Range：从头来，别把旧字节接在后面
                    print("  服务端不支持续传，重新开始", file=sys.stderr)
                    have = 0
                declared = int(response.headers.get("Content-Length") or 0)
                if not total:
                    total = declared + have
                mode = "ab" if have else "wb"
                step = max(total // 20, 1 << 20) if total else 8 << 20
                next_mark = (have // step + 1) * step
                with open(part, mode) as fh:
                    while True:
                        chunk = response.read(1 << 20)
                        if not chunk:
                            break
                        fh.write(chunk)
                        have += len(chunk)
                        if have >= next_mark:
                            pct = f" {have * 100 // total}%" if total else ""
                            print(f"  {have / (1 << 20):.0f} MB{pct}", file=sys.stderr)
                            next_mark += step
            if total and part.stat().st_size >= total:
                break
            print(f"  只下到 {part.stat().st_size}/{total or '?'} 字节，重试 {attempt}/{retries}", file=sys.stderr)
        except Exception as exc:  # 网络、超时、SSL
            size = part.stat().st_size if part.is_file() else 0
            print(f"  第 {attempt} 次中断（{type(exc).__name__}: {exc}），已下 {size} 字节", file=sys.stderr)
            if attempt == retries:
                raise ReError(
                    f"下载 {label} 失败：{exc}",
                    hint=f"已保留 {part}，网络恢复后重跑同一条命令会从断点继续；慢网可设 HTTPS_PROXY",
                )
            time.sleep(min(2 * attempt, 8))
    size = part.stat().st_size if part.is_file() else 0
    if total and size < total:
        raise ReError(
            f"下载 {label} 不完整：{size}/{total} 字节",
            hint=f"保留的 {part} 会在下次运行续传",
        )
    part.replace(dest)
    print(f"  -> {dest}（{size / (1 << 20):.1f} MB）", file=sys.stderr)
    return dest


def _find_layout(root: Path) -> Path:
    """在解压结果里找"真正的那一层"：带 bin/rizin 或 support/analyzeHeadless 的目录。"""
    marks = (
        Path("bin") / "rizin.exe", Path("bin") / "rizin",
        Path("support") / "analyzeHeadless.bat", Path("support") / "analyzeHeadless",
    )
    for candidate in [root, *sorted(p for p in root.rglob("*") if p.is_dir())]:
        if any((candidate / mark).is_file() for mark in marks):
            return candidate
    entries = [e for e in root.iterdir() if e.name != "__MACOSX"]
    return entries[0] if len(entries) == 1 and entries[0].is_dir() else root


def _extract_zip(archive: Path, target: Path) -> None:
    """解压并提升到真正的那一层（不假定只有唯一顶层目录）。"""
    tmp = Path(tempfile.mkdtemp(prefix="re-extract-", dir=str(target.parent)))
    try:
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(tmp)
        source = _find_layout(tmp)
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
        [r"rizin-windows-static-v.*\.zip$", r"rizin-windows-shared64-v.*\.zip$", r"rizin-windows.*\.zip$"],
    )
    print(f"rizin {tag}", file=sys.stderr)
    path = _install_zip("rizin", url, "rizin")
    if not (path / "bin" / "rizin.exe").is_file():
        raise ReError(f"rizin 解压后没有 bin/rizin.exe：{path}", hint=f"看看目录里到底是什么：{_tree_sample(path)}")
    return path


def install_ghidra() -> Path:
    tag, url = github_asset("NationalSecurityAgency/ghidra", r"ghidra_.*_PUBLIC_.*\.zip$")
    print(f"ghidra {tag}（约 570 MB，慢慢下）", file=sys.stderr)
    path = _install_zip("ghidra", url, "ghidra")
    if not ghidra_headless():
        raise ReError(
            f"ghidra 解压后找不到 support/analyzeHeadless：{path}",
            hint=f"目录里是：{_tree_sample(path)}",
        )
    return path


def _tree_sample(path: Path, limit: int = 6) -> str:
    try:
        names = sorted(item.name for item in Path(path).iterdir())[:limit]
    except OSError:
        return "（读不到）"
    return ", ".join(names) or "（空）"


def ghidra_java_min() -> int:
    """Ghidra 自己声明的 JDK 最低版本；读不到就按 25（当前 Ghidra 12 的要求）。"""
    root = ghidra_headless()
    if not root:
        return 25
    base = Path(root).parent
    for candidate in (base.parent / "Ghidra" / "application.properties",
                      base / "Ghidra" / "application.properties"):
        try:
            for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("application.java.min="):
                    return int(line.split("=", 1)[1])
        except (OSError, ValueError):
            continue
    return 25


def java_version(java: str | None = None) -> int:
    """主版本号：JDK 8 的 "1.8.0_411" 归一到 8；拿不到返回 0。"""
    import re

    exe = java or java_path()
    if not exe:
        return 0
    try:
        result = subprocess.run([exe, "-version"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return 0
    text = (result.stderr or "") + (result.stdout or "")
    match = re.search(r'version "([0-9][0-9._]*)', text)
    if not match:
        return 0
    parts = re.split(r"[._]", match.group(1))
    try:
        major = int(parts[0])
    except (ValueError, IndexError):
        return 0
    if major == 1 and len(parts) > 1:
        try:
            return int(parts[1])
        except ValueError:
            return 0
    return major


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
            elif name == "buildtools":
                if buildtools_path():
                    print(f"buildtools 已就位：{buildtools_path()}", file=sys.stderr)
                else:
                    install_buildtools()
            else:
                raise ReError(f"不认识的引擎：{name}", hint="可用：rizin、ghidra、java、buildtools")
        except ReError as exc:
            failed += 1
            print(f"re: {exc.message}", file=sys.stderr)
            if exc.hint:
                print(f"    {exc.hint}", file=sys.stderr)
        except Exception as exc:  # 网络、解压、权限
            failed += 1
            print(f"re: 安装 {name} 失败：{exc}", file=sys.stderr)
    return 1 if failed else 0


BUILD_TOOLS_URL = "https://dl.google.com/android/repository/build-tools_r34-windows.zip"


def install_buildtools() -> Path:
    """下 Android build-tools（apksigner + zipalign）到 engines/buildtools。

    只装 re repack --sign 真正用到的两件工具；解压后把含 apksigner 的那一层
    整个搬到 engines/buildtools，repack 的探测路径就对得上。
    """
    import shutil
    import zipfile

    target = engines_dir() / "buildtools"
    if buildtools_path():
        return target
    archive = download(BUILD_TOOLS_URL, engines_dir() / "_buildtools.zip", "Android build-tools 34")
    staging = engines_dir() / "_buildtools_tmp"
    shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(archive) as bundle:
            bundle.extractall(staging)
        marker = next((p for p in staging.rglob("apksigner.bat")), None)
        if marker is None:
            marker = next((p for p in staging.rglob("apksigner")), None)
        if marker is None:
            raise ReError(
                "build-tools 包里没找到 apksigner",
                hint="换一个 build-tools 版本，或手工解压到 engines/buildtools",
            )
        target.mkdir(parents=True, exist_ok=True)
        for item in marker.parent.iterdir():
            destination = target / item.name
            if item.is_dir():
                shutil.copytree(item, destination, dirs_exist_ok=True)
            else:
                shutil.copy2(item, destination)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
        archive.unlink(missing_ok=True)
    return target


def status() -> list[dict]:
    rows = []
    for name, purpose in ENGINES.items():
        path = tool_path(name)
        note = ""
        ok = bool(path)
        if name == "java" and path:
            version = java_version(path)
            needed = ghidra_java_min() if ghidra_headless() else 0
            if needed and version < needed:
                ok = False
                note = f"版本过低：{version} < Ghidra 要求的 {needed}（re setup --java）"
            else:
                note = f"版本 {version}" if version else ""
        rows.append({"name": name, "path": path, "ok": ok, "purpose": purpose, "note": note})
    return rows


def _batch_wrapper(cmd: list) -> tuple[list, Path | None]:
    """把 .bat/.cmd 调用包进一个临时 .cmd。

    直接 CreateProcess 一个 .bat 时，参数由 cmd.exe 重新解析：路径里的空格、括号、
    & 会把命令行拆开（`...) was unexpected at this time`）。写一个参数已逐个加引号的
    包装器交给 cmd，解析就只剩一层。文件按系统 ANSI 代码页写，中文路径才不会乱码。
    """
    if os.name != "nt" or not str(cmd[0]).lower().endswith((".bat", ".cmd")):
        return list(cmd), None
    quoted = []
    for arg in cmd:
        text = str(arg).replace("%", "%%").replace('"', '""')
        quoted.append(f'"{text}"')
    handle, name = tempfile.mkstemp(prefix="re-run-", suffix=".cmd")
    os.close(handle)
    path = Path(name)
    body = "@echo off\r\n" + " ".join(quoted) + "\r\nexit /b %ERRORLEVEL%\r\n"
    encoding = "mbcs" if os.name == "nt" else "utf-8"
    try:
        path.write_bytes(body.encode(encoding))
    except UnicodeEncodeError:
        path.unlink(missing_ok=True)
        return list(cmd), None
    return ["cmd.exe", "/d", "/c", str(path)], path


def _kill_tree(proc) -> None:
    """连孙进程一起杀。

    analyzeHeadless.bat 会再拉起 java.exe：只 kill 直接子进程的话，孙进程还攥着
    管道，communicate() 会一直等到分析结束——超时就形同虚设。
    """
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                       capture_output=True, timeout=30)
    else:
        try:
            os.killpg(os.getpgid(proc.pid), 9)
        except OSError:
            proc.kill()


def run(cmd, timeout=120, cwd=None, env=None) -> subprocess.CompletedProcess:
    """统一的子进程调用：不让任何外部工具把 DSH 挂死（含超时后的进程树清理）。"""
    cmd, wrapper = _batch_wrapper(list(cmd))
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            cwd=cwd,
            env=env,
            text=True,
            errors="replace",
        )
    except OSError as exc:
        if wrapper is not None:
            wrapper.unlink(missing_ok=True)
        raise ReError(f"启动不了外部工具 {cmd[0]}：{exc}", hint="确认引擎还在（re doctor）")
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        try:
            proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        raise ReError(
            f"命令超时（{timeout}s）：{' '.join(map(str, cmd))}",
            hint="加大超时（--timeout）或缩小分析范围；进程树已强制结束",
        )
    finally:
        if wrapper is not None:
            wrapper.unlink(missing_ok=True)
    return subprocess.CompletedProcess(cmd, proc.returncode, out, err)

