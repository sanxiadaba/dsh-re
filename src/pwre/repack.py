"""APK 重打包链：重写 zip → 对齐 → 重签 → 校验。

`repack()` 只管 zip 层；`sign()` / `verify()` / `gen_key()` 把 Android
build-tools 的 apksigner 和 JDK 的 keytool 串起来。四个入口都是纯函数，
不碰 argparse；CLI 接线（`re repack` / `re sign` / `re verify`）留给 cli.py。

对齐的判定对象是**条目数据区**：`ZipInfo.header_offset` 是 local header 的
起点，数据起点还要加上 30 字节固定头、文件名和 extra 字段。zipalign 保证的
是后者按 4 字节（`-p` 时 .so 按 4096）对齐，所以校验不能直接拿
`header_offset % 4` 当结论。
"""

import os
import re
import shutil
import struct
import tempfile
import zipfile
import zlib
from pathlib import Path

from . import engines
from .errors import ReError

_APKSIGNER_NAMES = ("apksigner.bat", "apksigner.exe", "apksigner.cmd", "apksigner")
_ZIPALIGN_NAMES = ("zipalign.exe", "zipalign.bat", "zipalign.cmd", "zipalign")
_APKSIGNER_HINT = "装 Android build-tools，或把 build-tools 放进 PATH"
_KEYTOOL_HINT = "装 JDK（keytool 在 JDK 的 bin 里），或把包含 keytool 的目录放进 PATH"


# ---------------------------------------------------------------- 工具探测


def _version_key(text: str) -> tuple[int, ...]:
    """把 `34.0.0`、`build-tools_34.0.0` 之类的名字变成可比较的数字串。"""
    match = re.search(r"\d+(?:\.\d+)*", text)
    if not match:
        return ()
    return tuple(int(part) for part in match.group(0).split("."))


def _pick_direct(base: Path, names: tuple[str, ...]) -> Path | None:
    for name in names:
        candidate = base / name
        if candidate.is_file():
            return candidate
    return None


def _pick_versioned(base: Path, names: tuple[str, ...], best=None) -> tuple | None:
    """在 `build-tools/<版本>/` 这类目录里取版本号最大的一个。"""
    best_key, best_path = best if best else (None, None)
    try:
        children = list(base.iterdir())
    except OSError:
        return best if best else None
    for child in children:
        if not child.is_dir():
            continue
        for name in names:
            candidate = child / name
            if not candidate.is_file():
                continue
            key = _version_key(child.name)
            if best_path is None or key > best_key:
                best_key, best_path = key, candidate
            break
    return (best_key, best_path) if best_path else None


def _sdk_roots():
    """ANDROID_HOME / ANDROID_SDK_ROOT，去重后按环境变量顺序给出。"""
    seen = set()
    for key in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        raw = os.environ.get(key)
        if not raw:
            continue
        path = Path(raw)
        marker = str(path).lower()
        if marker in seen:
            continue
        seen.add(marker)
        yield path


def _which_any(names: tuple[str, ...]) -> Path | None:
    for name in names:
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


def apksigner_path() -> Path | None:
    """按 engines → ANDROID_HOME/ANDROID_SDK_ROOT → PATH 的顺序找 apksigner。"""
    try:
        base = engines.engines_dir() / "buildtools"
    except OSError:
        base = None
    if base is not None and base.is_dir():
        found = _pick_direct(base, _APKSIGNER_NAMES)
        if found is None:
            picked = _pick_versioned(base, _APKSIGNER_NAMES)
            found = picked[1] if picked else None
        if found is not None:
            return found

    best = None
    for root in _sdk_roots():
        build_tools = root / "build-tools"
        if not build_tools.is_dir():
            continue
        best = _pick_versioned(build_tools, _APKSIGNER_NAMES, best)
    if best is not None:
        return best[1]

    return _which_any(_APKSIGNER_NAMES)


def zipalign_path() -> Path | None:
    """和 apksigner 同样的探测链，外加 apksigner 的同目录兄弟。"""
    try:
        base = engines.engines_dir() / "buildtools"
    except OSError:
        base = None
    if base is not None and base.is_dir():
        found = _pick_direct(base, _ZIPALIGN_NAMES)
        if found is None:
            picked = _pick_versioned(base, _ZIPALIGN_NAMES)
            found = picked[1] if picked else None
        if found is not None:
            return found

    best = None
    for root in _sdk_roots():
        build_tools = root / "build-tools"
        if not build_tools.is_dir():
            continue
        best = _pick_versioned(build_tools, _ZIPALIGN_NAMES, best)
    if best is not None:
        return best[1]

    apksigner = apksigner_path()
    if apksigner is not None:
        found = _pick_direct(apksigner.parent, _ZIPALIGN_NAMES)
        if found is not None:
            return found

    return _which_any(_ZIPALIGN_NAMES)


def _java_homes() -> list[Path]:
    """按优先级列出可能的 JDK/JRE 根目录。"""
    homes = []
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        homes.append(Path(java_home))
    java = shutil.which("java")
    if java:
        homes.append(Path(java).resolve().parent.parent)

    candidates = [Path(r"C:\Program Files\Java"), Path(r"C:\Program Files (x86)\Java")]
    local = os.environ.get("LOCALAPPDATA")
    if local:
        candidates.append(Path(local) / "Programs" / "Java")
    candidates += [
        Path(r"C:\Program Files\Android\Android Studio\jbr"),
        Path(r"C:\Program Files\Android\Android Studio\jre"),
    ]
    if local:
        candidates += [
            Path(local) / "Programs" / "Android Studio" / "jbr",
            Path(local) / "Programs" / "Android Studio" / "jre",
        ]
    for base in candidates:
        if base.name.lower() in ("jbr", "jre") and base.is_dir():
            homes.append(base)
            continue
        if not base.is_dir():
            continue
        try:
            homes.extend(child for child in base.iterdir() if child.is_dir())
        except OSError:
            continue

    seen = set()
    unique = []
    for home in homes:
        marker = str(home).lower()
        if marker in seen:
            continue
        seen.add(marker)
        unique.append(home)
    return unique


def _keytool_path() -> Path | None:
    """keytool 常常不在 PATH（只装了 JRE），所以再找 JAVA_HOME 和 Java 安装目录。"""
    exe = "keytool.exe" if os.name == "nt" else "keytool"
    found = shutil.which("keytool")
    if found:
        return Path(found)
    for home in _java_homes():
        candidate = home / "bin" / exe
        if candidate.is_file():
            return candidate
    return None


def _java_path() -> Path | None:
    exe = "java.exe" if os.name == "nt" else "java"
    for home in _java_homes():
        candidate = home / "bin" / exe
        if candidate.is_file():
            return candidate
    return None


def _apksigner_jar(tool: Path) -> Path | None:
    for candidate in (
        tool.parent / "lib" / "apksigner.jar",
        tool.parent / "apksigner.jar",
        tool.parent.parent / "framework" / "apksigner.jar",
    ):
        if candidate.is_file():
            return candidate
    return None


def _apksigner_command(tool: Path, args: list[str]) -> list[str]:
    """优先绕过 .bat 直接调 apksigner.jar。

    apksigner.bat 用 `%1` + `call` 转发参数，口令里的 " % ^ 会被 cmd.exe
    再解释一次（实测会变成 "Missing input APK" 或口令错误）。jar 由
    CreateProcess 直接拉 java，argv 原样传递，list 参数才真正安全。
    """
    if os.name == "nt" and tool.suffix.lower() in (".bat", ".cmd"):
        jar = _apksigner_jar(tool)
        java = _java_path()
        if jar is not None and java is not None:
            return [str(java), "-jar", str(jar), *args]
    return [str(tool), *args]


def _run(cmd: list[str], timeout: int = 300):
    """list 形式 argv 交给 engines.run：.bat 的参数由它安全包一层。"""
    try:
        return engines.run(cmd, timeout=timeout)
    except ReError:
        raise
    except OSError as exc:
        raise ReError(
            f"启动外部工具失败：{cmd[0]}（{exc}）",
            hint="确认工具还在 build-tools / PATH 里，并且有执行权限",
        )


def _quiet_unlink(path: Path) -> None:
    """清理临时文件；清理失败不能盖住真正的错误。"""
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _redact(text: str, secrets: tuple[str, ...]) -> str:
    """错误信息里可能带整条 argv（engines.run 超时会这么做），先抹掉口令。"""
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***")
    return text


# ---------------------------------------------------------------- 重打包


def _replacement_map(root: Path | None) -> dict[str, Path]:
    if root is None:
        return {}
    root = Path(root)
    if not root.is_dir():
        raise ReError(f"replace_dir 不是目录：{root}", hint="传解包后的目录，内部按相对路径匹配包内条目")
    mapping = {}
    try:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                mapping[path.relative_to(root).as_posix()] = path
    except OSError as exc:
        raise ReError(
            f"遍历 replace_dir 失败：{root}（{exc}）",
            hint="检查目录权限；损坏的符号链接也可能让遍历中断",
        )
    return mapping


def _clone_info(info: zipfile.ZipInfo, extra: bytes = b"") -> zipfile.ZipInfo:
    """复制条目元数据；压缩方式与外部属性必须原样保留。"""
    cloned = zipfile.ZipInfo(filename=info.filename, date_time=info.date_time)
    cloned.compress_type = info.compress_type
    cloned.external_attr = info.external_attr
    cloned.internal_attr = info.internal_attr
    cloned.create_system = info.create_system
    cloned.create_version = info.create_version
    cloned.extract_version = info.extract_version
    cloned.reserved = info.reserved
    cloned.comment = info.comment
    cloned.extra = extra
    return cloned


def _read_entry(zf: zipfile.ZipFile, info: zipfile.ZipInfo, replacement: Path | None) -> bytes:
    source = str(replacement) if replacement is not None else info.filename
    try:
        if replacement is not None:
            return replacement.read_bytes()
        return zf.read(info)
    except (zipfile.BadZipFile, zlib.error) as exc:
        raise ReError(
            f"{info.filename} 读不出来（{exc}）",
            hint="CRC 错说明条目损坏或包被截断；重新下载/解包后再改",
        )
    except (RuntimeError, NotImplementedError) as exc:
        raise ReError(
            f"{info.filename} 用了不支持的压缩/加密方式（{exc}）",
            hint="加密的 APK 要先解密；不认识的压缩方式用 7z 重新打包",
        )
    except OSError as exc:
        raise ReError(f"读不了 {source}（{exc}）", hint="检查文件是否存在、是否有读权限")


def _entry_data_offsets(path: Path) -> list[tuple[zipfile.ZipInfo, int]]:
    """从 local header 算出每个条目的数据起点（不是 header_offset）。"""
    out = []
    with zipfile.ZipFile(path) as zf, open(path, "rb") as fh:
        for info in zf.infolist():
            if info.is_dir():
                continue
            fh.seek(info.header_offset)
            head = fh.read(30)
            if len(head) != 30 or head[:4] != b"PK\x03\x04":
                raise ReError(
                    f"{path.name} 的 local header 坏了：{info.filename}",
                    hint="zip 结构不完整；用 zipalign 或重新打包后再试",
                )
            name_len, extra_len = struct.unpack("<HH", head[26:30])
            out.append((info, info.header_offset + 30 + name_len + extra_len))
    return out


def _checked_zip(path: Path, hint: str) -> zipfile.ZipFile:
    try:
        return zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise ReError(f"{path.name} 不是有效的 zip/APK：{exc}", hint=hint)
    except OSError as exc:
        raise ReError(f"打不开 {path}（{exc}）", hint="检查路径、权限和文件是否被占用")


def _expected_names(zf: zipfile.ZipFile) -> tuple[list[zipfile.ZipInfo], list[str]]:
    seen = set()
    entries = []
    duplicates = []
    for info in zf.infolist():
        if info.filename in seen:
            duplicates.append(info.filename)
            continue
        seen.add(info.filename)
        entries.append(info)
    return entries, duplicates


def repack(src: Path, dst: Path, replace_dir: Path | None = None, align: bool = True) -> dict:
    """把 src 重写成 dst，按相对路径替换条目，并把未压缩条目对齐。

    返回里 `alignment` 说明对齐方式：`zipalign`（调外部工具）、`builtin`
    （纯 Python 重写）、`none`（align=False）。`unmatched` 列出 replace_dir
    里没被包内条目命中的文件——不因此失败，但要让人看见。
    """
    src = Path(src)
    dst = Path(dst)
    if not src.is_file():
        raise ReError(f"源 APK 不存在：{src}", hint="确认路径；可以先用 re apk 看看它是不是 APK")
    try:
        if src.resolve() == dst.resolve():
            raise ReError("src 和 dst 是同一个文件", hint="重打包要写到新路径，避免读一半把源包截断")
    except OSError:
        pass
    if dst.exists() and dst.is_dir():
        raise ReError(f"dst 是目录：{dst}", hint="dst 必须是文件路径，例如 out.apk")

    replacements = _replacement_map(replace_dir)
    try:
        dst.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ReError(f"建不了输出目录 {dst.parent}（{exc}）", hint="换一个有写权限的输出路径")

    zipalign = zipalign_path() if align else None
    builtin_align = bool(align and zipalign is None)

    try:
        handle, temp_name = tempfile.mkstemp(
            prefix=f".{dst.stem}.repack-", suffix=".apk", dir=str(dst.parent)
        )
        os.close(handle)
    except OSError as exc:
        raise ReError(f"建不了临时文件（{exc}）", hint="检查输出目录的写权限和磁盘空间")
    built = Path(temp_name)

    source = None
    expected = []
    duplicates = []
    replaced = []
    unmatched = []
    try:
        source = _checked_zip(src, "包可能截断或损坏；换个来源重下")
        entries, duplicates = _expected_names(source)
        expected = [info.filename for info in entries]
        unmatched = sorted(set(replacements) - set(expected))
        with zipfile.ZipFile(built, "w", allowZip64=True) as output:
            output.comment = source.comment
            for info in entries:
                replacement = replacements.get(info.filename)
                if replacement is not None:
                    replaced.append(info.filename)
                data = b"" if info.is_dir() else _read_entry(source, info, replacement)
                extra = b""
                if builtin_align and info.compress_type == zipfile.ZIP_STORED:
                    # writestr 会先 seek 回 start_dir；此时 tell() 就是 local header 起点。
                    position = output.fp.tell()
                    name_len = len(info.filename.encode("utf-8"))
                    pad = (-(position + 30 + name_len)) % 4
                    extra = b"\x00" * pad
                output.writestr(_clone_info(info, extra), data)
        source.close()
        source = None

        if zipalign is not None:
            result = _run(
                [str(zipalign), "-f", "-p", "4", str(built), str(dst)],
                timeout=300,
            )
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "").strip()
                raise ReError(
                    f"zipalign 失败（退出码 {result.returncode}）：{detail[-500:]}",
                    hint="确认 build-tools 完整；或去掉 --align 用内置对齐重跑",
                )
            alignment = "zipalign"
        else:
            try:
                os.replace(built, dst)
            except OSError as exc:
                raise ReError(
                    f"写不回 {dst}（{exc}）",
                    hint="目标可能被别的程序占用或只读；关掉它再重试",
                )
            alignment = "builtin" if builtin_align else "none"

        with _checked_zip(dst, "重打包产物读不回来，磁盘可能写满") as final:
            actual = [info.filename for info in final.infolist() if not info.is_dir()]
            stored = [
                (info.filename, offset)
                for info, offset in _entry_data_offsets(dst)
                if info.compress_type == zipfile.ZIP_STORED
            ]
        if actual != expected:
            missing_names = [name for name in expected if name not in set(actual)]
            extra_names = [name for name in actual if name not in set(expected)]
            raise ReError(
                f"重打包后条目对不上：期望 {len(expected)}，实际 {len(actual)}",
                hint=f"缺失 {missing_names[:5]}，多出 {extra_names[:5]}；输出可能被截断",
            )
        if align:
            bad = [name for name, offset in stored if offset % 4]
            if bad:
                raise ReError(
                    f"对齐失败：{', '.join(bad[:5])} 的数据区不是 4 字节对齐",
                    hint="用 build-tools 里的 zipalign -f -p 4 重跑，或把 build-tools 放进 PATH",
                )

        return {
            "src": str(src),
            "dst": str(dst),
            "entries": len(actual),
            "replaced": sorted(replaced),
            "unmatched": unmatched,
            "duplicates": duplicates,
            "alignment": alignment,
            "zipalign": str(zipalign) if zipalign is not None else None,
            "size": dst.stat().st_size,
        }
    except ReError:
        raise
    except (zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise ReError(f"重打包 {src.name} 失败：{exc}", hint="包结构坏了；先用 re unpack 验证能不能解开")
    except zlib.error as exc:
        raise ReError(f"压缩数据损坏：{exc}", hint="CRC/解压错说明包被改坏；换原始包重来")
    except (EOFError, NotImplementedError, RuntimeError) as exc:
        raise ReError(f"重打包 {src.name} 失败：{exc}", hint="包可能加密或用了不支持的压缩方式")
    except OSError as exc:
        raise ReError(f"重打包 {src.name} 时文件操作失败：{exc}", hint="检查读写权限、磁盘空间，以及目标是否被占用")
    finally:
        if source is not None:
            try:
                source.close()
            except OSError:
                pass
        _quiet_unlink(built)


# ---------------------------------------------------------------- 签名 / 密钥 / 校验


def _sign_argv(
    apk: Path,
    keystore: Path,
    ks_pass: str,
    key_alias: str,
    key_pass: str,
    v1: bool,
    v2: bool,
    v3: bool,
    out: Path,
) -> list[str]:
    """apksigner 的参数表；口令里的 &、"、% 原样留在单个 argv 元素里。"""
    return [
        "sign",
        "--ks", str(keystore),
        "--ks-pass", f"pass:{ks_pass}",
        "--ks-key-alias", key_alias,
        "--key-pass", f"pass:{key_pass}",
        "--v1-signing-enabled", "true" if v1 else "false",
        "--v2-signing-enabled", "true" if v2 else "false",
        "--v3-signing-enabled", "true" if v3 else "false",
        "--out", str(out),
        str(apk),
    ]


def sign(
    apk: Path,
    keystore: Path,
    ks_pass: str,
    key_alias: str,
    key_pass: str | None = None,
    v1: bool = True,
    v2: bool = True,
    v3: bool = True,
) -> dict:
    """apksigner 原地重签 apk（先写临时文件，成功后才替换）。"""
    apk = Path(apk)
    keystore = Path(keystore)
    tool = apksigner_path()
    if tool is None:
        raise ReError("找不到 apksigner", hint=_APKSIGNER_HINT)
    if not apk.is_file():
        raise ReError(f"APK 不存在：{apk}", hint="先 repack 出包，再签名")
    if not keystore.is_file():
        raise ReError(f"keystore 不存在：{keystore}", hint="先用 gen_key 生成，或指向已有的 .jks/.keystore")
    if not (v1 or v2 or v3):
        raise ReError("v1/v2/v3 至少要开一个", hint="全关会签出无法安装的包")

    effective_key_pass = ks_pass if key_pass is None else key_pass
    try:
        handle, temp_name = tempfile.mkstemp(
            prefix=f".{apk.stem}.signed-", suffix=apk.suffix or ".apk", dir=str(apk.parent)
        )
        os.close(handle)
    except OSError as exc:
        raise ReError(f"建不了签名临时文件（{exc}）", hint="检查 APK 所在目录的写权限")
    temp = Path(temp_name)
    _quiet_unlink(temp)  # 让 apksigner 自己创建 --out，避免它拒绝已存在文件

    cmd = _apksigner_command(
        tool, _sign_argv(apk, keystore, ks_pass, key_alias,
                         effective_key_pass, v1, v2, v3, temp)
    )
    secrets = (ks_pass, effective_key_pass)
    try:
        try:
            result = _run(cmd, timeout=300)
        except ReError as exc:
            raise ReError(_redact(str(exc), secrets), hint=exc.hint, code=exc.code) from None
        if result.returncode != 0:
            detail = _redact((result.stderr or result.stdout or "").strip(), secrets)
            raise ReError(
                f"apksigner 签名失败（退出码 {result.returncode}）：{detail[-500:]}",
                hint="看上面的报错：keystore 口令/alias 不对，或密钥类型不被支持",
            )
        if not temp.is_file() or temp.stat().st_size == 0:
            raise ReError(
                "apksigner 退出码 0，但没有写出签名包",
                hint="确认 build-tools 完整；也可手动运行 apksigner sign 看看输出",
            )
        try:
            os.replace(temp, apk)
        except OSError as exc:
            raise ReError(
                f"签名包替换不回 {apk.name}（{exc}）",
                hint="APK 可能被别的程序占用；关掉后重试",
            )
    finally:
        _quiet_unlink(temp)

    try:
        size = apk.stat().st_size
    except OSError as exc:
        raise ReError(f"签名成功但读不到 {apk.name}（{exc}）", hint="检查文件是否被占用或权限变化")
    return {
        "path": str(apk),
        "size": size,
        "v1": bool(v1),
        "v2": bool(v2),
        "v3": bool(v3),
        "apksigner": str(tool),
        "stdout": _redact((result.stdout or "").strip(), secrets),
        "stderr": _redact((result.stderr or "").strip(), secrets),
    }


def gen_key(
    keystore: Path,
    alias: str,
    ks_pass: str,
    dname: str = "CN=re, O=dsh-re, C=CN",
) -> dict:
    """keytool 生成 RSA 2048 签名密钥；不覆盖已存在的 keystore。"""
    keystore = Path(keystore)
    tool = _keytool_path()
    if tool is None:
        raise ReError("找不到 keytool", hint=_KEYTOOL_HINT)
    if keystore.exists():
        raise ReError(
            f"keystore 已存在：{keystore}",
            hint="gen_key 不覆盖已有密钥；换一个路径，或先手动备份/删除",
        )
    try:
        keystore.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ReError(f"建不了 keystore 目录（{exc}）", hint="换一个有写权限的路径")

    cmd = [
        str(tool),
        "-genkeypair",
        "-keystore", str(keystore),
        "-alias", alias,
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-validity", "10000",
        "-storepass", ks_pass,
        "-keypass", ks_pass,
        "-dname", dname,
    ]
    try:
        result = _run(cmd, timeout=120)
    except ReError as exc:
        _quiet_unlink(keystore)
        raise ReError(_redact(str(exc), (ks_pass,)), hint=exc.hint, code=exc.code) from None
    if result.returncode != 0:
        _quiet_unlink(keystore)
        detail = _redact((result.stderr or result.stdout or "").strip(), (ks_pass,))
        raise ReError(
            f"keytool 生成密钥失败（退出码 {result.returncode}）：{detail[-500:]}",
            hint="口令至少要 6 位；dname 里逗号后的空格和 C= 两项都要保留",
        )
    if not keystore.is_file():
        raise ReError(
            "keytool 退出码 0，但没有生成 keystore",
            hint="确认目标目录可写；也可手动运行 keytool -genkeypair 排查",
        )
    try:
        size = keystore.stat().st_size
    except OSError as exc:
        raise ReError(f"生成成功但读不到 keystore（{exc}）", hint="检查文件是否被占用或权限变化")
    return {
        "keystore": str(keystore),
        "alias": alias,
        "dname": dname,
        "size": size,
        "keytool": str(tool),
    }


def verify(apk: Path) -> dict:
    """apksigner verify --print-certs：返回是否通过、生效的签名方案和证书。"""
    apk = Path(apk)
    tool = apksigner_path()
    if tool is None:
        raise ReError("找不到 apksigner", hint=_APKSIGNER_HINT)
    if not apk.is_file():
        raise ReError(f"APK 不存在：{apk}", hint="确认路径；先 repack/签名再校验")

    # apksigner 0.9 只有加 --verbose 才打印各签名方案；--print-certs 仍然要带。
    cmd = _apksigner_command(tool, ["verify", "--verbose", "--print-certs", str(apk)])
    result = _run(cmd, timeout=120)
    text = result.stdout or ""
    if result.stderr:
        text = f"{text}\n{result.stderr}" if text else result.stderr

    schemes = []
    for match in re.finditer(
        r"Verified using\s+(v[\d.]+)\s+scheme[^:]*:\s*(true|false)", text, re.IGNORECASE
    ):
        if match.group(2).lower() == "true":
            schemes.append(match.group(1).lower())

    dn = ""
    sha256 = ""
    for line in text.splitlines():
        lowered = line.lower()
        if not dn and "certificate dn:" in lowered:
            dn = line.split(":", 1)[1].strip()
        if not sha256 and "certificate sha-256 digest:" in lowered:
            sha256 = line.split(":", 1)[1].strip()

    return {
        "ok": result.returncode == 0 and "does not verify" not in text.lower(),
        "schemes": schemes,
        "dn": dn,
        "sha256": sha256,
        "raw": text.strip(),
    }
