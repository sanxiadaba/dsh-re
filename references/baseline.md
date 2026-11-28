# dsh-re 底稿（baseline）

> 唯一项目理解来源。工人只读：本文件 + 自己的任务书 + 本簇文件。
> 版本：`main` @ `8643985`，2026-11-28。基线测试：`121 passed, 13 subtests`（pytest 9.2.0）。

## 1. 是什么

`re` 是 DSH 技能 + Python CLI（包名 `pwre`）：看清已编译/打包产物（PE/ELF、HEX/SREC 固件、APK、安装包、两版差异），并连真硬件（J-Link/SWD、串口）。不依赖 GUI 或 MCP。

## 2. 入口

- Windows 真正入口：`.venv\Scripts\re.exe`（console script，`pip install -e .` 生成）。
- `re.cmd` 是转发脚本，**当前是 LF 行尾**（540 字节、CR=0）→ cmd.exe 解析碎，`cmd /c re.cmd --version` exit 2。这是 P0。
- `re` 不在 PATH。
- 无 venv / worktree 环境：`$env:PYTHONPATH='src'; & <主仓>\.venv\Scripts\python.exe -m pwre ...`。

## 3. 模块职责

| 模块 | 职责 |
|---|---|
| `cli.py` | argparse + 全部子命令实现；`--json` 前置重排；异常→退出码 |
| `detect.py` | magic 嗅探（PE/ELF/Mach-O/DEX/zip/asar/CAB/OLE/HEX/SREC/文本/压缩包…）；PE 壳判定 |
| `native.py` | `re pe` / `re elf` 结构报告 |
| `scan.py` | ASCII/UTF-16/GBK 字符串扫描 + 分类 |
| `diff.py` | 4 KB 块差异 + PE 结构差异 |
| `disasm.py` | rizin 唯一入口（pdj/aflj/axtj/aa/af） |
| `engines.py` | 引擎/工具定位、下载（断点续传）、JDK、统一 `run()`（超时+杀树） |
| `decompile.py` | Ghidra headless 单函数/全量 |
| `image.py` | 段表模型（合并/空洞/摊平，`MAX_FLAT=64MiB`） |
| `hexfile.py` | Intel HEX / S-record 解析 |
| `firmware.py` | 文件 → Image（裸 bin 需 `--base`） |
| `armvec.py` | Cortex-M 向量表 |
| `fwmap.py` | 固件结构分析（asm/函数/外设引用） |
| `proto.py` | 定长分帧 + 恒定位/变化位 |
| `serialport.py` | 串口列端口/监听/环回/收发（8N1 写死） |
| `chip.py` | J-Link SWD（Windows-only） |
| `mem.py` | Windows 进程/模块/内存读 |
| `apk.py` | APK 结构、框架、加固、SDK 线索（不解析 DEX/arsc） |
| `axml.py` | Android 二进制 XML 解析 |
| `repack.py` | APK 重写/对齐/重签/校验 |
| `patch.py` | PE/ELF 补丁计划（x86/x64） |
| `unpack.py` | zip/tar/gz/xz/bz2/zst/asar/cab/msi/7z/rar/PyInstaller/UPX |
| `gate.py` | 可改性打分 + HTTP 探测 |
| `out.py` / `errors.py` | 文本/JSON 输出；`ReError(message, hint, code)` |

## 4. 不变量（红线）

1. **不降级**：`dis/funcs/fwmap` 无 rizin 直接失败并给安装命令；`fwmap --partial` 是唯一显式降级，标 `degraded: true`。
2. **不猜**：认不出格式/架构/向量表/哈希不符，必须报错，不返回半成品。
3. **不特例**：不认识项目名、芯片型号；一切从文件内容推。
4. **补丁只走计划文件**：所有改动写 JSON 计划（可 diff、可重放）；执行后必须 `自检 通过`；改副本不改原件。
5. **重签必须验**：`re repack --sign` 后必须 `校验=通过`。
6. **输出**：默认紧凑文本（十几行）；`--json` 全量；地址十六进制带前缀，偏移是文件内偏移。
7. **错误与退出码**：`ReError(message, hint, code)`；0 成功 / 1 一般错误 / 2 用法或输入错误 / 3 依赖缺失（`references/commands.md:12`）。
8. **路径安全**：unpack/repack 防路径逃逸；2 GiB 炸弹上限。
9. **外部进程**：统一走 `engines.run()`（超时 + 杀进程树），不要裸 `subprocess.run`。
10. **平台**：Windows 一等公民；`mem`/`chip`/CAB/MSI/build-tools 是 Windows-only，别在别的平台假装支持。

## 5. 约定

- CLI：argparse；子命令在 `cli.py`；`--json` 由 `main()` 前置重排。
- 输出：`out.py` 的 `emit_text/emit_json/warn`；`--json` 统一走一个函数（本轮加 `schema: 1`）。
- 引擎：`engines.require(name)` / `rizin_path()` / `jadx_path()` / `apktool_path()`；缺就 `ReError(code=3)` 并给安装命令。
- 测试：`tests/` 用 pytest；样本现场构造，不放二进制；全量 `python -m pytest -q`。
- 数据：`%LOCALAPPDATA%\dsh-re`（`DSH_RE_DATA` 可改）；engines/ tools/ 不进仓库。
- 依赖：`pyproject.toml` 5 个运行时依赖（pefile/pyelftools/capstone/zstandard/pyserial）；pytest 是开发依赖，已装进 `.venv`。

## 6. 验收命令

```
# 全量（主仓根目录）
& .venv\Scripts\python.exe -m pytest -q          # 期望 121+ passed
# worktree（无 .venv）
$env:PYTHONPATH='src'; & C:\software\svn\z_code\Git\dsh-re\.venv\Scripts\python.exe -m pytest -q

# 入口（主仓）
cmd /c re.cmd --version                          # 当前 exit 2；R-00 后必须 0
# 体检
& .venv\Scripts\python.exe -m pwre doctor
# 门（R-00 后必须 exit 2）
& .venv\Scripts\python.exe -m pwre hex LICENSE --base 0x08000000
& .venv\Scripts\python.exe -m pwre proto LICENSE
```

## 7. 陷阱

- `re.cmd` 必须 CRLF；`.gitattributes` 的 `*.cmd text eol=crlf` 在 SVN 检出时不生效，必须实测字节。
- worktree 里没有 `.venv`；用 `PYTHONPATH=src` + 主 venv 的 python，**不要** `pip install -e .`。
- `cli.py` 是共享文件：W1 四簇不得改；每个新模块导出 `add_parser(subparsers)`，由 `cli.py` 懒加载。
- `engines.run()` 会 `.bat` 包装 + taskkill 杀树；不要绕过。
- `disasm.py` 的 rizin JSON 解析是 O(n²)（P13），本轮不动。
- `patch.py` 只 x86/x64（P10），本轮不动。
- `unpack` 的 msiexec `/a` 会执行安装器自定义动作（P14），本轮不动。
- 大文件：`path.read_bytes()` 整读（P11）；本轮只修 `id`/`apk` 的头读。
- 本机 `java` 是 JRE 8；Ghidra 必须用 `engines` 里的 JDK 25。
- 本机 AVD 全是 arm64 镜像 + GPU off + 1.5G + 临时 data（不可用）；`x86probe` 的 `image.sysdir` 还指向 arm64。

## 8. 红线区（改动需谨慎）

- `cli.py`：所有子命令入口；只允许 R-00 / R-05 改（R-04 只允许动 `apk` 段）。
- `engines.py`：下载/安装/进程封装；改动要做断点续传与超时回归。
- `repack.py` / `patch.py`：高风险，已有测试，非本簇任务不得改。
- `references/*.md`：文档跟随实现；改动要同步。

## 9. 本轮计划（地基 + APK 端到端）

- 默认环境：AVD API 35 `google_apis` `x86_64` + WHPX + `-gpu host` + 4G + 快照。
- 验收样本：`kiss.apk`（`fr.neamar.kiss`）+ `人才助手1.6.9.apk`（`com.talenthelper.refactor`）。
- 簇：R-00 入口/诚实性/CLI 骨架；R-01 设备层；R-02 插桩层；R-03 抓包层；R-04 APK 静态；R-05 证据+集成；V 独立复验。
- 不 push、不 svn commit；一簇一 commit。

## 10. 近期变更

- `8643985` test(patch): rel8 放宽与 verified_boundary 逃生门回归。
- 本轮开工：基线 pytest 121 passed；worktree 旧记录已 prune。
