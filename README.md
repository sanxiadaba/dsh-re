# dsh-re

给 DeepSeek Harness（DSH）用的逆向军刀：**一条命令看清一个已经编译/打包好的东西**——固件、PE/ELF、安装包、asar、APK、两版差异。

不是 GUI，不是 MCP server，就是命令行。DSH 用 bash / pwsh 直接抽刀，输出默认压到十几行，要全量才 `--json`。

## 它解决什么

逆向最烦的不是"不会"，是来回折腾：找工具、拼参数、输出太吵、结论没证据。

`re` 把常用刀片收进一个入口，并且守三条硬规矩：

- **不降级**：`re dis` 没有 rizin 就直接失败并给安装命令，不拿玩具凑数。
- **不猜**：认不出架构、找不到向量表、哈希不符，明确报错，不返回半成品。
- **不特例**：不认识项目名、不认识芯片型号，一切从文件内容推。

## 安装

```powershell
git clone https://github.com/sanxiadaba/dsh-re.git
cd dsh-re
python -m venv .venv
.\.venv\Scripts\pip install -e .
.\re.cmd doctor
.\re.cmd setup --rizin --ghidra     # 下载引擎到 %LOCALAPPDATA%\dsh-re\engines
```

引擎不进仓库、不进 PATH，卸载时删掉 `%LOCALAPPDATA%\dsh-re` 即可。

Linux / macOS 把 `.venv\Scripts` 换成 `.venv/bin`，用 `./re.sh`。

## 用

```powershell
re id firmware.hex
re fw firmware.hex                 # 向量表、Reset、中断、代码区
re dis firmware.hex --at 0x08000114 -n 16
re decompile firmware.hex --at 0x08000114

re id PowerWriter.exe
re pe PowerWriter.exe
re strings PowerWriter.exe -k path -l 20
re diff old.exe new.exe

re unpack app.asar -o app.unpacked
```

## 命令

| 命令 | 作用 |
|---|---|
| `id` | 格式、架构、编译器、壳、哈希 |
| `strings` | 字符串：偏移、编码、按类型过滤 |
| `pe` / `elf` | 节区、导入导出、资源、加固 |
| `hex` | Intel HEX / S-record：段表、校验、转 BIN |
| `fw` | Cortex-M 向量表、入口、中断 |
| `dis` / `funcs` / `xref` | 反汇编、函数表、交叉引用（rizin） |
| `decompile` | 反编译一个函数（Ghidra） |
| `diff` | 两版：字节段差异 + 结构差异 |
| `unpack` | zip / apk / jar / asar / tar / gz / xz / zst / cab / msi / PyInstaller |
| `doctor` / `setup` | 体检、装引擎 |

## 装成 DSH skill

仓库根目录就是 skill 目录（`SKILL.md` 在这里）。用 junction 指过来，本机不留副本：

```powershell
New-Item -ItemType Junction -Path "$env:USERPROFILE\.dsh\skills\re" -Target "D:\repo\z_code\Git\dsh-re"
```

## 数据目录

| 内容 | 位置 |
|---|---|
| 引擎（rizin、Ghidra、JDK） | `%LOCALAPPDATA%\dsh-re\engines`（可用 `DSH_RE_DATA` 覆盖） |
| 反编译临时工程 | 同上，跑完即删 |

## 许可

MIT。见 [LICENSE](LICENSE)。
