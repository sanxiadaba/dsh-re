# re

一条命令看清一个**已经编译/打包好的东西**：固件、PE/ELF、安装包、APK、两版差异；
需要动手时再连真硬件（J-Link/SWD、串口）。
DSH skill + 命令行，不依赖 GUI 或 MCP。

## 30 秒上手

需要 Python 3.11+。

```powershell
git clone https://github.com/sanxiadaba/dsh-re.git
cd dsh-re
python -m venv .venv
.\.venv\Scripts\pip install -e .        # pip 包名是 pwre，命令是 re
.\re.cmd doctor                          # 体检
.\re.cmd setup --rizin                   # 反汇编引擎，必需
```

然后第一条命令永远是它：

```powershell
.\re.cmd id 你的文件
```

Linux / macOS 把 `.venv\Scripts` 换成 `.venv/bin`，`.\\re.cmd` 换成 `./re.sh`。

## 调用方式

`pip install -e .` 只把 `re` 装进虚拟环境。两种用法：

- 不激活环境：`.\re.cmd id x.exe`（Windows）、`./re.sh id x`（Linux/macOS）
- 激活环境后：`.\.venv\Scripts\Activate.ps1`，然后直接 `re id x.exe`

## 常用命令

```powershell
.\re.cmd id      xxx.exe          # 是什么、什么架构、什么壳、产品名/版本
.\re.cmd strings xxx.exe -c 关键词   # 找 URL / 路径 / 密钥（ASCII/UTF-16/GBK）
.\re.cmd fw      firmware.hex     # 向量表、入口、中断、向量目标
.\re.cmd dis     firmware.hex --at 0x08000114 -n 20
.\re.cmd unpack  app.exe -o out   # 剥包；UPX 壳直接脱
.\re.cmd apk     app.apk          # 包名、框架、加固、原生库、SDK 线索
.\re.cmd chip    --compare firmware.hex   # 芯片里是不是这一版
.\re.cmd serial  -p COM11 --loopback      # 串口短接/接线自检
```

完整命令与参数见 [`SKILL.md`](SKILL.md) 和 [`references/commands.md`](references/commands.md)，
场景配方见 [`references/recipes.md`](references/recipes.md)。所有命令都支持 `--json`。

## 三条规矩

- **不降级**：`dis` 没有 rizin 就直接失败并给安装命令，不拿玩具凑数。
- **不猜**：认不出架构、找不到向量表、文本文件当二进制，都明确报错，不返回半成品。
- **不特例**：不认识项目名、不认识芯片型号，一切从文件内容推。

## 引擎与数据

`setup --rizin` 约 110 MB，`setup --ghidra` 约 570 MB（另外按需下 JDK，约 200 MB）。
下载支持断点续传与重试；网络慢可以设 `HTTPS_PROXY`。可选工具（`upx`/`apktool`/`jadx`）放进
`%LOCALAPPDATA%\dsh-re\tools`，`re doctor` 会显示有没有。

都装在 `%LOCALAPPDATA%\dsh-re`（`DSH_RE_DATA` 可改），不进仓库、不进 PATH，卸载删掉这个目录即可。

## 装成 DSH skill

```powershell
New-Item -ItemType Junction -Path "$env:USERPROFILE\.dsh\skills\re" -Target "<本仓库的绝对路径>"
```

## 排错

- 卡住先跑 `.\re.cmd doctor`，它会列出缺的引擎/可选工具，JDK 版本不够也会说。
- `decompile` 第一次慢是正常的（Ghidra 要导入并分析）。
- 加壳/加密文件被 `funcs`/`dis` 拒绝是预期行为：`re id` 会说是哪种壳，UPX 用 `re unpack` 脱，其它从内存 dump。
- `re: 还没建虚拟环境` / `依赖没装好`：按提示在仓库目录执行 `python -m venv .venv` 和 `.venv\Scripts\pip install -e .`。

## 相关项目

- [flash-algos](https://github.com/sanxiadaba/flash-algos)：1056 个 CMSIS-Pack 烧录算法（`.FLM`），
  用 `re elf` / `re funcs` 可以直接看里面的 `Init` / `ProgramPage`。

## 许可

MIT。
