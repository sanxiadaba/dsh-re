# 命令参考

只写参数与行为，套路在 `recipes.md`。文中 `re` 指 `re.cmd`（Windows）或 `re.sh`（Linux/macOS）；`--json` 放在子命令前后都行。

## 全局

| 参数 | 说明 |
|---|---|
| `--json` | 输出完整 JSON（默认是给人读的紧凑文本） |
| `--version` | 版本 |

退出码：`0` 成功；`1` 有结果但有问题（校验错、缺引擎、比对不一致等，原因已写进输出）；`2` 参数不对；`3` 工具内部错误。

## re id

```
re id 文件
```

识别格式（按内容，不看扩展名）、架构、位数、字节序、入口、编译器、**壳名**、版本信息（ProductName/FileVersion/CompanyName）、节、导入依赖、SHA256。
PE 会判断"原始数据为 0 的节 + 入口落在异常段 + 高熵"，并据此说出具体壳（UPX/ASPack/MPRESS/VMProtect/Themida…）和下一步命令。

## re strings

```
re strings 文件 [-n 4] [-m 0] [-k url] [-c 子串] [-r 正则] [-l 200] [--all] [-e gbk] [--no-utf16]
```

扫 ASCII、UTF-16LE/BE、**GBK**（中文 Windows 程序的主要编码），输出 `偏移 编码 文本`。
`-k` 的分类：url、path、email、ip、format、hex、pem。默认最多 200 条（`--all` 看全部），
`-e` 只扫指定编码。一条都没匹配时会说明本次扫了哪些编码，而不是干巴巴一句"没有"。

## re pe / re elf

```
re pe 文件
re elf 文件
```

PE：节表（rva、虚拟大小、文件大小、权限、熵）、按 DLL 分组的导入（纯序数显示成 `#12`）、导出、
资源类型（CURSOR/BITMAP/RCDATA/VERSION…）、VERSIONINFO、Authenticode 有无。
ELF：节表、DT_NEEDED、SONAME、RPATH/RUNPATH、动态符号数、NX/RELRO。

## re hex

```
re hex 文件 [--base 0x08000000] [--to bin --out x.bin] [--fill 0xFF] [--force]
```

Intel HEX / Motorola S-record：段表、范围、记录数、校验错误、空洞；可转成裸 BIN（空洞按 `--fill` 填，取值 0x00–0xFF）。
`起始` 是启动地址记录（HEX 类型 05 的线性地址，类型 03 按 CS:IP 计算），**不是**向量表里的 Reset。
映像有错误或为空时拒绝转 BIN；`--out` 已存在且没给 `--force` 也拒绝。
裸 BIN 需要 `--base`。

## re fw

```
re fw 文件 [--base 0x08000000] [--vectors]
```

Cortex-M 向量表：初始 SP、Reset、标准异常入口、IRQ 表。
判断规则只有三条：SP 在 SRAM 范围、Reset 带 Thumb 位、Reset 落在某个段里。
IRQ 枚举**不会**因为中间有 0 就停（PY32/STM32 常有保留槽）；输出会标出"多少个都指向同一个默认处理"，
以及真正独立的处理函数。`向量目标` 是向量指向的范围，不是代码总量。
`--vectors` 列出全部 Thumb 向量。

## re fwmap

```
re fwmap 文件 [-o 输出目录] [--base 0x08000000] [--force] [--partial]
```

一次产出：`image.bin`、`full.asm`（从第一个向量目标开始的线性反汇编，向量表标为头部）、
`functions.json`（rizin 函数表）、`analysis.json`（每函数指令数、调用图、外设地址命中）、`function-map.md`。

外设地址覆盖字面量池 `ldr rX,[pc,#imm]` 与 `movw/movt` 两种构造，结果带函数归属。
缺 rizin 时**直接失败**（不产出半成品）；确实只要线性反汇编就加 `--partial`，结果里 `degraded: true`。
输出目录非空要 `--force`。

## re funcs

```
re funcs 文件 [-l 40] [--arch arm] [--bits 16] [--deep] [--force] [--timeout 90] [--base ...]
```

- 固件：先用向量表当函数根（`af` 建在 `aa` 之前，否则会被整段函数吞掉），再 `aaaa` 深分析。
- 裸 BIN 加 `--base` 也能自己推架构、取向量种子，不必手填 `--arch/--bits`。
- PE/ELF：默认 `aa` 浅扫；`--deep` 才 `aaaa`。
- 文件疑似加壳时直接拒绝，`--force` 才硬跑。

## re dis

```
re dis 文件 [--at 0x08000114] [--sym 名字] [-n 20] [--arch arm] [--bits 16] [--base 0x08000000]
```

输出 `地址 字节 汇编`。不给 `--at`/`--sym` 时：固件从第一个向量目标开始，PE/ELF 从 rizin 认的入口开始。
`--sym` 会先在符号表里解析成地址再反汇编（符号名不拼进 rizin 命令）。

## re xref

```
re xref 文件 --at 0x0800161c [--deep] [--force] [--timeout 90]
```

谁引用了这个地址。

## re decompile

```
re decompile 文件 --at 0x08000114 [--sym 名字] [--base 0x08000000] [--timeout 300]
```

Ghidra headless 反编译一个函数。固件按向量表推处理器（Cortex-M → `ARM:LE:32:Cortex`）并用 BinaryLoader 按基址装载。
输入会先摊到干净路径再交给 Ghidra——路径里有空格/括号/中文也能跑（`analyzeHeadless.bat` 过 cmd 解析时会碎）。
第一次跑要导入+分析，慢；超时用 `--timeout` 调，超时会连孙进程一起杀掉。

## re decompile-all

```
re decompile-all 文件 -o all.c [--base ...] [--timeout 900]
```

一次导入分析，把所有函数反编译到一个 `.c`。结果先写到临时目录再复制到 `-o`，路径不干净也不影响 Ghidra。

## re diff

```
re diff A B
```

先按 4 KB 块给字节差异段与相同比例（块边界按两文件共同长度截断，追加的尾巴单独算），
再按格式给结构差异（PE：节的虚拟/文件大小与熵、导入新增/删除、导出增减、入口、时间戳）。

## re unpack

```
re unpack 文件 [-o 目录] [--force]
```

支持：zip/jar/apk/ooxml、tar、gzip/xz/bz2/zstd、asar（校验条目哈希）、cab（expand）、msi（msiexec 管理安装）、7z/rar（需要 7z.exe）、PyInstaller CArchive、**UPX 壳的 PE**（调 `upx.exe -d`）。
目标目录非空且没给 `--force` 会拒绝，避免覆盖。
NSIS/Inno 这类自解压 PE 不在支持内：装 7-Zip 后用 `7z x`。

## re apk

```
re apk 文件
```

不用 apktool 也能回答第一眼要看的：包名/版本/minSdk/targetSdk、应用名、权限、组件数量、
**框架**（Flutter / React Native / Unity / Cocos / Xamarin / Cordova / Capacitor）、
**加固特征**（appComponentFactory 自定义壳、或 libjiagu/libshell/libDexHelper 等已知壳）、
dex 数量与大小（判断逻辑是不是在 Java 层）、原生库清单、高熵可疑资产、第三方 SDK 线索（OAID/AdMob/穿山甲/优量汇/MMKV/ffmpeg…）。

## re chip

```
re chip --info   [--device PY32F030] [--speed 4000]
re chip --dump out.bin [--base 0x08000000] [--size 0x8000]
re chip --compare firmware.hex
re chip --flash firmware.hex --device PY32F030 --yes
```

J-Link + SWD 真硬件：

- `--info`：读 CPUID 与 flash 头 64 字节，打印 SP / Reset（不指定 `--device` 时按 Cortex-M0 连）。
- `--dump`：把 flash 读回成 bin。
- `--compare`：芯片 flash 与固件文件逐字节比对，给出不同字节数与前几处差异（退出码 1 表示不一致）。
- `--flash`：擦除 + 烧写 + 读回校验；会先擦整个 flash，必须 `--yes` 确认，且必须给 `--device`
  （J-Link 靠器件名选 flash 算法）。

没有 JLink.exe 时明确报错，不假装能跑。

## re serial

```
re serial --list
re serial -p COM11 -b 115200 --listen 3
re serial -p COM11 --loopback
re serial -p COM11 --send "text:hello" [--wait 1]
re serial -p COM11 --send "hex:01 03 00 00"
```

串口（需要 pyserial）：列端口、监听 N 秒、环回自检（发探针并校验回显，用来验证 PA2/PA3 这类短接和接线）、
按文本或十六进制发送并收回。

## re mem

```
re mem --list [--filter 名字]
re mem --pid 1234 --modules
re mem --pid 1234 --addr 0x401000 --size 0x1000 [-o dump.bin] [--force]
```

Windows（ReadProcessMemory）。用 `PROCESS_QUERY_LIMITED_INFORMATION` 读进程名，受保护进程也能列出来，
打不开的个数会单独报。dump 默认只显示前 512 字节，要全量用 `-o`；目标已存在要 `--force`。

## re proto

```
re proto 抓包.bin --frame 16 [--max 8]
```

按固定帧长切分，统计每个偏移的取值集合：恒定位压成区间、变化位压成区间，并打印前几帧的十六进制。
尾部不足一帧的字节会明说被忽略。目前只支持定长分帧（变长/带同步字的协议先自己切好）。

## re doctor / re setup

```
re doctor
re setup --rizin --ghidra     # 可以一次给多个；--all = java + rizin + ghidra
```

引擎装到 `%LOCALAPPDATA%\dsh-re\engines`（可用 `DSH_RE_DATA` 改），可选工具装到 `...\tools`（upx / apktool / jadx），
都不进仓库、不进 PATH。
`doctor` 会核对 JDK 版本与 Ghidra 要求（`application.java.min`），版本不够也计入"缺"。
`setup` 的下载支持断点续传与重试，慢网/断流会保留 `.part` 下次接着下。

## re patch

```
re patch --plan 补丁.json [--dry-run] [--json]
```

计划文件把改动写成数据，可 diff、可重放：

```json
{"file": "副本.exe",
 "ops": [
   {"kind": "patch", "va": "0x43f766", "bytes": "ba 6a 57 00 00", "note": "改立即数（VA 不是文件偏移）"},
   {"kind": "patch", "va": "0x14001ebe0", "bytes": "b801000000c3", "note": "按 VA 改"},
   {"kind": "add_section", "name": ".pwre", "file": "cave.bin", "characteristics": "0x60000020"},
   {"kind": "detour", "at": "0x475224", "section": ".pwre", "code": "b802000000c3", "note": "判定恒返回 2"}
 ]}
```

- 支持 PE / PE32+（add_section/detour）与 ELF（只支持 patch，按 offset/va 改字节，Android 的 .so 就走这条）。`offset` 与 `va` 二选一（都给按 offset），`va` 是**绝对地址**（ImageBase+RVA）。
- `add_section` 追加到文件尾，同步 `NumberOfSections` / `SizeOfImage` / 节表项；头部放不下第 n+1 个节表项会直接报错。
- `detour` 在 `at` 写 `E9 rel32`，把被覆盖的完整指令（用 capstone 找到 ≥5 字节边界）搬进洞，
  洞布局是 `code → 原始指令 → E9 回跳 at+N`，`at+5..at+N` 填 NOP。
- 全部改动先落内存、一次原子写回，然后重读逐条自检；`自检 通过` 才算完。
- `--dry-run` 只演算不落盘，`changes` 与真实执行逐条一致。
- 不支持：ARM64 跳板、RIP 相对指令的重定位、CheckSum/AuthentiCode（改了签名必然失效）。

## re repack

```
re repack in.apk -o out.apk [-r 替换目录] [--no-align] [--sign \
    --keystore x.jks --ks-pass pass:… --key-alias … [--key-pass …] | --gen-key x.jks …] [--json]
```

- `-r/--replace 目录`：按相对路径替换包内同名条目（`替换目录/lib/arm64-v8a/libapp.so` → `lib/arm64-v8a/libapp.so`）；
  没命中的替换文件会列出来，不静默丢弃。重名条目只写第一份。
- 对齐：有 `zipalign` 用 `zipalign -f -p 4`，没有就内置把未压缩条目按 4 字节对齐（不保证 `.so` 页对齐）。
- `--sign`：`apksigner` 探测顺序 engines/buildtools → `ANDROID_HOME`/`ANDROID_SDK_ROOT` 的 build-tools（取最高版本）→ `PATH`；
  找不到会直接报错并给安装命令（`re setup --buildtools`）。`--gen-key` 用 keytool 现场生成（不覆盖已有 keystore）。
- 口令里有 `"`、`%`、`&` 时，有 `lib/apksigner.jar` + java 会直接走 `java -jar`，绕过 `.bat` 的 cmd 转义。
- 重打包必然让 v1/v2/v3 摘要失效，所以"改包 + 不重签"没有意义。

## re gate

```
re gate 文件 [--probe https://…] [--timeout 8] [--json]
```

输出判定（`客户端可改` / `疑似服务端权威` / `证据不足`）、置信度、逐条信号（带权重与证据）、下一步建议。
静态信号来自壳/框架/本地校验/付费墙模型/支付串/明文主机；`--probe` 只发一次 GET，看响应是不是加密信封
（`"hash": true`、长 base64、`items` 明文列表、401/403），失败不抛异常。
判定树与实战对照见 `references/gate.md`。
