# 命令参考

只写参数与行为，套路在 `recipes.md`。

## 全局

| 参数 | 说明 |
|---|---|
| `--json` | 输出完整 JSON（默认是给人读的紧凑文本） |
| `--version` | 版本 |

退出码：`0` 成功；`1` 有结果但发现问题（校验错、段重叠等，已写进输出）；`2` 参数/环境不对；`3` 工具内部错误。

## re id

```
re id 文件
```

识别格式（按内容，不看扩展名）、架构、位数、字节序、入口、编译器、节、壳的迹象、导入依赖、SHA256。
PE 会额外判断"原始数据为 0 的节 + 入口落在异常段 + 高熵"这类加壳迹象；ihex/srec 会提示下一步跑 `re hex` / `re fw`。

## re strings

```
re strings 文件 [-n 4] [-m 0] [-k url] [-c 子串] [-r 正则] [-l 20] [--no-utf16]
```

扫 ASCII 与 UTF-16LE，输出 `偏移 编码 文本`。`-k` 的分类：url、path、email、ip、format、hex、pem。

## re pe / re elf

```
re pe 文件
re elf 文件
```

PE：节表（rva、虚拟大小、文件大小、权限、熵）、按 DLL 分组的导入、导出、资源类型、Authenticode 有无。
ELF：节表、DT_NEEDED、SONAME、RPATH、动态符号数、NX/RELRO。

## re hex

```
re hex 文件 [--base 0x08000000] [--to bin --out x.bin] [--fill 0xFF]
```

Intel HEX / Motorola S-record：段表、范围、记录数、校验错误、空洞；可转成裸 BIN（空洞按 `--fill` 填）。
裸 BIN 需要 `--base`。

## re fw

```
re fw 文件 [--base 0x08000000] [--vectors]
```

Cortex-M 向量表：初始 SP、Reset、标准异常入口、IRQ 表、代码区范围。
判断规则只有三条：SP 合理、Reset 带 Thumb 位、Reset 落在映像内。`--vectors` 列出全部非零向量。

## re funcs

```
re funcs 文件 [-l 40] [--arch arm] [--bits 16] [--deep] [--force]
```

- 固件：先用向量表当函数根，再 `aaaa` 深分析（32 KB 固件约 2–3 秒）。
- PE/ELF：默认 `aa` 浅扫；`--deep` 才 `aaaa`。
- 文件疑似加壳时直接拒绝（静态分析只会得到垃圾，还可能跑很久），`--force` 才硬跑。

## re dis

```
re dis 文件 [--at 0x08000114] [--sym 名字] [-n 20] [--arch arm] [--bits 16] [--base 0x08000000]
```

输出 `地址 字节 汇编`。不给 `--at`/`--sym` 时：固件从 Reset 开始，PE/ELF 从 rizin 认的入口开始。

## re xref

```
re xref 文件 --at 0x0800161c [--deep] [--force]
```

谁引用了这个地址。分析深度与 `re funcs` 相同。

## re decompile

```
re decompile 文件 --at 0x08000114 [--sym 名字] [--base 0x08000000] [--timeout 300]
```

Ghidra headless 反编译一个函数。固件会按向量表推处理器（Cortex-M → `ARM:LE:32:Cortex`）并用 BinaryLoader 按基址装载。
第一次跑要导入+分析，慢；超时用 `--timeout` 调。

## re diff

```
re diff A B
```

先按 4 KB 块给字节差异段与相同比例，再按格式给结构差异（PE：节的虚拟/文件大小与熵、导入新增/删除、导出增减、入口、时间戳）。

## re unpack

```
re unpack 文件 [-o 目录] [--force]
```

支持：zip/jar/apk/ooxml、tar、gzip/xz/bz2/zstd、asar（校验条目哈希）、cab（expand）、msi（msiexec 管理安装）、7z/rar（需要 7z.exe）、PyInstaller CArchive。
目标目录非空且没给 `--force` 会拒绝，避免覆盖。

## re mem

```
re mem --list [--filter 名字]
re mem --pid 1234 --modules
re mem --pid 1234 --addr 0x401000 --size 0x1000 [-o dump.bin]
```

Windows（ReadProcessMemory）。权限不够、地址没映射都会明确报错。

## re proto

```
re proto 抓包.bin --frame 16 [--max 8]
```

按固定帧长切分，统计每个偏移的取值集合：恒定位压成区间、变化位压成区间，并打印前几帧的十六进制。
用来快速判断协议头长度、哪些字段是参数。

## re doctor / re setup

```
re doctor
re setup --rizin | --ghidra | --java | --all
```

引擎装到 `%LOCALAPPDATA%\dsh-re\engines`（可用 `DSH_RE_DATA` 改），不进仓库、不进 PATH。
`--ghidra` 会读 Ghidra 自己声明的最低 JDK 版本，不够就补装对应版本。
