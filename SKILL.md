---
name: re
description: >
  逆向工程军刀：认格式、看固件向量表、反汇编、反编译、剥包、比两版、看运行时内存与报文。
  遇到 .hex/.srec/.bin 固件、PE/ELF 的 exe/dll、asar/APK/zip/MSI/CAB 安装包，或者要回答
  "这是什么""这版改了什么""这串报文哪些位在变""这个函数在干什么"时用。
  Triggers: 逆向, 反编译, 脱壳, 固件分析, 向量表, 拆包, 二进制对比, 协议字段,
  reverse engineering, decompile, unpack, firmware, binary diff.
---

# re：逆向军刀

看清一个**已经编译/打包好的东西**：固件、PE/ELF、安装包、asar、APK、两版差异。
有源码的问题不要用本 skill，直接读源码。

命令就是本目录下的 `re.cmd`（Linux/macOS 用 `re.sh`）。DSH 加载时会给出 Base directory，
用它拼：`& "<base>\re.cmd" ...`。如果 `re` 已在 PATH 上，直接 `re ...`。

## 开工前先体检一次

```
re doctor
```

末尾会列出缺什么、给出一条安装命令。缺引擎就装，不要用更弱的工具凑：

```
re setup --rizin     # 反汇编、函数、交叉引用
re setup --ghidra    # 反编译（自动带 JDK）
```

## 默认流程

1. **先认**：`re id <文件>` —— 格式、架构、编译器、壳、哈希、可疑线索。
2. **按类型分头走**：

| 你手上是 | 下一步 |
|---|---|
| 固件（.hex/.srec/.bin） | `re hex` 看段 → `re fw` 看向量表/入口 → `re funcs` → `re dis --at` → `re decompile --at` |
| PE / ELF / DLL | `re pe` / `re elf` → `re strings` → `re funcs` → `re xref --at` → `re decompile --at` |
| 安装包、asar、zip、APK、MSI、CAB | `re unpack` 摊开，再回到第 1 步 |
| 两个版本 | `re diff A B`，先看字节差异段，再看导入/节差异 |
| 一堆报文 / 内存 / 进程 | `re proto`（离线分帧看字段）、`re mem`（进程/模块/内存 dump，Windows） |

3. **给结论**：每条都要能落到地址、偏移或文件条目上。拿不准就写"推断"，别编。

## 命令表

| 命令 | 什么时候用 |
|---|---|
| `re id 文件` | 第一个命令，永远先跑它 |
| `re strings 文件` | 找 URL、路径、密钥、格式串；`-k url` / `-c 关键词` / `-l 20` |
| `re pe 文件` / `re elf 文件` | 节区、导入导出、资源、加固 |
| `re hex 文件 [--to bin --out x]` | HEX/S-record 段表、校验、转 BIN |
| `re fw 文件 [--vectors]` | Cortex-M：SP、Reset、异常、中断表、代码区 |
| `re fwmap 文件 [-o 目录]` | 一次产出全量反汇编、函数地图、外设引用（固件结构分析） |
| `re funcs 文件 [--deep]` | 函数表；固件用向量表当根，PE 默认浅扫 |
| `re dis 文件 --at 0x... -n 20` | 反汇编；不给 `--at` 时从入口/Reset 开始 |
| `re xref 文件 --at 0x...` | 谁引用这个地址 |
| `re decompile 文件 --at 0x...` | 反编译一个函数（Ghidra，首次较慢） |
| `re diff A B` | 两版差在哪 |
| `re unpack 文件 [-o 目录]` | 剥包：zip/apk/jar/asar/tar/gz/xz/zst/cab/msi/pyinstaller |
| `re mem` | 列进程、列模块、按地址 dump（Windows） |
| `re proto` | 把抓包按帧切分，指出恒定位与变化位 |
| `re doctor` / `re setup` | 体检与装引擎 |

## 输出约定

- 默认是给人读的紧凑文本，控制在十几行；要全量加 `--json`。
- 地址一律十六进制带前缀，偏移一律文件内偏移。
- 退出码：`0` 成功；`1` 有结果但有问题（校验错等，已写在输出里）；`2` 参数/环境不对；`3` 工具自身错误。

## 硬规则

- **不降级**：`re dis` 没有 rizin 会直接失败并给安装命令，不会拿玩具凑数。
- **不猜**：认不出架构、找不到向量表、哈希不符，都会明确报错，不返回半成品。
- **不硬来**：加壳文件跑 `re funcs` 会被拒绝（静态分析只会得到垃圾），先 `re unpack` 或从内存 dump。
- **不特例**：不认识项目名、不认识芯片型号；一切从文件内容推。

## 典型路线

- **陌生固件**：`re id` → `re hex`（段与空洞）→ `re fw`（向量表）→ `re dis --at <Reset>` → `re funcs` → 挑大的 `re decompile`
- **加壳 exe**：`re id`（看壳与入口所在段）→ 静态到此为止 → dump 内存后再 `re id` / `re funcs`
- **两版对比**：`re diff old.exe new.exe` → 差异段 → `re pe` 看节/导入变化
- **安装包**：`re id` → `re unpack` → 对里面最大的 exe 重跑 `re id`
- **APK/asar**：`re unpack` → `re strings` 找接口与密钥 → dex/js 再单独看

细节参数见 `references/commands.md`，场景配方见 `references/recipes.md`。
