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

第一次用先按仓库 README 建 venv 并装 rizin（`re setup --rizin`）。
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
| 固件（.hex/.srec/.bin） | `re hex` 看段 → `re fw` 看向量表/入口 → `re funcs` → `re dis --at` → `re decompile --at`；要确认芯片里是不是这一版就 `re chip --compare` |
| PE / ELF / DLL | `re pe` / `re elf` → `re strings` → `re funcs` → `re xref --at` → `re decompile --at` |
| 安装包、asar、zip、APK、MSI、CAB | `re unpack` 摊开；APK 先 `re apk` 看包名/框架/壳/SDK 线索，再回到第 1 步 |
| 要改二进制 / 重签 APK | `re patch --plan`（计划文件：改字节、加节、装 5 字节跳板）→ 打完 `re dis` 复核；APK 用 `re repack` 替换文件后 `--sign` 重签 |
| 不确定"改了有没有用" | 先 `re gate 文件`：判定是客户端可改还是服务端权威，再决定要不要动手 |
| 两个版本 | `re diff A B`，先看字节差异段，再看导入/节差异 |
| 一堆报文 / 内存 / 进程 | `re proto`（离线分帧看字段）、`re mem`（进程/模块/内存 dump，Windows） |
| 真硬件 | `re chip --info` 探测、`--compare` 比对、`--dump` 读回、`--flash --yes` 烧写；`re serial --loopback` 验串口接线 |

3. **给结论**：每条都要能落到地址、偏移或文件条目上。拿不准就写"推断"，别编。

## 命令表

| 命令 | 什么时候用 |
|---|---|
| `re id 文件` | 第一个命令，永远先跑它 |
| `re strings 文件` | 找 URL、路径、密钥、格式串；`-k url` / `-c 关键词` / `-l 20` |
| `re pe 文件` / `re elf 文件` | 节区、导入导出、资源、加固 |
| `re hex 文件 [--to bin --out x]` | HEX/S-record 段表、校验、转 BIN |
| `re fw 文件 [--vectors]` | Cortex-M：SP、Reset、异常、中断表、向量目标 |
| `re fwmap 文件 [-o 目录]` | 一次产出全量反汇编、函数地图、外设引用（固件结构分析） |
| `re funcs 文件 [--deep]` | 函数表；固件用向量表当根，PE 默认浅扫 |
| `re dis 文件 --at 0x... -n 20` | 反汇编；不给 `--at` 时从入口/Reset 开始；有符号用 `--sym` |
| `re xref 文件 --at 0x...` | 谁引用这个地址 |
| `re decompile 文件 --at 0x...` | 反编译一个函数（Ghidra，首次较慢） |
| `re decompile-all 文件 -o all.c` | 所有函数反编译到一个文件 |
| `re diff A B` | 两版差在哪 |
| `re unpack 文件 [-o 目录]` | 剥包：zip/apk/jar/asar/tar/gz/xz/zst/cab/msi/pyinstaller、**UPX 壳的 PE** |
| `re apk 文件` | APK 结构：包名/版本/权限/框架(Flutter/RN/Unity)/加固特征/原生库/SDK 线索 |
| `re patch --plan p.json [--dry-run]` | 按计划改字节、加节、装 5 字节跳板；写完自检并逐条回报改了哪里 |
| `re repack in.apk -o out.apk --sign …` | 重打包：替换条目、4 字节对齐、重签（v1/v2/v3）、校验；`--gen-key` 现场生成密钥 |
| `re gate 文件 [--probe URL]` | 判定"客户端可改 / 疑似服务端权威 / 证据不足"，给信号与下一步 |
| `re chip` | J-Link + SWD：`--info` 探测、`--dump` 读回、`--compare` 与固件比对、`--flash --yes` 烧写 |
| `re serial` | 串口：`--list`、`--listen N`、`--loopback` 环回自检、`--send text:…/hex:…` |
| `re mem` | 列进程、列模块、按地址 dump（Windows） |
| `re proto` | 把抓包按帧切分，指出恒定位与变化位 |
| `re doctor` / `re setup` | 体检与装引擎 |

## 输出约定

- 默认是给人读的紧凑文本，控制在十几行；要全量加 `--json`。
- 地址一律十六进制带前缀，偏移一律文件内偏移。

## 硬规则

- **不降级**：`re dis`/`re funcs`/`re fwmap` 没有 rizin 会直接失败并给安装命令，不会拿玩具凑数
  （`re fwmap --partial` 是显式的、结果里标 `degraded: true` 的例外）。
- **不猜**：认不出架构、找不到向量表、哈希不符，都会明确报错，不返回半成品。
- **不硬来**：加壳文件跑 `re funcs` 会被拒绝；`re id` 会说出是哪种壳（UPX/ASPack/VMProtect…），
  UPX 直接 `re unpack` 就能脱，其它壳从内存 dump（`re mem`）。
- **不特例**：不认识项目名、不认识芯片型号；一切从文件内容推。
- **改前先判**：真要动二进制前先 `re gate`；它说"疑似服务端权威"时，改客户端只能改展示，不能改结果——先找服务端下发的那条链路。
- **补丁只走计划文件**：所有改动写进 JSON 计划（可 diff、可重放），执行后必须看 `自检 通过`；`--dry-run` 先演算一遍。改的是副本，不要直接改原始样本。
- **重签必须验**：`re repack --sign` 之后一定看 `校验=通过`；包内 `lib/*.so` 换过就必然要重签（v1/v2/v3 摘要全变）。

细节参数见 `references/commands.md`，场景配方见 `references/recipes.md`，判定树见 `references/gate.md`。
