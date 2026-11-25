# 场景配方

每条都是"从拿到文件到能说人话"的最短路径。命令里的地址换成你实际看到的。

## 1. 陌生固件（HEX / S-record / bin）

```powershell
re id firmware.hex          # 先确认是 Intel HEX 还是裸 BIN
re hex firmware.hex         # 段、范围、空洞、校验
re fw firmware.hex          # SP / Reset / 异常 / 中断表 / 代码区
re dis firmware.hex --at <Reset> -n 40
re funcs firmware.hex       # 203 个函数里挑最大的几个
re decompile firmware.hex --at <大函数地址>
```

判断依据：`re fw` 给出的 Reset 落在映像内且带 Thumb 位，说明是 Cortex-M；
SP 落在 0x2000_0000 附近基本是 SRAM。中断表非零项多，说明是中断驱动的固件，
先看 SysTick / 串口 / USB 相关的中断入口。

裸 BIN 必须给加载地址：`--base 0x08000000`；架构认不出来时补 `--arch arm --bits 16`。

## 2. 加壳的 PE

```powershell
re id app.exe               # 看"壳"那一行：哪些节没有原始数据、入口落在哪、哪节高熵
re pe app.exe               # 节表与导入（壳通常保留导入给加载器用）
re strings app.exe -k url   # 壳没加密完的部分常能漏出线索
```

静态到这一步就该停：`re funcs` 会被拒绝。下一步是动态——把进程跑起来、从内存 dump
（`re mem --pid` / 外部 dump 工具），再对 dump 出来的映像跑 `re id`，`re funcs` 才有意义。

## 3. 两个版本差在哪

```powershell
re diff old.exe new.exe
```

输出顺序：字节差异段 → 相同比例 → 节变化 → 导入新增/删除 → 导出增减 → 入口/时间戳。
先看"差异段"落在哪个节，再看导入增减，基本能判断是修 bug 还是加了功能。

## 4. 安装包

```powershell
re id setup.exe             # 可能是 NSIS/Inno/MSI/CAB，先看识别结果
re unpack setup.exe -o out  # 支持的直接摊开
re id out\<最大的 exe>      # 对里面的主体重跑一遍
```

MSI 走管理安装（`msiexec /a`）；CAB 用 `expand`；7z/rar 需要 PATH 上有 `7z.exe`。

## 5. Electron / asar

```powershell
re id resources\app.asar
re unpack resources\app.asar -o app_unpacked   # 条目哈希会校验
re strings app_unpacked\main.js -k url
```

asar 里的 `.node` 是原生模块，回到第 2/3 条按 PE 处理。

## 6. APK / JAR

```powershell
re unpack app.apk -o apk_unpacked
re strings apk_unpacked\classes.dex -n 6 -k url
re id apk_unpacked\lib\arm64-v8a\libfoo.so
```

DEX 反编译需要 jadx（`re doctor` 会报缺）；`.so` 按 ELF 处理。

## 7. .NET

```powershell
re id app.exe               # 看导入里有没有 mscoree / 节名 .NET 特征
ilspycmd app.exe -o out     # ilspycmd 在 PATH 上时直接反编译
```

## 8. 协议字段

```powershell
re proto capture.bin --frame 16
```

恒定位连续的区间是协议头/固定参数，变化位才是载荷。再结合 `re dis` / `re decompile`
找到打包函数，就能把偏移和字段名对上。

## 9. 运行时内存

```powershell
re mem --list --filter 目标进程
re mem --pid 1234 --modules
re mem --pid 1234 --addr 0x401000 --size 0x2000 -o dump.bin
re id dump.bin
```

dump 出来的段先 `re id` 认类型，再按前面几条走。

## 常用组合

- 认不出格式：`re id` → 看 magic 与"线索"里的字符串 → 再决定用哪条
- 想知道某个字符串谁在用：`re strings -c 关键词` 拿偏移 → `re dis --at` 附近 → `re xref --at`
- 想知道某地址在哪个函数：`re funcs` 找包含它的区间 → `re decompile --at` 该函数入口
