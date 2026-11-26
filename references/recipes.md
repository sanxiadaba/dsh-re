# 场景配方

每条都是"从拿到文件到能下结论"的最短路径。命令里的地址换成你实际看到的。不知道该走哪条？先 `re id`，再按下面 11 条对号。

## 1. 陌生固件（HEX / S-record / bin）

```powershell
re id firmware.hex          # 先确认是 Intel HEX 还是裸 BIN
re hex firmware.hex         # 段、范围、空洞、校验
re fw firmware.hex          # SP / Reset / 异常 / 中断表
re dis firmware.hex --at <Reset> -n 40
re funcs firmware.hex       # 按大小排，挑最大的几个看
re decompile firmware.hex --at <大函数地址>
re fwmap firmware.hex -o fwmap   # 一次出全量反汇编 + 函数地图 + 外设引用
```

判断依据：`re fw` 给出的 Reset 落在映像内且带 Thumb 位，说明是 Cortex-M；
`独立处理` 那一行列出的才是真正注册了的中断（其余多半是默认死循环）。
裸 BIN 必须给加载地址：`--base 0x08000000`；架构和向量种子会自动推，推不出才要 `--arch/--bits`。

## 2. 加壳的 PE

```powershell
re id app.exe               # "壳"那一行会给壳名：UPX / ASPack / VMProtect …
re unpack app.exe -o out    # UPX 直接脱，产出 out\<名字>.unpacked.exe
re id out\<脱壳后的文件>     # 节表恢复正常、入口回到 .text 就对了
re strings out\... -c 关键词   # 脱壳后中文串也能读（GBK）
```

`re id` 认不出具体壳时会说"疑似"并列出理由。不是 UPX 的壳（VMProtect/Themida/自定义）静态到这一步就停：
下一步是动态——把进程跑起来、从内存 dump（`re mem --pid`），再对 dump 出来的映像跑 `re id`。

## 3. 两个版本差在哪

```powershell
re diff old.exe new.exe
```

输出顺序：字节差异段 → 相同比例 → 节变化 → 导入新增/删除 → 导出增减 → 入口/时间戳。
先看"差异段"落在哪个节，再看导入增减，基本能判断是修 bug 还是加了功能。

## 4. 安装包

```powershell
re id setup.exe             # 可能是 MSI/CAB/PyInstaller，也可能是 NSIS/Inno 自解压
re unpack setup.exe -o out  # 支持的直接摊开
```

MSI 走管理安装（`msiexec /a`）；CAB 用 `expand`；7z/rar 需要 PATH 上有 `7z.exe`；
NSIS/Inno 不在 `re unpack` 支持内，装 7-Zip 用 `7z x`。

## 5. Electron / asar

```powershell
re id resources\app.asar
re unpack resources\app.asar -o app_unpacked   # 条目哈希会校验
re strings app_unpacked\main.js -k url
```

asar 里的 `.node` 是原生模块，回到第 2/3 条按 PE 处理。

## 6. APK

```powershell
re apk app.apk                  # 包名/版本/框架/壳/原生库/SDK 线索，一条命令
re unpack app.apk -o apk_raw    # 摊开 zip：dex、so、assets、resources.arsc
re strings apk_raw\classes.dex -e gbk -l 40
```

- Flutter 应用（`libflutter.so` + `libapp.so`）：逻辑在 Dart AOT 快照里，Java 层基本是壳；
  `re strings lib\arm64-v8a\libapp.so` 能看到 `package:xxx/...dart` 源码路径与类名。
- 有 `appComponentFactory` 自定义类 + 小 classes.dex + 高熵 assets：是加固壳，先确认壳类型再谈改包。
- 要看 Java 源码：`jadx`（`re doctor` 会显示装没装）指向 apk 或 dex 即可。

## 7. .NET

```powershell
re id app.exe               # 看导入里有没有 mscoree / 节名 .NET 特征
ilspycmd app.exe -o out     # 需要另装 ilspycmd
```

## 8. 协议字段

```powershell
re proto capture.bin --frame 16
```

恒定位连续的区间是协议头/固定参数，变化位才是载荷。再结合 `re dis` / `re decompile`
找到打包函数，就能把偏移和字段名对上。变长/带同步字的协议先自己切好再喂。

## 9. 运行时内存

```powershell
re mem --list --filter 目标进程
re mem --pid 1234 --modules
re mem --pid 1234 --addr 0x401000 --size 0x2000 -o dump.bin
re id dump.bin
```

dump 出来的段先 `re id` 认类型，再按前面几条走。`-o` 已存在要 `--force`。

## 10. 芯片里跑的是不是这一版（J-Link / SWD）

```powershell
re chip --info                          # CPUID、SP、Reset
re chip --compare firmware.hex          # 逐字节比对；"完全相同"才算同一版
re chip --dump chip.bin                 # 读回来当普通固件分析
re chip --flash firmware.hex --device PY32F030 --yes   # 擦+写+读回校验
```

`--compare` 报不同字节数并列出前几处差异地址——这是判断"这份 HEX 是不是芯片里那版"的唯一可靠办法。
烧写会擦整个 flash，务必先 `--compare` 确认目标。

## 11. 串口到底通不通（短接/接线/波特率）

```powershell
re serial --list                        # 端口名与驱动
re serial -p COM11 --loopback           # 发探针、校验回显：短接对不对一次说清
re serial -p COM11 --listen 3           # 听 3 秒，看芯片有没有主动吐数据
re serial -p COM11 --send "hex:01 03 00 00" --wait 1
```

回显一致 = TX/RX 短接正确、端口和波特率可用；`--listen` 收到 0 字节 = 芯片没在发（或不在这个口上）。

## 常用组合

- 认不出格式：`re id` → 看 magic 与"线索"里的字符串 → 再决定用哪条
- 想知道某个字符串谁在用：`re strings -c 关键词` 拿偏移 → `re dis --at` 附近 → `re xref --at`
- 想知道某地址在哪个函数：`re funcs` 找包含它的区间 → `re decompile --at` 该函数入口
- 静态看不出所以然：`re chip --compare` + `re serial --listen`，先确认硬件那一半
