# caoin

Android arm64 无痕 hook 工具集。面向 frida 等公开工具特征明显、容易被反调试或代码完整性校验发现的场景，提供更隐蔽的 hook 手段。

> **定位说明（先读）**：caoin 不是 frida 的通用替代。它的"无痕"是用"通用性"换来的——每条路线都有明确的适用边界（见 [能力边界](#能力边界)）。需要"任意函数随便 hook"的场景，请用 frida / Dobby。
>
> **原理讲解（caoin-shadow）**：从 arm64 虚拟内存/页表/异常到读写分离 hook 的完整原理，见 [docs/原理.md](docs/原理.md)。

## 组件

| 组件 | 类型 | 作用 | 关键约束 |
|---|---|---|---|
| **caoin-shadow** | 内核 KPM | shadow 页读写分离：改返回值 / 改参数（`argN=`，x0..x30）/ **透传执行原逻辑**（重定位桩），**不改代码字节**（过 CRC 自检）；影子页与 status 页**内核分配** → 目标 maps **零新增** | 目标对受管页做 `mprotect`/`madvise` → hook **静默失效**（页表被内核合法改写；实测自愈救不回） |
| **caoin-hw** | 内核 KPM | 硬件断点：参数观察、改寄存器（地址级，不碰 PTE/内存） | 仅 6 个断点槽；不能改执行流 |
| **caoin** | CLI | 统一入口：`prep` / `shadow run|load|unload` / `hw` / `build` / `doctor` | 纯 shell，主机与设备通用 |
| **caoin_prep** | CLI | KPM 流程自动化：远程符号解析（+ 可选准备影子页/status 页）→ 输出 KPM args | 只解析 dynsym（共享库导出符号）；`nommap` 模式全程不用 ptrace |

## 架构

```
用户态  ┌─ caoin ──→ caoin_prep ──→ 解析符号/准备页 ──→ KPM args
        │      └──→ kpatch su kpm load|unload ─────────────┐
        ▼                                                  ▼
内核态  ┌─ caoin-shadow (KPM) ── PTE 读写分离 + do_page_fault hook ─┐
        ├─ caoin-hw (KPM) ────── DBGBVR/BCR 直写 + 断点异常接管    ├─→ 目标进程
        └─ 伴侣钩子：exit_mmap / copy_process（回收 + fork 防护）  ┘
```

- **caoin-shadow**：把受管页 PTE 在「执行视图（指向 shadow 页，X-only）」与「读取视图（指向原页，RW+UXN）」之间翻转。执行走 shadow 页里的桩（改返回值），读取恒拿到原页字节 → 代码段 CRC 自检不破。触发靠 `do_page_fault` 的页权限 fault。
- **caoin-hw**：绕过 perf_event 直接编程 AArch64 调试寄存器（DBGBVR/BCR/WVR/WCR），自己接管断点异常（`breakpoint_handler` / `single_step_handler` / `watchpoint_handler`），命中后改寄存器、单步放行原指令再重新武装。内核里不留 `perf_event` / `thread_struct.debug` / `bp_on_reg[]`。

## 构建

### 用户态（WSL / Linux aarch64 交叉）

```bash
# 依赖：aarch64-linux-gnu-gcc；另需从设备拉 bionic libc.so 与 linker64
#   adb pull /apex/com.android.runtime/lib64/bionic/libc.so  build/libc_bionic.so
#   adb pull /system/bin/linker64                            build/linker64
make                 # 构建 CLI + 用户态工具 + 测试目标，产物在 build/
make cli             # 只装统一 CLI（纯 shell，不需要交叉编译器）
```

### 安装与发布

```bash
make install PREFIX=/usr/local   # 安装 caoin、caoin_prep、KPM 源码与文档
make dist                        # 源码发布包 dist/caoin-<version>.tar.gz
make dist-bin                    # 带二进制的发布包（需先 make）
```

安装后 `caoin` 从 `$(PREFIX)/share/caoin/kpm` 找 KPM 文件，也可用 `CAOIN_KPM_DIR` 覆盖。

### 内核模块（KernelPatch 生态 CMake）

KPM 需要 [KernelPatch](https://github.com/bmax121/KernelPatch) 构建环境（本仓库不包含）：

```bash
cp caoin_ko/caoin_kpm.c  <kp-tree>/kpms/caoin-shadow/     # 配 caoin_hw_CMakeLists.txt
cp caoin_ko/caoin_hw.c   <kp-tree>/kpms/caoin-hw/         # 见 caoin_ko/CMakeLists 示例
cd <kp-tree>/build && cmake .. && make caoin-shadow.kpm caoin-hw.kpm
```

## 用法

### 统一 CLI

```bash
caoin version
caoin doctor          # 检查 caoin_prep / kpatch / .kpm 是否就位
caoin help
```

`caoin` 是纯 shell 入口：工具默认从脚本同级 `build/`、`$CAOIN_HOME/bin` 或 `PATH` 查找，
KPM 文件从 `$CAOIN_KPM_DIR`、当前目录、`$CAOIN_HOME/kpm` 查找。
kpatch 调用前缀默认 `kpatch su`，可用 `CAOIN_KPATCH` 或 `--kpatch` 覆盖。

### KPM shadow（改返回值 / 执行流）

```bash
# 目标零配合：prep 解析符号；影子页/status 页默认由 KPM 内核分配
# （nommap：不用 ptrace、目标 maps 零新增）
caoin shadow run <pid> <module|@> <symbol> --stub

# 只准备、不装载（输出可直接喂给 KPM 的参数串）
caoin shadow run <pid> <module|@> <symbol> --print

# 手工分两步
caoin prep <pid> <module|@> <symbol>
caoin shadow load "pid=0x.. tva=0x.. shva=0x.. sva=0x.. stub=1"

caoin shadow unload
```

**改参数 + 透传**（`recstub`：先覆盖寄存器，再跑**原逻辑**，返回值真实）：

```bash
# nommap 是默认：影子页/status 页交给 KPM 内核分配（目标 maps 零新增，全程不用 ptrace）
# stubmode=2 走重定位桩；argN 覆盖 xN（x0..x30）
caoin shadow run <pid> <module|@> <symbol> \
  --stub --stubmode 2 --arg0=0x64 --arg1=0x0

# 旧路径（远程 mmap 影子页/status 页，需要 ptrace）：显式 --mmap
# 随机化入口桩寄存器/stub 返回值/status magic：--polymorph
caoin shadow run <pid> <module|@> <symbol> --mmap --stub
caoin shadow run <pid> <module|@> <symbol> --polymorph --stub
```

`--<key>=<value>` 会原样透传给 KPM（如 `--arg0=0x64`、`--tva1=0x..`），
等价于 `--kpm-arg arg0=0x64`。

重定位桩会重定位**被入口桩覆盖的 4 条序言指令**（跨页 B/BL、ADR/ADRP、CBZ/TBZ、LDR literal），
之后函数体在原偏移继续执行 —— 所以能 hook **真实函数**（旧版不做重定位，只支持"寄存器运算型"）。

### KPM 硬件断点（参数观察 / 改寄存器）

```bash
caoin hw add <pid> <addr> x0=0x100          # 执行断点 + 寄存器覆盖
caoin hw addw <pid> <addr> 4                # 写观察点（len 1/2/4/8）
caoin hw load "verbose=1;add <pid> <addr> if x1=5"   # 条件覆盖
caoin hw unload
```

多命令用 `;` 分隔（本机 kpatch 精简版无 ctl0 子命令，args 是唯一配置入口）。

## 能力边界

**这是 caoin 最重要的一节**——"无痕"和"通用"是 trade-off，每条路线都有硬约束：

| 约束 | 原因 | 影响 |
|---|---|---|
| **`mprotect`/`madvise` 改写受管页 PTE** | caoin 的状态（影子 PFN + execute-only 权限）只存在 PTE 里，而 `mprotect`/`madvise` 是**内核（EL1）**在改页表——PTE 的 AP/UXN 位只约束 EL0，对内核没有任何约束力。且 `mprotect` **保留 PFN、只重写权限位**（不是"把原页换回来"） | 实测（`selfread` mode 7）：`mprotect` 后影子页 PFN 不变，但后果取决于跷跷板当时停在哪一态——**SHADOW 态 → 影子页失去 execute-only、变成 EL0 可读 → 读隐藏破**（目标能读到桩字节，CRC 自检即可发现；实测 `rd_eq_base=0`）；**STEP 态 → 原页被改成可执行 → 桩静默失效且从此不再 fault**（实测桩立即变回原返回值并永久不再恢复）。`madvise(MADV_DONTNEED)` 则是 zap PTE、按 VMA 重建 → 回到原页、桩失效。同权限 `mprotect` 被内核早退、PTE 不动（实测确认）。自愈（重写影子 PTE）实测**救不回** |
| **KPM shadow 并发下 TLB 抖动** | 每次视图切换会在别的核留下陈旧翻译，纠正一次 = 一次全量 `tlbi vmalle1is`（本机 `vaae1is` 在 fault 上下文活锁、`alle1is` panic，只剩全量可用） | 修复前实测 4 线程下 98% 的 handler 进入都在纠正陈旧 TLB，且**一 engage 就活锁**；修复（桩装完补 flush + 取指 permission fault 也纠正）后同一压测（4 线程 / 4.19e9 次迭代）取指纠正降到 1727 次、`bad=0`。低频调用场景可忽略 |
| **改关键函数返回值会崩** | 非 caoin 特有，frida 同样如此 | 改值要挑函数 / 用条件 hook |
| **硬件断点仅 6 槽** | 硬件资源上限（本机 brps=6 wrps=4） | 只能同时观察少量点 |

**实测对照**（自建双层检测样本 `tests/shellwatch.c`：代码段 CRC 自检 + maps 扫描）：

| 路线 | CRC 自检 | maps 痕迹 | 改执行流 |
|---|---|---|---|
| KPM shadow | ✓ 不破 | **零新增**（影子页内核分配；实测 maps 95→95 无 diff） | ✓ |
| KPM 硬件断点 | ✓ 不破 | 无（不动内存） | ✗（仅改寄存器） |

## 与 wxshadow 的关系

**caoin-shadow 的 shadow 页机制与 [wxshadow](https://github.com/bmax121/KernelPatch) 同源**（本仓库 README 早期即注明"wxshadow 同款"）。核心机制（执行走 shadow、读取走原页）一致，差异在：

- **触发方式**：wxshadow 用 BRK 指令（`register_user_break_hook`）；caoin 用页权限 fault（hook `do_page_fault`）
- **翻转粒度**：wxshadow per-page 全局；caoin per-hook 表（多 hook 独立状态）
- **控制入口**：wxshadow 用 prctl；caoin 用 load args / 内核态注入

效果等价（都是"原页字节不变 + 执行重定向"）。**caoin 相对 wxshadow 的真正增量是**：内核态注入（无 ptrace 特征）、端到端工具链（符号解析 + 自动化）、自指读软件模拟（解掉独占页约束）、重定位桩（能 hook 真实函数），以及硬件断点路线。

**两者的共同边界**：状态都存在 PTE 里，而 PTE 的权限位只约束 EL0 → 内核（EL1）对页表的任何改写都无解。具体地，`mprotect` 保留 PFN 只重写权限位（SHADOW 态 → 读隐藏破；STEP 态 → 原页变可执行、桩静默死），`madvise(MADV_DONTNEED)` 则 zap 后按 VMA 重建（回到原页、桩失效）。wxshadow 的 per-page PTE 锁解决的是**并发竞态**，解决不了"页表被内核改写"。

## 项目结构

```
caoin/
├── cli/
│   ├── caoin          #   统一 CLI（纯 shell）
│   └── prep.c         #   符号解析 + 页准备
├── caoin_ko/          # 内核 KPM 模块
│   ├── caoin_kpm.c    #   caoin-shadow：shadow 页读写分离
│   ├── caoin_reloc.c  #     KPM 侧 arm64 指令重定位器（recstub 用）
│   ├── caoin_hw.c     #   caoin-hw：硬件断点
│   └── legacy/        #   退役路线源码（LKM 换页版 v1/v2b/v2d/v2e），仅存档
├── hook/              # ARM64 hook 原语（重定位、跳转桩）+ 主机端单测
├── tests/             # 测试目标与检测样本（target_dyn / shtarget / shellwatch / selfread / poke64）
│                      #   selfread：9 格实验目标（自指读 / 页内读别页 / 跨页调用探针 / 改参数 / fork / 多线程 / mprotect / madvise / 同权限 mprotect 判据）
├── docs/              # 原理.md / DEVLOG.md
├── build.sh           # 用户态与测试目标构建
├── Makefile           # 构建 / 安装 / 发布
└── VERSION
```

## 许可

GPL-2.0（见 [LICENSE](LICENSE)）。内核模块运行于 Linux 内核之上，且机制借鉴了同生态的 GPL 项目（wxshadow、KernelPatch）。

## 免责声明

仅限**授权范围内的安全研究**（自有设备、CTF、明确的测试授权）。使用者需自行承担合规责任。
