# caoin 开发日志

> 从 README 提取的实测记录、踩坑实录与路线演进（按时间倒序，含退役路线）。
> 发布版概览见仓库根目录 README.md。

## 路线

- [x] **P0**：内核模块可加载性确认（equuleus 4.9：CONFIG_MODULES=y, modules_disabled=0）
- [x] **P1**：inline hook 原语（B/BL、ADR/ADRP 正负偏移、CBZ/TBZ、LDR literal；主机单测 + 真机 ALU/ADRP 序言双验证）
- [x] **P2**：注入器（ptrace + 远程 __loader_dlopen + memfd 隐匿加载）+ agent（零依赖自解析）+ CLI 配置化——真机三组行为级验证全过
- [x] **P3-v1**：内核换页 hook（幽灵模块路线，见下）
- [x] **P3-v2**：X-only 权限 + fault 跷跷板（读写分离：校验读原页，执行走桩页）——LKM/VBAR 路线退役（idle 恢复 + KP 自保护）；**KPM 路线（2026-10-14）全链路闭环 + 无痕验证通过（见下方实测）**
- [x] **P3-v2.5**：内核态注入（status 页握手 → KPM 目标 fault 上下文内核侧直装：页表 walk 取 shva 物理帧线性地址 → 写桩 + cache 维护；零 ptrace/信号/TracerPid/零 pc 劫持）
- [x] **P3-v3**：多 hook 点表驱动（hooks[4] 每项独立跷跷板状态/视图状态/KPTI 兜底；fault 按 far 页帧分发；tva1/shva1… 参数；R3-REQ 重发防丢）——**重启后干净内核回归全通：777/778 双 hook 同时生效、互不干扰、unload 恢复 88/30、无 Bad page**
- [x] **P3-v3**：多 hook 点（777/778 同时生效）+ **记录+透传桩**（影子页 scratch 跑原逻辑，返回真实值 88/30；参数报告区已有，x0=0 异常待查）
- [x] **P3-v4（fork 防护，2026-10-15）**：copy_process 伴侣钩子——fork 前 pause（受管页 PTE 恢复原值，防子进程继承 shadow PFN 导致 RSS/rmap 记账错位）、fork 后 resume；只处理非 CLONE_VM；状态经 `args->local.data[0]` 传递。真机实测 39 次 fork pause/resume 成对、0 条 Bad rss-counter/Bad page、双 hook 不受影响。**同轮修复 caoin-shadow 卸载路径 panic 隐患**（`hook_unwrap`→`hook_unwrap_remove`，见下）。
- [x] **P3-v4（符号解析自动化，2026-10-15）**：`caoin_prep` 工具（`cli/prep.c`）——给定 `<pid> <module> <symbol>` 自动解析远程 ELF dynsym 符号 + ptrace 远程 mmap 影子页（拷贝受管页快照）/status 页 → 输出可直接喂 KPM 的 args；KPM 支持**页内偏移**（shva_off 自动 = tva & 0xFFF）与 **`stub=1`**（加载即装桩，跳过 INJ_REQ 握手）。真机端到端：目标零配合 → 桩生效（函数返回值变 777）、unload 恢复、无异常。
- [ ] **P3-v4（收尾）**：参数捕获可见性定位；try_to_unmap 回收窗口；ll 壳实战
- [x] **P3-v5（参数观察，2026-10-15）**：硬件断点 KPM（`caoin_ko/caoin_hw.c`，构建产物 `caoin-hw.kpm`）——借鉴 kern/Hook 的 hw_hook 思路重写：直写 DBGBVR/BCR/WVR/WCR + hook 4.9 的 breakpoint_handler/single_step_handler/watchpoint_handler + `__switch_to` per-CPU 编程 + 单步恢复协议；**真机验证通过**（断点命中+寄存器改写+单步恢复+干净卸载+压力回归，见下节）
- [x] **app 域注入实战（2026-10-15）**：真实用户 app（untrusted_app 域）上跑通完整注入链路——root ptrace app + memfd 隐匿加载 agent + 用户态 inline hook + 日志回传；**顺带修一处特征泄露**（trampoline memfd 名 "caoin" → "jit-cache"）。实测见下节。
- [x] **ll 壳双层检测对抗实测（2026-10-15）**：自建检测样本（代码段 CRC 自检 + maps 扫描 + TracerPid），对照 caoin 两条路线。**结论：agent（inline hook）过不了 CRC 自检（改字节）、maps 暴露；KPM shadow 双层全过**（CRC 不破 + maps 干净 + 桩生效）。修正原论断（"agent memfd = 完整解"不成立）。见下节。
- [ ] 后置：Java 层下沉的 ArtMethod 全覆盖；更强反调试（信号/时序类）对抗

## P3-v5 硬件断点模块（caoin-hw，2026-10-15 真机验证通过）

**动机**：minstore/recstub 桩实证 store 类影子页桩不可行（I-cache 跨核陈旧）后，参数观察型 hook（命中→改寄存器→放行原指令→重新武装）的正确工具是硬件断点。技术栈借鉴 `git.colorsky.fun/kern/Hook`（GPL-3.0 的 hw_hook 模块；**思路重写不拷贝**，防字节特征）。

**真机实测（MI 8 Pro / equuleus 4.9.337 / APatch，2026-10-15）**：
- 加载：`kpatch su kpm load caoin-hw.kpm "add <pid> <addr> x0=0x100"` → `ready (brps=6 wrps=4)`，三 handler 全 hook（`bp=...e92c(r2) ss=...a94(r2) wp=...ebb0(r2)`）
- 执行断点改寄存器：目标（自编静态 hwtest，循环打印 `hw_victim(i)=2i+1`，victim 固定 0x402000）→ `HIT pc=402000 x0=<真实参数>` + 返回值被覆盖（`x0=0x100` → 输出恒 513）；**连续 670 次调用持续命中**（单步恢复 + 重新武装稳定）
- 卸载：目标保持运行下 unload → 输出立即恢复 `2i+1`、进程存活、槽全零（BVR/BCR/WVR/WCR=0）、load average 0.22、无 panic
- 压力：3×(load+add → unload) 无残留累积、无 Bad page、无 undefined instruction
- 静音：默认零诊断打印（无痕优先），`verbose=1` 开流程日志

**踩坑实录（4 个 bug，全部真机定位）**：
1. **handler 选型错**：4.9 硬件断点（EC 0x30）走 `breakpoint_handler`，**不是** `brk_handler`（后者是 BRK 指令 EC 0x3C）。hook 错 → 断点命中无人处理 → 目标卡在断点循环。改为 `breakpoint_handler`（4.9，wrap3，regs=arg2）/`do_breakpoint`（6.x，wrap2，regs=arg1）按符号探测。
2. **跨 load 残留累积**：`hw_prog_clear` 原只清"记账槽"，模块反复 load/unload 时非当前 CPU 的槽无人清 → 残留跨实例累积 → 6 个 brp 全被填满 → 新实例找不到空闲槽、断点永不武装。改为**每次 switch 清全部槽**（自愈残留，代价 ~10 条 MSR/切换）。
3. **unload 路径 panic**（pstore 取证 `Internal error: undefined instruction: 0, PC is at __switch_to+0x8/0xf0`）：`hook_unwrap` 走 hotpatch→stop_machine，在模块 exit（RCU 上下文）里恢复原指令的窗口被其他 CPU 取指 → 全零指令 → panic。改用 `hook_unwrap_remove(...,0)`（只摘链不恢复指令，kern/Hook 的 kp_unhook.h 方案）+ `on_each_cpu` 清所有 CPU 槽与 MDSCR.SS/MDE。
4. **offsets 解析**：本机 KP **不导出** `task_struct_offset` 符号（`kp_tab absent`）——探针法（`get_task_mm(current)` 扫描）是唯一路径，实测 mm 偏移 0x5c8（与 caoin-shadow 一致）。KP 表读取保留为对照。

**与参考实现的差异（caoin 语境）**：4.9 static handler 名与签名（见坑 1）；单步恢复 hook `single_step_handler`（4.9）/`try_step_suspended_breakpoints`（6.x）；控制通道用 KPM_CTL0 字符串命令——本机 kpatch 精简版**无 ctl0 子命令**，故 args 为唯一配置入口：`load ... "verbose=1;add <pid> <addr> xN=v"`（';' 分隔多命令）。

**痕迹面（与跷跷板互补）**：无 perf_event / 无 thread_struct.debug / 无 bp_on_reg[] / 不动 PTE 不动内存字节（CRC 与 /proc/pid/mem 双无痕）；残留 = DBG 寄存器非零（ground truth）+ MDSCR.MDE + 内核 text 上 breakpoint_handler/single_step_handler/watchpoint_handler/__switch_to/exit_mmap 首指令被 hook（KP 框架固有）+ 单步时序侧写。

**未实测 / 遗留**：观察点（addw）与条件覆盖（cond）代码已备但未跑；`del`/`clear`/`hit`/`slots` 命令需 ctl0 通道（本机不可用），仅 args 驱动；外部调试寄存器虚拟化未移植（caoin 不需要反调试别人）；`hw_breakpoint_reset`（热插拔/休眠）擦槽靠下次 switch 自愈；EL1 断点不支持；观察点 far"最近匹配"启发式未做。

## fork 防护 + 卸载路径修复（2026-10-15 真机验证通过）

**fork 防护（copy_process 伴侣钩子）**：fork 时 `copy_process` 快照父进程页表——受管页 PTE 若停在 SHADOW/STEP，子进程会继承 shadow 页 PFN，内核按 shadow 页记账子进程 RSS/rmap → 后续 teardown 触发 `Bad rss-counter` / `Bad page map`（wxshadow 同款问题）。防护 = fork 前把受管页 PTE 恢复原值（pause），`copy_process` 返回后翻回原视图（resume）；只处理非 `CLONE_VM`（线程共享 mm，无页表快照）；状态经 KP 的 `args->local.data[0]` 在 before/after 间传递。装不上只 warn（安全增强，不阻断主链路）。

**实测**：tdyn4 主循环每 8 轮 `clone(SIGCHLD,0,0,0,0)`（真 fork，非 CLONE_VM）→ dmesg **39 次 `fork pause (2 hooks)`/`fork resume (2 hooks)` 成对**；`t(5)=777 t2(5)=778 crc_ok=1` 全程稳定（双 hook 不受 fork 影响）；**0 条 Bad rss-counter / Bad page**；unload 后恢复 88/30。

**卸载路径 panic 修复（同源 bug，caoin-hw 先发现）**：`caoin_restore` 原用 `hook_unwrap()`（走 hotpatch→stop_machine：睡眠调用 + 恢复原指令的窗口被其他 CPU 取指）。caoin-hw 真机实证该路径在 `__switch_to` 上直接 panic（pstore：`Internal error: undefined instruction: 0, PC is at __switch_to+0x8/0xf0`）。do_page_fault/exit_mmap/copy_process 同为高频/关键路径，同样风险 → 全部改 `hook_unwrap_remove(...,0)`（只摘链，不 sleep、不恢复指令；函数保留跳 KP trampoline，空链 tail-call 原函数）。**实测**：3 轮 load/unload 压力（tdyn4 持续 fork）全成功、无 panic、load average 0.36。

**顺带修复**：`caoin_install_recstub` 的 `enc[9]` 数组实际写 12 条指令（越界写）——recstub 默认不启用故未暴露，改 `enc[16]`。

## 符号解析自动化（caoin_prep，2026-10-15 真机端到端验证）

**解决的问题**：此前 KPM 流程要求目标进程自备影子页/status 页并输出 CFG（tdyn4 专用），实战目标不会配合。

**用法**：
```
# 目标零配合（普通进程，循环调用某函数即可）：
./shtarget &                                  # pid=11452
caoin_prep 11452 @ shtarget_func              # → pid=0x2cbc tva=0x61eb97cfe0 shva=0x7ae766a000 sva=0x7ae757b000
kpatch su kpm load caoin-shadow.kpm "pid=0x2cbc tva=0x61eb97cfe0 shva=0x7ae766a000 sva=0x7ae757b000 stub=1"
# → 目标函数返回值被桩覆盖（777）
```

**caoin_prep 三步**（全程 ptrace，仅准备期；完成后 detach，运行期无痕迹）：
1. `/proc/pid/maps` 找模块基址 → 远程 ELF dynsym 解析符号 → **tva**（函数真实地址，含页内偏移）
2. 远程 `mmap` 影子页(RW) → 拷贝受管页 `[tva & ~0xFFF, +4K)` 到影子页（**影子页 = 原页快照**，KPM 只在其上写桩）→ **shva**
3. 远程 `mmap` status 页并写一次（fault-in）→ **sva**

**KPM 侧配合改动**：
- **页内偏移**：`shva_off` 自动 = `tva & 0xFFF`（原硬编码 0，要求函数页对齐）。实战目标函数不在页首。
- **`stub=1`**：加载即装桩（跳过 INJ_REQ 握手）。原桩安装由目标写 status=INJ_REQ 触发（tdyn4 第 3 轮），自动化流程里目标不发请求。

**踩坑（4 个，全部真机定位）**：
1. **静态链接程序无 `.dynsym`**：`-rdynamic` 只对动态链接生效；静态程序的 local 符号在 `.symtab`（不映射内存，远程读不到）→ 测试目标必须动态链接（实战目标是共享库，导出符号天然在 dynsym）。
2. **受管页内其他被执行的代码干扰跷跷板**：caoin-shadow 的翻转是**页级**的——页内若有其他被执行的代码（如主循环），状态机被频繁打断、桩不生效（`DUMP far=<页内其他偏移> esr=9600000f` 内核态 fault）。**受管函数须独占页**（tdyn4 用 `aligned(4096)+fill`；shtarget 用汇编 `.balign 4096 + .fill 64` 让函数在页内偏移 0xfe0、页内其余为不执行的填充）。
3. **status 页未 fault-in**：KPM 经内核线性映射读 status 页，PTE 未 present 时 PFN 推导失败（`wstat slot unreadable`）→ caoin_prep 须写一次触发缺页。
4. **KPM 会覆写 status**（写 5/6/7 握手标记），故 caoin_prep 预写 INJ_REQ 无效 → 加 `stub=1` 直接装桩。

**残留限制**：caoin_prep 只能解析 dynsym（共享库导出符号）；**页级独占约束**是 caoin-shadow 架构固有的（参数观察类需求用 caoin-hw 硬件断点，无此约束）。

## app 域注入实战（2026-10-15 真机验证通过）

**背景**：此前所有验证都在 shell 域。本节点是在真实 **untrusted_app 域**进程（`com.reqable.android`，u0_a511）上跑通完整链路。

**验证链路**（全部实测通过）：
1. **root ptrace app 可行**：`caoin_prep 7624 libc.so write` → 解析出 `write=0x74c13ec700`、远程 mmap 影子/status 页成功（magisk 域不受 app 的 SELinux ptrace 限制）
2. **memfd 隐匿加载 agent**：`caoin_inject 7624 caoin_agent.so "libc.so|write" memfd` → `INJECT OK`；app maps 显示 `/memfd:cache (deleted)`，**无 `/data/local/tmp` 路径**（绕 maps 路径黑名单）
3. **用户态 inline hook 生效**：`OK #0x0 write @0x74c13ec700`；app 活动时命中记录持续产出（实测一次会话 255KB 日志），格式 `#0x0 lr=... a0=<fd> a1=<buf> a2=<count> ... ret=<返回值>`
4. **透传正确**：`a2=0x18` → `ret=0x18`（write 正常返回，行为无破坏）
5. **无痕**：`TracerPid: 0`（注入后 detach、agent 无驻留线程）
6. **日志回传**：app 域对 `/data/local/tmp` 无写权限 → injector 预建日志文件 + chmod 666
7. **app 存活正常**：注入/hook 全程 app 不崩

**顺带修复：特征泄露**。agent 的 trampoline memfd 原用名字 `"caoin"` → `/proc/pid/maps` 直接显示 `/memfd:caoin (deleted)`，**把工具身份写进了目标 maps**（与"低特征"目标直接冲突）。改为 `"jit-cache"`——伪装成 ART 自己的 JIT 代码缓存（app maps 里本来就有同名映射，反而起混淆作用）。修复后 maps 只见 `/memfd:cache`（agent so）+ `/memfd:jit-cache`（trampoline），无工具名。

**KPM 路线在 app 域的适用性**：caoin-shadow 页级翻转要求受管函数独占页，app 的共享库函数（libc 等）与大量代码同页 → **不适用**；app 域 hook 走 agent（用户态 inline hook，无页约束）。参数观察类需求可用 caoin-hw（硬件断点，地址级）。

## ll 壳双层检测对抗实测（2026-10-15 真机验证）

**背景**：README 原论断是"v2 读写分离 + agent 的 memfd 加载 = 对 ll 壳双层检测的完整解"。设备上没有现成加固壳样本，故自建检测样本 `tests/shellwatch.c` 复现 ll 壳的两类检测，用**同一目标**对照 caoin 两条路线。

**检测样本（shellwatch）**：受管函数独占页（页内偏移 0xfe0），每轮输出：
- `crc=`：对受管页做滚动校验和（模拟代码段完整性自检）
- `exec=`/`susp=`/`memfd=`：maps 扫描——可执行映射数 / `/data/` 路径数 / `/memfd:` 映射数
- `tracer=`：读 `/proc/self/status` 的 TracerPid

**实测对比（同一目标，同一 hook 点）**：

| 路线 | CRC 自检 | exec | susp | memfd | tracer | hook 生效 |
|---|---|---|---|---|---|---|
| 基线 | `ok` | 8 | 2 | 0 | 0 | — |
| **agent（用户态 inline hook）** | **`CHANGED`** ✗ | 12 | 4 | 5 | 0 | ✓（透传） |
| **KPM shadow（stub=1）** | **`ok`** ✓ | 8 | 2 | 0 | 0 | ✓（777） |

**结论（修正原论断）**：
- **agent 的 inline hook 必然改目标代码字节 → 过不了 CRC 自检**（`crc=CHANGED`）；且 dlopen 的 agent so + trampoline 会新增 memfd/可执行/路径映射，maps 扫描能数出来。
- **KPM shadow 是 CRC 自检的正解**：读写分离（执行走 shadow、读取走原页）→ 原页字节不变 → `crc=ok`；影子页是匿名 mmap（无路径、非可执行 VMA）→ `exec/susp/memfd` 全不变。
- 所以"双层检测的完整解"= **KPM shadow 防 CRC** + （agent 只在**不触碰被自检代码**时用，且其 memfd 只解决**路径黑名单**这一种 maps 检测，**maps diff/计数仍能发现**）。
- **约束**：KPM shadow 要求受管函数独占页（本样本满足）；实战中若目标函数与大量代码同页，该路线不适用（见 P3-v4 架构约束记录）。

**未覆盖**：更强反调试（信号/时序类、ptrace 自附加、硬件断点/调试寄存器检测）未在本样本内——归入后续"更强反调试对抗"。

## 无痕 hook 闭环实测（2026-10-14 下午，独立页版全链路通过）

**[G] 悬案根因（tombstone + init 日志取证链）**：EL0 表被某条 tva fault 经 `caoin_flip_el0` 首次发现路径提前缓存（TTBR0 实测 = mm->pgd 本身，本机内核无 KPTI 副本，pte 地址与 mm->pgd walk 结果相同）→ 哨兵分支的 `!el0_pte_addr` 条件永远为假 → vfork 子进程读哨兵页的 SIGSEGV **放行给原生路径** → bionic debuggerd（crash_dump64）在子进程上跑 ~80ms——**vfork 子进程与父进程共享用户栈，debuggerd handler 把父进程的栈现场踩烂** → crash_dump 完成后子进程才死透 → 父进程唤醒，vfork 返回后几条指令内 SIGSEGV 死在 [G] 之前。取证链：init 日志 `Untracked pid <主> received signal 11`（无 crash buffer 记录 = handler 状态已坏）+ 子进程 tombstone（fault addr = sent 页，pc = sentinel_fire+36）。两轮复测时序完全一致（flip_el0 → ~80ms → 父死）。

**修复**：哨兵分支去掉 `!el0_pte_addr` 限制——目标进程的哨兵 fault **每次都必须吃掉**（flip SHADOW + cur_view 同步 + pc+=4 跳过读 + skip_origin），EL0 表发现失败也照样跳过读（宁可跷跷板不 arm，不能放 SIGSEGV 进 vfork 共享栈）。同轮顺带：主跷跷板路径加进程校验（sp_el0→task->mm==mm_run，防他进程同 VA fault 被吞/污染日志）、ec20/ec24/sent 计数器（ctl0 dump）、flt 日志 SENT 标记、restore 补 EL0 表回落、origview AP=01 注释修正（实为 EL0 RW 非 RO——dc civac 依赖它，改真 RO 会 ec=24 eret 重试永假死循环）。

**内核死循环残渣（已修复，2026-10-14 晚）**：此前 KPM 运行过的系统在目标进程退出后出现 `Bad rss-counter` / `Bad page state(swapper)`，后续无关进程陷入内核态死循环（stime 100%、root SIGKILL 杀不死，只能重启；重启后同一二进制正常——实证非代码问题而是内核残渣）。**根因 = 目标退出时 PTE 停在 SHADOW（PFN=shadow anon 页），exit_mmap 的 zap_pte_range 按错误物理页释放 → shadow 页双重 unmap + rss 记账错位 → 坏页流入后续分配。**修复（wxshadow 同款伴侣钩子）：① exit_mmap before hook——目标 mm 退出时 zap 之前恢复原 PTE（此刻 mmap_sem 未持有、mm 仍活，安全）；② restore 悬挂防护——目标已死则页表随 mm 释放，禁止写 pte_addr（防页表页复用后的随机内存写）；③ 找不到 exit_mmap 或 hook 失败则拒绝 arm。**验证：3×(load→515→SIGKILL→unload) 压力循环，Bad page state / Bad rss-counter 全程 0 条（修复前每轮必现），load average 0.19，新进程可被 SIGKILL 正常终止（死循环消除的直接证据）。**已知残留边界：低内存下文件页回收（try_to_unmap）zap 翻转态 PTE 的窗口未钩（8GB 测试机未触发）；fork 复制翻转页表的防护（wxshadow 的 copy_process pause/resume）未做——ll 壳实战前需补。

**[F] 后父进程死（verbose 必现 bug，同日修复）**：status=5（locate 完成）即唤醒目标，它立刻 [F]/vfork/读哨兵；verbose=1 时 init 的 mm[] 转储 printk 把 5→7 窗口拉到 0.9ms，哨兵 fault 抢在 vbar_on=1 之前到达 → hook 放行 → 子死 → debuggerd 踩 vfork 共享栈 → 父死（verbose=0 时窗口 μs 级，此前闭环靠时序运气）。修复：KPM 哨兵分支提到 vbar_on 门之前（mm_run/shadow_pte_val 未就绪时只跳过读+吞 SIGSEGV，不 flip）；tdyn4 忙等收紧为 status>=6（arm 完成才动）。

## 内核态注入（2026-10-14 深夜闭环，ptrace 注入器退役）

**全链路**：tdyn4 第 3 轮主循环写 status=0xCA0F0002（注入请求；外部亦可经 /proc/pid/mem 直写，见 poke64 工具）→ KPM 在目标 fault 上下文（current = 目标线程，do_page_fault 入口 mmap_sem 未持有）探测命中 → `filp_open(payload.bin)` + `vm_mmap` 固定基址 0x7f00000000（文件映射 R|X，正规 vma，页账内核托管）→ 劫持 `regs->pc` 跳 entry（x0=status 页 / x1=原 PC）→ skip_origin 吞掉本次 fault → payload 写 magic 0xCA0FCA0F 回 status → `br x1` 原线程无缝续命。**零 ptrace/零信号/零 TracerPid/零停止态；payload 固定基址 16 字节（movz/movk/str/br）。实测：注入后 515/crc 持续稳定、unload 干净恢复、Bad page/rss 0 条、全程静音无日志。**

**踩坑实录（每个独立成立）**：
- **EL1 probe 读用户 VA 禁用**：KP 的 probe 实现从无关进程上下文读他人用户地址会弄脏 CPU 的 user-access 状态——真机实证随后该核上无关进程（wifi HAL）usercopy BUG panic。status 页读取一律走内核线性映射（cfg_e2 = 页 PFN，init 自推导）
- **dc civac 无 exception fixup**：`caoin_write_status` 旧版 probe_read EFAULT 后仍无条件 `dc civac slot`——slot 无效即 panic（多次 load 随机崩的根因）。防御：probe_read 成功（slot 可翻译）才允许写 + civac
- **探测块必须在跷跷板状态机之前**：目标自身 fault 全被 handled 短路 return，探测放后面永远不在目标上下文执行；放前面命中即发射，被吞的跷跷板 fault 由 payload 返回后重试自然恢复
- **nostdlib 下禁用一切 bionic 调用**：`-e main` 跳过 bionic 初始化，libc 函数（open/pwrite 内部碰 TLS/errno）必崩——工具类程序用纯 svc（poke64：openat/write/pwrite64/exit 四个 syscall 零符号）
- **mksh 算术 32 位**：`$((0x629c776028))` 溢出为负，dd seek 大地址必炸——大地址写入用 poke64
- 已知边界：MAP_FIXED 0x7f00000000 假设高端空隙（39 位 VA 上限 512GB 内），实战目标先读 maps 确认；payload 目前是验证桩，P2 agent 的完整功能（符号解析/写 trampoline）需按固定基址约定重编后由同通道加载

## 记录+透传桩（2026-10-15 凌晨，真机验证通过）

**桩升级为真实 hook 语义**：KPM 安装时（1）把原函数指令从 tva 线性地址拷到影子页 +0x800 scratch；（2）在受管函数偏移处写序言——x16=报告地址(shva+0xF00)，str x0..x3 → 报告区，b scratch。执行流：调用进桩（SHADOW 可执行，无 fault 依赖）→ 记录 x0-x3 → b 同页 scratch 跑原逻辑 → 原函数自身 ret 返回调用者。**实测：t(5)=88 / t2(5)=30 真实返回值稳定输出，crc_ok=1，target 存活**——hook 从"替换返回值"升级为"参数观察 + 原逻辑透传"。
限制：scratch 内 PC 相对指令（adrp/b/bl）未重定位（目标函数须寄存器运算型）；真实场景接 P2 reloc.c。

**状态修正（03:20 取证）**：88/30"透传值"实为**基线巧合**——88 是 caoin_target 真实返回值，recstub 版实际 **install 后目标卡死 → SIGSEGV 未通过**。crash 取证：`SEGV_MAPERR fault=0xd at caoin_target+0x14`，**x16=shva+0xF00 报告地址装载正确**（序言前 4 条 movz/movk 在跑），但执行流随后在 tva+0x14 解引用 0xd（x16=5 = fp(5) 残留值 +8）——**CPU 取指到的是 shadow 页旧内容（快照/515 桩），新序言后半未生效**；DUMP=0 = install 后 fault hook 彻底静默。头号嫌疑：**目标线程 eret 后被调度迁移到另一核，`ic ivau` 只失效执行核的 I-cache，跨核陈旧指令行未失效**（777 版两指令桩能跑 = 碰巧同核/恰好命中新行）。**已修复（12:5x，ic iallu）**：逐行 `ic ivau` 只失效对应行，行内陈旧混合仍会取指到旧字节（pc=shadow+0x18 处 crash far=魔数——恰好是上一轮桩长度覆盖不到的位置）。修复 = install 尾部加 `ic iallu`（本核全量 I-cache 失效；install 核 = 目标 fault 核，eret 后目标就在本核执行，全量失效足够）+ 自旋排空。**修复后 minstore 桩全通**：双 hook 777/778 稳定、cap 报告区布局正确、unload 恢复、无 Bad page、进程存活。记录+透传桩（参数捕获+原逻辑透传）与替换桩双形态可用。

**最小闭环实验结果（03:4x-04:4x，minstore 8 条桩）**：store 类桩实测**不可行**——
install 后目标 crash，fault far = **魔数本身被当指令地址**（pc 飞到 0xca0fca51），
指令级推演对不齐（x16/x17 dump 正确、所有候选指令的 far 都不该是魔数）→
判定 CPU 执行的字节流与 KPM 写入的字节流不一致（跨核 I-cache 行内部分陈旧），
且 install 后 fault hook 彻底静默 + 引发内核残渣（load 52、Bad page x2、
adb offline 需人工恢复）。**工程决断：minstore/recstub 代码保留（stub_mode）
但默认 stub_mode=0（777 替换桩，已证可靠）**；参数观察型 hook（需要断点语义）
归入 P3-v5，正确工具是硬件断点（参考 kern/Hook 的 hw_hook：绕 perf 直写
DBGBVR/BCR + hook do_breakpoint）或 UXN 页异常（对方 UXN_abort 的全页重编译），
而不是影子页内嵌桩。**caoin 的"改返回值"型 hook 语义在 777 桩上已完整闭环。**

## agent 注入集成（2026-10-14 深夜闭环 → 10-15 定稿）

payload v3（真 agent 雏形：读 tva/shva → 生成 777 桩写 shadow 页 → cache 维护 → 完成标记）+ 调用约定改为 KPM 寄存器直传（x4=tva/x5=shva——status 页内存约定废弃：+0x100 处散布 g_pagemap_diag/g_sent_va/g_code_va 等全局，内存块写会被 page_pa() 等覆写，payload 读到的是全局值而非 CFG，CRC 假阳性也是同源）。注入请求协议补全：KPM 探测命中后先消费（清零+civac）再发射——请求残留导致每个 fault 重新注入死循环。

**当前卡点（未破，PC 落地已证实）**：inj_trace 追踪（劫持后 12 次 fault 全量记录）证明 **regs->pc 修改真实落地**——劫持后出现 `pc=7f00000000 esr=82000005`（取指 translation L1 fault，页表未建）。已修：GUP 预填充（初版带 FOLL_WRITE 对 R|X vma 直接 EFAULT——读语义才对）；已加 icache 同步。修后 0x7f 取指 fault 消失（PTE 已建）但 payload 仍未执行（str 无效果），且 br 回原 PC 的取指 fault 未见于 trc、目标卡死在注入点（用户态 100% utime、无 fault、无输出）。疑点集中：劫持吞掉的 fault 状态机未跑（cur_view 未变），eret 后的执行/重试与跷跷板状态机的交互未理清。下一轮：① trc 只过滤目标进程 fault + 加大窗口（64 条），看 payload br 回后的取指 fault 究竟是否存在；② 或劫持时先走完状态机再劫持（顺序：fault_check 处理 → 劫持），消除"吞状态机"变量；③ payload 先落 shadow 页尾部（KPM 已知良好可执行内存）隔离目标地址变量。

**后续排查轮（同日晚）**：①②③已做——②劫持挪到 handled 块内（状态机先处理再劫持，eret 时视图已切）；③ payload 改为**匿名 RWX 页 + 内核 copy_to_user 写入 + 手工 dc cvau/ic ivau**（文件映射执行的 page cache/GUP/icache 变量全部消除，payload 字节数组直接嵌入 KPM）。**新破两案**：④ 4.9 arm64 的 `copy_to_user` 无 kallsyms 符号（静态包装），真身是 `__arch_copy_to_user`——解析失败致 inject_try 静默 return（无日志盲区，解析失败现已加 CK_ERR）；⑤ 跨核消费写（probe_write 清零 + civac）会被目标核的脏行写回覆盖（MESI），消费不可靠——改为 `inj_done` 单次标记（实例生命周期只注入一次），无 cache 竞争。**仍未破**：hijack 发生（trc 证实 inj_trace 置位）、RWX 页就绪（maps 可见 rwxp）、copy_to_user 成功（无 copy fail），但 payload 的 store 依旧无效果，且 hijack 后目标 br 回的取指 fault 未见于 trc 窗口（窗口被杂散 fault 消耗是取证缺陷）。下一轮：trc 改为只记录目标进程（is_target_proc）的 fault + 窗口 64 条；payload 入口加"存在证明"store 到 INJ_BASE 页自身（+0xFF8），KPM 侧 GUP 后直接读物理页验证——把"执行"与"可见性"两个变量彻底分开。

**存在证明轮结果（次日凌晨，10+ 轮实验，证据链完整）**：
- **I-cache 根因修复（已确认生效）**：copy_to_user 只清 D-cache 不清 I-cache，eret 取指命中注入页陈旧 I-cache 行。修复 = 对注入页物理帧的**内核线性地址**做 dc cvau/ic ivau（I-cache PIPT，对同物理帧任意 VA 操作等效；用户 VA 直接操作在 SW_TTBR0_PAN 下 fault）。修复后 **INJFLT pc=7f00000028 出现 = payload 真实开始执行**（重大突破）
- **寄存器参数不穿透（已证实）**：payload 从 x24(shva) 读到垃圾值 5 → far=5 取指 fault（0xCA0FCA00 状态标记也未见）。skip_origin=1 与 callee-saved x19-x24 均不穿透
- **参数块自页传递已部署**（payload v7：KPM copy_to_user 后往 +0x7F0 写 status/ret_pc/tva/shva 四参数，payload 用固定基址绝对寻址自读）——尚未验证到参数读取点
- **已修复（最终形态）**：**放弃 pc 劫持**——方案B panic 反证劫持链路全通（"Attempting to execute userspace memory"，CPU 确实跳进注入页），但 arm64 PAN 禁止内核执行用户页；且 pc 劫持在内核路径上制造 EL1 取指 abort 并卡死目标。**最终形态 = 内核侧直装**：注入请求探测命中后，KPM 在目标线程上下文（current 已验证）经页表 walk 取 shva 物理帧 → **内核线性地址直接写 777 桩** → dc cvau/ic ivau（线性地址，PIPT 等效）→ status=完成标记。**不碰 regs->pc、不 skip_origin**——当前 fault 交还原生流程，eret 后目标自然恢复，下一轮 fp(5) 走新桩返回 777。实测：777 稳定输出、crc_ok=1、unload 恢复 88、无 Bad page、设备无恙。**内核态注入全链路闭环。**

**根因链复盘（payload 执行丢失悬案）**：① I-cache 根因——copy_to_user 只清 D-cache，eret 取指命中注入页陈旧 I-cache 行（修复=对物理帧内核线性地址做 cache 维护，I-cache PIPT 等效），修复后 INJFLT pc=7f28 证明 payload 真实执行；② 寄存器参数不穿透——payload 从 x24 读到垃圾（do_page_fault 返回路径改写），改自页参数块仍未达（pc 劫持的 EL1 abort 先卡死）；③ 放弃劫持后 ①的 cache 维护方法沿用至 shva 桩写入，问题消失。技术储备保留：INJ_BASE 匿名 RWX + copy_to_user + I-cache 修复在"需要注入可执行代码进用户空间"场景仍然有效。

## 代码审计（2026-10-14 晚，0.4.1）

**KPM（caoin_kpm.c，现 ~700 行）**：删除全部 VBAR 路线死代码（向量表/el0_entry asm、slot_tab、广播三函数、unused 符号解析，约 230 行）；kernel_read 调用 &pos 的"修正"实为踩雷（见下）；ctl0 dump 字段名 vbar→armed；头注释重写为当前架构。**重要移除：cfg_from_file 整体删除**——踩坑实录：0.4.0 起 kpm load 必现内核 panic（pstore：fault = .bss 地址 + 2^44，PC 落在 cfg_from_file 的逐字节扫描循环；两次开机/两种参数均复现；禁用该函数后同环境全绿）——疑为 KP loader（kp_malloc_exec 非页对齐分配）在特定模块基址下 ADRP/重定位错位，与模块体积变小后落入的分配桶相关。该函数本就冗余（运行脚本从 tdyn4.out 解析后传 args）且历史上有 kernel_read 挂死记录，args 成为唯一配置来源。**教训：对 KPM 的任何结构性删改后，load 必须先做 dummy-args 烟雾测试（panic 即重启）。**

**tdyn4（tests/target_dyn.c）**：删死代码（shadow_handler/out2_str/g_shadow_ret_off/nanosleep 声明/_start 永不可达的第二循环）；新增 raw wait4(260) 收尸哨兵子进程——进程表不再留 [tdyn4] zombie 条目（无痕清单再减一项）。回归实测：515/crc_ok 正常、ZOMBIE=0、SIGKILL→unload→Bad page/rss 0 条、系统 load 正常。

**审计确认安全（推演论证，注释已固化进代码）**：exit_mmap 钩子与 fault 翻转无并发竞态（exit_mmap 仅最后一个线程退出时触发，其余线程已死不再 fault）；哨兵分支双入口（vbar_on 前/后）校验次序；EL0 表与 mm->pgd 不同表的机器上哨兵未 fire 时 restore 无法回落 EL0 表——KPTI 副本机型实战前的待办。

**闭环实测数据（shell 域，tdyn4 独立页版；桩 = movz 515 验证桩，agent 写真实 trampoline 到 shadow 页的集成另列 P3-v3）**：
- `[G]` 出现，`caoin_target(5)=515`（原函数 88）稳定输出，`crc_ok=1` 全程，主循环持续；哨兵子进程 `_exit` 成 zombie（父不 wait，正常）
- 无痕验证：/proc/modules、/proc/kallsyms、/sys/module 零痕迹；maps 无新映射（shadow 页 = 目标自 mmap 的匿名页）；**跨进程 root 读 /proc/pid/mem（GUP），hooked 与 unload 后内容 md5 一致**——桩字节零泄漏；unload 干净恢复（status=0xF，t5 回 88，进程存活）
- GUP 读恒拿原页的机制性原因：任何非 hook 路径的 fault（含 GUP 的 faultin_page）走 handle_mm_fault → ptep_set_access_flags 按 vma 权限（r-xp）修复 PTE 回原页；EL0 执行 fault 再由 do_page_fault hook 翻回 SHADOW——跷跷板自愈
- 当前可见痕迹（0.3.0 静音版）：默认 dmesg **零** caoin-kpm 输出（错误路径 CK_ERR 常打、流程日志走 `verbose=1`、ctl0 dump 不受门控）；次级小痕迹：哨兵子进程 zombie 条目（测试目标未 wait，模块无关）。静音版实测：加载/hook(515)/unload(88) 全通，dmesg grep caoin-kpm = 0

## P3 内核换页（caoin_ko/，v1 已通）

**幽灵模块路线**（无需精确源码树）：
- 模块零内核符号引用：`find_task_by_vpid`/`probe_kernel_read`/`printk` 地址经 cfg 二进制注入（marker 定位 + patch_cfg.py），vermagic 构建期配平（基座树改 SUBLEVEL=337 + CONFIG_LOCALVERSION）
- 运行时结构偏移探测：`probe_kernel_read` 安全读 + pagemap 真值判据（expect_phys），task->mm/mm->pgd 偏移自动锁定（本机 0x5c8/0x48）
- 换页：只换 PTE 物理页号保留属性位 + 内联 `tlbi` flush；rmmod 恢复原 PTE

**本 ROM 内核特殊性（踩坑实录）**：39 位 VA / 3 级页表（PAGE_OFFSET=0xffffffc000000000，基座树 48 位完全不同）；slab/task_struct 在 vmalloc 区（0xffffffca...）；两次 panic 教训（未 patch 空指针、结构偏移裸解引用）→ 全路径安全读。

v1 = 换页版（执行与读取同走 shadow 页）；v2 读写分离后，配合 agent 的 memfd 加载即为对 ll 壳双层检测的完整解。

## v2b 真机实测（2026-10-13，MI 8 Pro / equuleus 4.9.337 / Android 13）

**已闭环**：
- 模块加载 → PTE 定位（probe walk + pagemap 双判据）→ PTE 换 shadow 视图（--x）→ VBAR 换表 → **自隐藏**（init 尾部 kobject_del + list_del，地址全走 cfg 注入）全通
- **解隐藏**：目标进程 status 页写 `0xCA0F0001` → 模块内 timer_list（地址 cfg 注入）每秒轮询 → list_add 挂回原位（保存的 list.prev，不引用 modules 符号）→ rmmod 正常。`/proc/pid/mem` 写 status 页即可远控
- 内核触碰面：一次 `msr vbar_el1` + 目标进程 PTE 读写 + 一次 kobject_del，零内核符号引用（仅工具链固有 3 个：__stack_chk_fail/__stack_chk_guard/memstart_addr）

**当前卡点（已定位，架构级）**：`apd insmod`（folkpatch 官方 LKM 加载后门，顺带解开间歇 EPERM 之谜）加载全绿后目标进程假死，sysrq 全核回溯铁证：fault 走 `el0_da → do_page_fault → handle_mm_fault → ptep_set_access_flags`——**异常从未进入我们的向量表**。已修掉的两个真 bug：① `tlbi vae1is` 只刷当前 ASID（改 vaae1is）；② VBAR 是 per-CPU（on_each_cpu/smp_call_function 全核广播，cfg 注入地址）。广播确认执行后 fault 仍走旧表 → **VBAR 被恢复**（嫌疑：cpuidle 的 cpu_resume 从 cpu_context 恢复旧 VBAR，或 folkpatch pathhide 主动保护向量表）。**结论：per-CPU VBAR 换表敌不过 idle 恢复/KP 自保护，LKM 路线到此为止；正解 = KPM 内用 KP hook 框架挂 do_page_fault（wxshadow 同款），但需重刷 stock KP kpimg（folkpatch 的 kpimg 无 KPM 支持，kpm load supercall = 255）。caoin_kpm.c 已备好待换 kpimg。另发现：内核 do_page_fault 的 ptep_set_access_flags 会持续覆写 shadow PTE，KPM 版必须在 do_page_fault hook 里抢在 handle_mm_fault 之前接管 fault（wxshadow 同款）。**
注意：**rmmod 前必须先 kill 卡死的目标**——目标核还在向量表处理中时卸载模块（释放 .text）→ panic。另：目标进程死亡后 unhide 永久失效（tick 轮询走目标 mm），需加 fail-safe（walk 连续失败 N 次 → 自动 list_add 挂回）。

**踩坑实录（新增）**：
- **本树 `init_timer_key` 是 4 参定制版**（timer, flags, name, key，无 func）——按 mainline 5 参调用 → function 未赋值 → `mod_timer` BUG_ON (timer.c:958) → panic。function 需单独赋值
- **patch_cfg2b.py 参数顺序**：struct 里 find_task/probe_read/printk 在前、status_phys 在后（status_phys 不在 sva 和 find_task 之间）。参数顺序写反 → find_task 槽装进 status_phys → init 直接 BLR 到物理地址 → Oops（pstore 定位 `pc=<status_phys>`）。pid 收 `0x` 格式防手算换基错误
- **用户态写代码页后必须 cache 维护**：逐行 `dc cvau` + `ic ivau` + dsb/isb。漏做则换视图后取指拿到 RAM 陈旧内容（脏行未写回）→ 执行垃圾指令。**`ic iallu` 在 EL0 非法**（UCI 不放行 IC IALLU）→ SIGILL
- **模块名 ≠ 设备文件名**：/proc/modules、/sys/module、kallsyms 用 .ko 内部名（shadow_v2b），insmod 成不同文件名不改变名字——排查时按内部名 grep
- **KASLR 开启**：每次开机 slide 不同，符号地址只能开机后从 /proc/kallsyms 取。kptr_restrict=2 且 sysctl 写入被 MIUI 加固：需 Permissive + dd 写（echo > 重定向会 EPERM），且 folkpatch 守护起来之前写不进——开机后要等/重试
- **panic 取证走 pstore**：/sys/fs/pstore/dmesg-ramoops-*（各 CPU PC、Kernel Offset 全在）；adb 会周期性假死（kill adb 进程重启 daemon 即可，别误判成设备翻车）

**wxshadow 对照**（F:\work\tmp\mkpms，KP 生态）：机制同源（用户态代码页 shadow、读 fault 切原页、执行走 shadow），但它是 KPM——需要 KP patched 内核（本测试机未装，insmod 幽灵模块路线不需要）；其 per-page 全局翻转 + STEPPING 忙等（retry 10000）可对照；其 GUP（follow_page_pte）/fork（copy_process）/exit_mmap 伴侣钩子是 v2b 缺的，后续移植参考。

## KPM 线真机实测（2026-10-14，folkpatch / Android 13）

**folkpatch 实测有完整 KP（kpatch su 通道可用，superkey=su），KPM 线复活——走 KP 官方通道 hook do_page_fault，无 KP hook panic（对比 LKM stop_machine 直写 text 被 KP 反篡改打死）。**

**已闭环（caoin_kpm.c，mkpms/kpms/caoin/）**：
- KPM 加载/卸载/CTL 全通（`kpatch su kpm load csh.kpm`）
- CFG 文件解析（kernel_read legacy 签名）→ locate（task->mm=0x5c8 / mm->pgd=0x48 偏移探测）→ PTE 推导全绿
- SHADOW PTE 翻转（pagemap 实证 PFN=shadow）
- **哨兵机制**：tdyn 忙等 status（KPM 写 status 页）→ vfork 子读 PROT_NONE 哨兵页 → fault 进 hook → 读 TTBR0（EL0 表）→ flip SHADOW + `regs->pc += 4` 跳过读指令 + skip_origin → **进程不死，跷跷板接管**
- **跷跷板交替成功**（vmalle1is 版实测）：`v=1 ec=24（SHADOW 数据 fault→切 STEP）↔ v=2 ec=20（STEP 取指 fault→切 SHADOW）`高频交替，无死循环无崩溃

**本轮五大根因修复（每个都是独立踩坑）**：
1. **PTE 写入必须 `dc civac` 落内存**：硬件页表 walk 不走 D-cache，内核 cacheable VA 写 PTE 只进 cache 行——`want=back` 回读一致是假象（同一 cache 行），MMU walk 读到的是内存旧 PTE。**这是 v2e 时代 tva_faults=0 的最终根因**（wxshadow 的 `wxshadow_flush_kern_dcache_area` 同款机制）
2. **TLBI 指令选型**：vaae1is（正确 VA 编码）在 fault 处理上下文无效（活锁）；**alle1is 会 panic**（pstore：`undefined instruction`=执行全零指令，清全局项毁了 KP trampoline 映射）；**vmalle1is（内核 local_flush_tlb_all 同款）有效且不崩**——清当前 VMID 全 ASID 非全局项
3. **WnR 位陷阱**：DC CIVAC 等 cache 维护指令 fault 时 ESR bit6（WnR）=1，SHADOW 分支按"非读放行"会把 CIVAC fault 落进原生路径卡死——SHADOW 视图下任何 ec=0x24 都该切 STEP（ORIG 页全权限，eret 重试必成）
4. **status 页写入同样要 dc civac**：否则 EL0 读到 cache 旧行（tdyn 忙等永不退出）；写后 EL0 可见
5. **printk 风暴**：活锁时 fault 每秒百万次，每次 printk 拖垮串口/adb——flt 日志必须限速（总数封顶）

**测试目标（tests/target_dyn.c）**：忙转代替 sleep（防 idle 丢 VBAR）+ 直返桩（movz w0,#515; ret）+ status 页握手 + 哨兵页（vfork 子读 PROT_NONE）+ **caoin_target 独占 4K 页**（section(".target.text") + aligned(4096) + fill 占满——主循环代码与 code 页同页时，CRC 读指令"自身可执行"与"读 tva 必 fault"互斥 → SHADOW/STEP 死锁对峙，独立页后闭环）

**当前剩余卡点**：独立页版已部署，实测 fault 链路已触发到主循环 CRC 读（flt#30 far=tva+0x110），但 [G]（哨兵 vfork 父恢复）未出现、515 输出未达——怀疑点：STEP 分支新加的 ec=24 重试对哨兵页二次 fault 的放行路径 / vfork 父子恢复时序。待下一轮定位。

## 注意

- **本目录在博客仓库内，暂不推送**。开源前必须明确决策——源码公开 = 字节模式进特征库，核心优势归零
- 测试机专用：KPM 翻车 = kernel panic，不碰日常机
- 参考实现：wxshadow（KPM 侧）、Dobby（重定位逻辑对照）
