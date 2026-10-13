# caoin

Android arm64 无痕 hook 工具。目标：低特征自研方案，替代对 frida 等公开工具的依赖。

## 架构

| 层 | 内容 | 来源 |
|---|---|---|
| 内核层 | KernelPatch + wxshadow KPM：shadow 页读写分离（执行走 shadow、读取走 original），过代码段 CRC 自检 | 现成，不重造 |
| hook 层 | ARM64 inline hook 原语：16 字节跳转桩（`LDR X16,#8; BR X16; addr`）+ PC 相对指令重定位（B/BL、ADR/ADRP、CBZ/TBZ、LDR literal），写入走 wxshadow 接口 | 自研，核心几百行 |
| 用户层 | agent：ptrace 注入、无驻留线程/端口、事件文件回传、可 detach；CLI：目标机上直接跑，attach / maps 基址 / 符号解析（strip so 支持 IDA map 导入） | 自研 |

回传不走 socket、agent 静态编译 musl + strip：特征值不公开是本工具的核心优势。

## 用法（用户态，P2 已全通）

```
# 构建（WSL aarch64 交叉环境，需先把设备 libc.so 拉到 build/libc_bionic.so）
bash build.sh

# 设备上注入（root）：
caoin_inject <pid> <agent.so> "<mod 或 @=主程序>|<symbol 或 0xoff>[|ret=0xhex]"

# 例：
caoin_inject 1234 /data/local/tmp/caoin_agent.so "@|caoin_target|ret=0x100"  # 改返回值
caoin_inject 1234 /data/local/tmp/caoin_agent.so "libc.so|write"             # 透传+记录参数流
caoin_inject 1234 /data/local/tmp/caoin_agent.so "libxxx.so|0x12345"         # strip so 偏移模式
caoin_inject 1234 /data/local/tmp/caoin_agent.so "libc.so|write|s1;m1=16"    # dump 字符串+16字节内存
```

日志：`/data/local/tmp/caoin_log_<pid>`（每条 hook 记录 x0-x7、dump、ret）。
agent 零 UND（no-libc + `-fno-builtin`），config 经 `/data/local/tmp/caoin_config`（支持多行多 hook 点）。

## Java 层下沉（DoCall 路线）

hook `libart.so` 导出的 `art::interpreter::DoCall` 四个模板实例（quick 桩 art_quick_* 是 hidden 不导出）。x0=ArtMethod*、x5=返回值出口，不改任何 ArtMethod：

```
# 例：hook DoCall<false,false>（invoke-virtual/special），只跟踪指定 ArtMethod：
libart.so|_ZN3art11interpreter6DoCallILb0ELb0EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE|if0=0x<ArtMethod*>;m0=32
```

实测（Android 13，untrusted_app 域）：libart 代码段可 mprotect 可 hook、热路径稳定；ArtMethod 32 字节结构 dump 可解码（method_index/entry_point）。
**覆盖边界**：AOT/JIT 编译的热方法不走 DoCall（纯解释执行方法才经过）；稳态 Flutter app 的 Java 层近乎零流量。全调用覆盖需另配 ArtMethod 入口方案。

## 权限地形（本机 ROM 实测）

| 域 | 匿名 RWX | memfd 双映射 | mprotect 系统库代码段 |
|---|---|---|---|
| shell | ✓ | ✓ | ✓ |
| untrusted_app | ✓ | ✓ | ✓（libart 可改） |
| system（settings 等） | ✗ | ✗ | 未知（分配先行失败） |

trampoline 默认 memfd 双映射（W^X），失败回退匿名 RWX；同函数重复 hook 会因入口已桩化（含 LDR literal → 就近分配约束）而失败，属可识别行为。

## app 进程注入注意

linker 不拦 /data/local/tmp 的 so；app 域对该目录无写权限，回传文件由 injector 预建 + chmod 666。同一 so 重复 dlopen 不重跑 constructor（linker 引用计数语义），重配 hook 点换 so 文件名。app 进程 maps 可达数百 KB，agent 侧已 512KB 循环读。

## 路线

- [x] **P0**：内核模块可加载性确认（equuleus 4.9：CONFIG_MODULES=y, modules_disabled=0）
- [x] **P1**：inline hook 原语（B/BL、ADR/ADRP 正负偏移、CBZ/TBZ、LDR literal；主机单测 + 真机 ALU/ADRP 序言双验证）
- [x] **P2**：注入器（ptrace + 远程 __loader_dlopen + memfd 隐匿加载）+ agent（零依赖自解析）+ CLI 配置化——真机三组行为级验证全过
- [x] **P3-v1**：内核换页 hook（幽灵模块路线，见下）
- [~] **P3-v2**：X-only 权限 + fault 跷跷板（读写分离：校验读原页，执行走桩页）——v2b VBAR 路线：模块加载/自隐藏/解隐藏/PTE 换页/VBAR 切换全通，**hook 跷跷板有 livelock 待解**（见 v2b 实测记录）
- [ ] 后置：Java 层下沉的 ArtMethod 全覆盖；app 进程注入实战（ll 壳对抗）

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

**当前卡点（livelock）**：insmod 后目标进程冻结——R 态、stime 持续增长、status 页实测已被模块写为 0x8 但进程不再输出；filter 零 reject（所有 fault 均 handled），即"处理→eret→重 fault"死循环。flt# 采样版（前 30 次 fault 打印 v/ec/dfsc/far）已编译待真机验证。注意：**rmmod 前必须先 kill 卡死的目标**——目标核还在向量表处理中时卸载模块（释放 .text）→ panic。

**踩坑实录（新增）**：
- **本树 `init_timer_key` 是 4 参定制版**（timer, flags, name, key，无 func）——按 mainline 5 参调用 → function 未赋值 → `mod_timer` BUG_ON (timer.c:958) → panic。function 需单独赋值
- **patch_cfg2b.py 参数顺序**：struct 里 find_task/probe_read/printk 在前、status_phys 在后（status_phys 不在 sva 和 find_task 之间）。参数顺序写反 → find_task 槽装进 status_phys → init 直接 BLR 到物理地址 → Oops（pstore 定位 `pc=<status_phys>`）。pid 收 `0x` 格式防手算换基错误
- **用户态写代码页后必须 cache 维护**：逐行 `dc cvau` + `ic ivau` + dsb/isb。漏做则换视图后取指拿到 RAM 陈旧内容（脏行未写回）→ 执行垃圾指令。**`ic iallu` 在 EL0 非法**（UCI 不放行 IC IALLU）→ SIGILL
- **模块名 ≠ 设备文件名**：/proc/modules、/sys/module、kallsyms 用 .ko 内部名（shadow_v2b），insmod 成不同文件名不改变名字——排查时按内部名 grep
- **KASLR 开启**：每次开机 slide 不同，符号地址只能开机后从 /proc/kallsyms 取。kptr_restrict=2 且 sysctl 写入被 MIUI 加固：需 Permissive + dd 写（echo > 重定向会 EPERM），且 folkpatch 守护起来之前写不进——开机后要等/重试
- **panic 取证走 pstore**：/sys/fs/pstore/dmesg-ramoops-*（各 CPU PC、Kernel Offset 全在）；adb 会周期性假死（kill adb 进程重启 daemon 即可，别误判成设备翻车）

**wxshadow 对照**（F:\work\tmp\mkpms，KP 生态）：机制同源（用户态代码页 shadow、读 fault 切原页、执行走 shadow），但它是 KPM——需要 KP patched 内核（本测试机未装，insmod 幽灵模块路线不需要）；其 per-page 全局翻转 + STEPPING 忙等（retry 10000）可对照；其 GUP（follow_page_pte）/fork（copy_process）/exit_mmap 伴侣钩子是 v2b 缺的，后续移植参考。

## 注意

- **本目录在博客仓库内，暂不推送**。开源前必须明确决策——源码公开 = 字节模式进特征库，核心优势归零
- 测试机专用：KPM 翻车 = kernel panic，不碰日常机
- 参考实现：wxshadow（KPM 侧）、Dobby（重定位逻辑对照）
