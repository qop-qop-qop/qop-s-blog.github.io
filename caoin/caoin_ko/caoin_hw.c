/* SPDX-License-Identifier: GPL-2.0 */
/*
 * caoin-hw — P3-v5 参数观察型 hook（硬件断点路线，P3-v5）
 *
 * 思路借鉴 git.colorsky.fun/kern/Hook 的 hw_hook（GPL-3.0，本文重写，
 * 不拷贝其代码）：绕过 perf_event 直写 DBGBVR/BCR/WVR/WCR，自己接管
 * 断点异常。内核里不产生 perf_event、不碰 thread_struct.debug、
 * 不占 bp_on_reg[]——软件痕迹只剩本模块自己的注册表与 DBG 寄存器本身。
 *
 * 与参考实现的关键差异（caoin 语境）：
 *  - 目标内核 4.9.337（无 do_breakpoint/do_watchpoint 全局符号），异常
 *    入口走 4.9 的 static handler：brk_handler / single_step_handler /
 *    watchpoint_handler（kallsyms 可查，wxshadow 已实证前两者存在）。
 *    6.x 的 do_breakpoint/do_watchpoint/try_step_suspended_breakpoints
 *    保留为优先探测项，与参考实现同序。
 *  - 4.9 单步恢复没有 try_step_suspended_breakpoints：hook
 *    single_step_handler，命中我们的 step 记录时 skip_origin 并重武装
 *    断点槽（返回 DBG_HOOK_HANDLED 语义 = skip_origin + ret 0）。
 *  - pt_regs 参数位置不能用 BTF（4.9 无 BTF），按 4.9 签名硬编码：
 *    brk_handler(u32 esr, regs)? — 实际 4.9 原型 brk_handler(unsigned long
 *    unused, unsigned int esr, struct pt_regs *regs)（与 wxshadow 的
 *    brk_handler_before arg1=esr/arg2=regs 一致，真机已验证）。
 *  - 控制通道：KPM_CTL0 字符串命令（与 caoin-shadow 同款），不走 auth
 *    二进制 syscall——caoin 现阶段单一 superkey 即够，少一层依赖。
 *  - 与 caoin-shadow（跷跷板）互补：断点 = 改寄存器/观察参数（不动页表
 *    不动内存字节，CRC/mem 双无痕）；跷跷板 = 改执行流。两者不共存于
 *    同一加载实例（本模块独立 load/unload）。
 *
 * 单步恢复协议（关键，参考实现的教训）：
 *   命中断点 → 关槽使能 + PSTATE.SS|MDSCR.SS → eret 执行原指令一次 →
 *   Software Step 异常 → single_step_handler hook：重开槽 + 清 MDSCR.SS +
 *   清 PSTATE.SS → skip_origin（不给用户态发 SIGTRAP）。
 *   per-CPU 槽位按 __switch_to 重装：切进 next 时清本 CPU 全部槽，
 *   再把 next->mm 命中的断点装进空闲槽（4.9 __switch_to(prev,next)，
 *   arg1=next）。
 *
 * 资源回收：不长期持有目标 mm 引用（add 时 get_task_mm 钉住、插入后
 * mmput）；exit_mmap 是 mm 销毁唯一出口，hook 它同步回收该 mm 全部
 * 记录——记录绝不比 mm 活得久，无需碰 mm_count。exit_mmap hook 失败
 * 则拒绝加载（否则死 mm 留悬空记录）。
 *
 * 控制命令（kpatch su kpm ctl0 caoin-hw "<cmd>"）：
 *   add   <pid> <addr> [xN=val ...]        执行断点（可选寄存器覆盖）
 *   addw  <pid> <addr> <len> [xN=val ...]  读写观察点（len=1/2/4/8）
 *   del   <pid> <addr>   clear <pid>   list <pid>   slots
 *   cond  <pid> <addr> <reg>=<val>         条件覆盖（不满足则只观察）
 *   uncond <pid> <addr>
 *   hit   <pid> <addr>                     最近命中寄存器快照
 *   disarm                                 全槽清零 + 停止编程（恢复现场）
 * 全部数值 16 进制（0x 前缀可省）。pid=0 表示 current。
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kallsyms.h>
#include <ktypes.h>
#include <hook.h>
#include <linux/sched.h>
#include <asm/current.h>
#include <asm/ptrace.h>

/* ---------------- 常量 ---------------- */

#define HW_MAX_BRP  16
#define HW_MAX_WRP  16
#define HW_MAX_CPU  16          /* 测试机 8 核，留倍余量 */
#define HW_MAX_BPS  16          /* 注册表容量 */

#define HW_MDSCR_SS   (1ull << 0)
#define HW_MDSCR_MDE  (1ull << 15)
#define HW_SPSR_SS    (1ull << 21)
#define HW_DFR0_BRPS_SHIFT 12
#define HW_DFR0_WRPS_SHIFT 20

#define HW_BP_EXECUTE   0
#define HW_BP_LOAD      1
#define HW_BP_STORE     2
#define HW_BP_RW        3

#define HW_BP_LEN_1 0x1
#define HW_BP_LEN_2 0x3
#define HW_BP_LEN_4 0xf
#define HW_BP_LEN_8 0xff

#define HW_REG_SP      31
#define HW_REG_PC      32
#define HW_REG_PSTATE  33
#define HW_REG_NUM     34

#define HW_GFP_KERNEL  0xcc0u   /* GFP_KERNEL，kallsyms 版本无关 */

/* ESR EC 调试事件（bits[31:26]）：0x6=BRK 由 brk_handler 收，硬件断点/
 * 单步/观察点是 EC 0x30~0x32 由 debug_exception 入口分发；4.9 的
 * brk_handler 只收 EC=0x06。硬件断点异常在 4.9 走 brk_handler 之前的
 * do_debug_exception→breakpoint_handler 链。断点 EC = 0x30（软件断点是
 * BRK 指令的 0x3C 由 brk_handler 处理）。watchpoint EC = 0x32，
 * single-step EC = 0x31。4.9 的 dispatch：debug_exception 先查
 * breakpoints（breakpoint_handler），再 watchpoints（watchpoint_handler），
 * single-step 走 single_step_handler。我们 hook 的是这些 handler 本体。 */
#define ESR_EVT_HWBP  0x0       /* ESR.ISS[29:27] 调试事件子类型 */
#define ESR_EVT_HWSS  0x1
#define ESR_EVT_HWWP  0x2

/* ---------------- 记录 ---------------- */

struct hw_bp {
    int used;
    u64 mm;             /* 归属 mm（无引用，exit_mmap 同步回收） */
    u32 pid;            /* 记录用途（诊断） */
    u32 kind;           /* HW_BP_EXECUTE / LOAD / STORE / RW */
    u32 len;            /* 观察点长度 */
    u64 bp_addr;        /* 用户请求地址 */
    u64 bvr;            /* 写入 DBGBVR/WVR 的对齐地址 */
    u32 bcr;            /* 编码后的控制字 */
    u64 regmask;        /* 覆盖位图（x0..x30 | SP | PSTATE） */
    u64 regs[HW_REG_NUM];
    u32 has_cond;
    u32 cond_reg;
    u64 cond_val;
    u64 hits;           /* 命中计数 */
    u64 last_regs[HW_REG_NUM];  /* 最近命中快照 */
};

static struct hw_bp g_bps[HW_MAX_BPS];
static volatile int g_lock;             /* LSE-less 自旋 */
static volatile int g_quiescing;        /* 卸载中：停止编程 */
static int g_ready;

/* 日志双档：加载/错误（pr_err/pr_info）常打；命中/武装/switch 等
 * 流程诊断默认静音（无痕优先，且每次上下文切换都打会刷爆 dmesg），
 * 用 args "verbose=1" 打开。 */
static u64 g_verbose;
#define CK_DBG(...) do { if (g_verbose) pr_info(__VA_ARGS__); } while (0)

static unsigned long g_saved_daif[HW_MAX_CPU];

static inline int hw_cpu_id(void)
{
    u64 v;
    asm volatile("mrs %0, mpidr_el1" : "=r"(v));
    /* affinity0 + affinity1*8 —— 与参考实现同款，8 核内唯一 */
    return (int)((v & 0xff) + (((v >> 8) & 0xff) * 8)) % HW_MAX_CPU;
}

static inline int hw_xchg(volatile int *p, int v)
{
    int old;
    unsigned int tmp;
    asm volatile("1:\n"
                 "ldaxr  %w0, [%2]\n"
                 "stlxr  %w1, %w3, [%2]\n"
                 "cbnz   %w1, 1b\n"
                 : "=&r"(old), "=&r"(tmp)
                 : "r"(p), "r"(v)
                 : "memory");
    return old;
}

static inline void bp_lock(void)
{
    int id = hw_cpu_id();
    asm volatile("mrs %0, daif" : "=r"(g_saved_daif[id]));
    asm volatile("msr daifset, #2");
    while (hw_xchg(&g_lock, 1))
        while (*(volatile int *)&g_lock)
            asm volatile("yield" ::: "memory");
}

static inline void bp_unlock(void)
{
    int id = hw_cpu_id();
    asm volatile("stlr %w0, [%1]" :: "r"(0), "r"(&g_lock) : "memory");
    asm volatile("msr daif, %0" :: "r"(g_saved_daif[id]) : "memory");
}

/* ---------------- 卸载：非 hotpatch 摘链 ----------------
 * hook_unwrap() 最终走 hotpatch()，正常情况选 stop_machine()（睡眠调用），
 * 而 KP 在 rcu_read_lock() 下调模块 exit() → 死锁；即便侥幸不锁死，恢复
 * 原指令的窗口也会被其他 CPU 取指命中。真机实证（pstore）：
 *   Internal error: undefined instruction: 0
 *   PC is at __switch_to+0x8/0xf0
 * ——卸载 __switch_to 时恢复窗口被别的 CPU 取到全零字节 → panic。
 * hook_unwrap_remove(..., 0) 只把链项置空（dsb，不 sleep、不恢复指令），
 * 函数保留跳 KP trampoline（空链 → tail-call 原函数），无竞态。
 * 这也是 kern/Hook 的 kp_unhook.h 采用的方案。 */
static void hw_unhook(void *func, void *before)
{
    if (func) hook_unwrap_remove(func, before, (void *)0, 0);
}

/* ---------------- 内核符号 ---------------- */

static void *(*kfn_find_task)(int);
static void (*kfn_put_task)(void *);
static u64 (*kfn_get_task_mm)(void *);
static void (*kfn_mmput)(void *);
static void *(*kfn_vmalloc)(unsigned long);
static void (*kfn_vfree)(const void *);
static int (*kfn_apv)(void *, unsigned long, void *, int, unsigned int);
static int (*kfn_on_each_cpu)(void (*)(void *), void *, int);

/* task_struct/mm_struct 偏移：KP 兼容表（folkpatch LKM 已填）+ 探针回退 */
static long off_task_mm = -1;
static long off_task_tgid = -1;

#define HW_FOLL_FORCE 0x8u

static inline u64 rd64(u64 a) { return *(volatile u64 *)a; }

static u64 hw_task_mm_of(void *task)
{
    if (!task || off_task_mm < 0) return 0;
    return rd64((u64)task + (u64)off_task_mm);
}

static u64 hw_current_mm(void) { return hw_task_mm_of((void *)current); }

static void *hw_task_by_pid(u32 pid)
{
    if (!kfn_find_task) return (void *)0;
    if (pid == 0) return (void *)current;
    return kfn_find_task((int)pid);
}

static void hw_put_task(void *task)
{
    if (task && task != (void *)current && kfn_put_task)
        kfn_put_task(task);
}

static void hw_put_mm(u64 mm)
{
    if (mm && kfn_mmput) kfn_mmput((void *)mm);
}

static int hw_read_mem(void *task, u64 addr, void *buf, int len)
{
    if (!kfn_apv || !task || !buf || len <= 0) return -1;
    return kfn_apv(task, addr, buf, len, HW_FOLL_FORCE);
}

/* ---------------- DBG 寄存器 ---------------- */

static void hw_mdscr_write(u64 v);
static void hw_debug_enable(void);
static void hw_bcr_write(int n, u64 v);
static void hw_wcr_write(int n, u64 v);

#define HW_RD_CASE(N, REG) case N: asm volatile("mrs %0, dbg" #REG #N "_el1" : "=r"(v)); break
#define HW_WR_CASE(N, REG) case N: asm volatile("msr dbg" #REG #N "_el1, %0" :: "r"(v)); break

static u64 hw_read_reg(int is_w, int n)
{
    u64 v = 0;
    if (is_w) {
        switch (n) {
        HW_RD_CASE(0, wvr); HW_RD_CASE(1, wvr); HW_RD_CASE(2, wvr); HW_RD_CASE(3, wvr);
        default: break;
        }
    } else {
        switch (n) {
        HW_RD_CASE(0, bvr); HW_RD_CASE(1, bvr); HW_RD_CASE(2, bvr); HW_RD_CASE(3, bvr);
        HW_RD_CASE(4, bvr); HW_RD_CASE(5, bvr);
        default: break;
        }
    }
    return v;
}

static void hw_write_reg(int is_w, int n, u64 v)
{
    if (is_w) {
        switch (n) {
        HW_WR_CASE(0, wvr); HW_WR_CASE(1, wvr); HW_WR_CASE(2, wvr); HW_WR_CASE(3, wvr);
        default: return;
        }
    } else {
        switch (n) {
        HW_WR_CASE(0, bvr); HW_WR_CASE(1, bvr); HW_WR_CASE(2, bvr); HW_WR_CASE(3, bvr);
        HW_WR_CASE(4, bvr); HW_WR_CASE(5, bvr);
        default: return;
        }
    }
    asm volatile("isb");
}

static u64 hw_mdscr_read(void)
{
    u64 v;
    asm volatile("mrs %0, mdscr_el1" : "=r"(v));
    return v;
}

static void hw_mdscr_write(u64 v)
{
    asm volatile("msr mdscr_el1, %0" :: "r"(v));
    asm volatile("isb");
}

static int hw_num_brps(void)
{
    u64 v;
    int n;
    asm volatile("mrs %0, id_aa64dfr0_el1" : "=r"(v));
    n = 1 + (int)((v >> HW_DFR0_BRPS_SHIFT) & 0xf);
    return (n > 6) ? 6 : (n < 1 ? 1 : n);
}

static int hw_num_wrps(void)
{
    u64 v;
    int n;
    asm volatile("mrs %0, id_aa64dfr0_el1" : "=r"(v));
    n = 1 + (int)((v >> HW_DFR0_WRPS_SHIFT) & 0xf);
    return (n > 4) ? 4 : (n < 1 ? 1 : n);
}

/* ctrl 编码（镜像 arch_build_bp_info/encode_ctrl_reg 语义） */
static u32 hw_encode_ctrl(int len_field, int type, int priv, int enabled)
{
    return ((u32)len_field << 5) | ((u32)type << 3) |
           ((u32)priv << 1) | (u32)(enabled & 1);
}

static int hw_build(u64 addr, u32 kind, u32 len, u64 *bvr_out, u32 *bcr_out)
{
    int lenf = 0, type, off;

    if (kind == HW_BP_EXECUTE) {
        type = HW_BP_EXECUTE;
        lenf = HW_BP_LEN_4;
        addr &= ~3ULL;
    } else {
        type = (int)kind;
        switch (len) {
        case 1: lenf = HW_BP_LEN_1; break;
        case 2: lenf = HW_BP_LEN_2; break;
        case 4: lenf = HW_BP_LEN_4; break;
        case 8: lenf = HW_BP_LEN_8; break;
        default: return -1;
        }
        off = (int)(addr & 7ULL);
        if (len == 8 && off) return -1;
        lenf <<= off;
        addr &= ~7ULL;
    }
    *bvr_out = addr;
    *bcr_out = hw_encode_ctrl(lenf, type, 2 /*EL0*/, 1);
    return 0;
}

/* 上面的宏式访问无法同时覆盖 BCR/WCR 口——直接展开： */

static u64 hw_bcr_read(int n)
{
    u64 v = 0;
    switch (n) {
    case 0: asm volatile("mrs %0, dbgbcr0_el1" : "=r"(v)); break;
    case 1: asm volatile("mrs %0, dbgbcr1_el1" : "=r"(v)); break;
    case 2: asm volatile("mrs %0, dbgbcr2_el1" : "=r"(v)); break;
    case 3: asm volatile("mrs %0, dbgbcr3_el1" : "=r"(v)); break;
    case 4: asm volatile("mrs %0, dbgbcr4_el1" : "=r"(v)); break;
    case 5: asm volatile("mrs %0, dbgbcr5_el1" : "=r"(v)); break;
    }
    return v;
}

static void hw_bcr_write(int n, u64 v)
{
    switch (n) {
    case 0: asm volatile("msr dbgbcr0_el1, %0" :: "r"(v)); break;
    case 1: asm volatile("msr dbgbcr1_el1, %0" :: "r"(v)); break;
    case 2: asm volatile("msr dbgbcr2_el1, %0" :: "r"(v)); break;
    case 3: asm volatile("msr dbgbcr3_el1, %0" :: "r"(v)); break;
    case 4: asm volatile("msr dbgbcr4_el1, %0" :: "r"(v)); break;
    case 5: asm volatile("msr dbgbcr5_el1, %0" :: "r"(v)); break;
    default: return;
    }
    asm volatile("isb");
}

static u64 hw_wcr_read(int n)
{
    u64 v = 0;
    switch (n) {
    case 0: asm volatile("mrs %0, dbgwcr0_el1" : "=r"(v)); break;
    case 1: asm volatile("mrs %0, dbgwcr1_el1" : "=r"(v)); break;
    case 2: asm volatile("mrs %0, dbgwcr2_el1" : "=r"(v)); break;
    case 3: asm volatile("mrs %0, dbgwcr3_el1" : "=r"(v)); break;
    }
    return v;
}

static void hw_wcr_write(int n, u64 v)
{
    switch (n) {
    case 0: asm volatile("msr dbgwcr0_el1, %0" :: "r"(v)); break;
    case 1: asm volatile("msr dbgwcr1_el1, %0" :: "r"(v)); break;
    case 2: asm volatile("msr dbgwcr2_el1, %0" :: "r"(v)); break;
    case 3: asm volatile("msr dbgwcr3_el1, %0" :: "r"(v)); break;
    default: return;
    }
    asm volatile("isb");
}

static int hw_slot_find_free(int is_w)
{
    int n = is_w ? hw_num_wrps() : hw_num_brps(), i;
    for (i = 0; i < n; i++)
        if (hw_read_reg(is_w, i) == 0 &&
            (is_w ? hw_wcr_read(i) : hw_bcr_read(i)) == 0)
            return i;
    return -1;
}

static void hw_slot_set_enable(int is_w, int slot, int en)
{
    u64 c = is_w ? hw_wcr_read(slot) : hw_bcr_read(slot);
    c = en ? (c | 1) : (c & ~1ULL);
    if (is_w) hw_wcr_write(slot, c); else hw_bcr_write(slot, c);
}

static void hw_debug_enable(void)
{
    hw_mdscr_write(hw_mdscr_read() | HW_MDSCR_MDE);
}

/* ---------------- per-CPU 槽位记账 ---------------- */

struct hw_prog {
    int n;
    int is_w[HW_MAX_BRP + HW_MAX_WRP];
    int slot[HW_MAX_BRP + HW_MAX_WRP];
};
static struct hw_prog g_prog[HW_MAX_CPU];

/* step 记账：task -> (is_w, slot, 期望 BVR 值) */
struct hw_step {
    void *task;
    int is_w;
    int slot;
    u64 val;
};
static struct hw_step g_steps[HW_MAX_CPU];
static volatile int g_step_lock;

static void hw_step_push(void *task, int is_w, int slot, u64 val)
{
    int i, idx = -1;
    while (hw_xchg(&g_step_lock, 1))
        asm volatile("yield" ::: "memory");
    for (i = 0; i < HW_MAX_CPU; i++)
        if (g_steps[i].task == task || !g_steps[i].task) { idx = i; break; }
    if (idx < 0) idx = 0;
    g_steps[idx].task = task;
    g_steps[idx].is_w = is_w;
    g_steps[idx].slot = slot;
    g_steps[idx].val = val;
    asm volatile("stlr %w0, [%1]" :: "r"(0), "r"(&g_step_lock) : "memory");
}

static int hw_step_pop(void *task, int *is_w, u64 *val)
{
    int i, slot = -1;
    while (hw_xchg(&g_step_lock, 1))
        asm volatile("yield" ::: "memory");
    for (i = 0; i < HW_MAX_CPU; i++) {
        if (g_steps[i].task == task && task) {
            if (is_w) *is_w = g_steps[i].is_w;
            if (val) *val = g_steps[i].val;
            slot = g_steps[i].slot;
            g_steps[i].task = (void *)0;
            break;
        }
    }
    asm volatile("stlr %w0, [%1]" :: "r"(0), "r"(&g_step_lock) : "memory");
    return slot;
}

static void hw_prog_record(int is_w, int slot)
{
    int id = hw_cpu_id();
    if (g_prog[id].n < HW_MAX_BRP + HW_MAX_WRP) {
        g_prog[id].is_w[g_prog[id].n] = is_w;
        g_prog[id].slot[g_prog[id].n] = slot;
        g_prog[id].n++;
    }
}

/* 清本 CPU 全部调试槽。
 * 不能用"只清记账槽"——模块反复 load/unload 时，非当前 CPU 的槽无人清，
 * 残留会跨实例累积（实测：6 个 brp 全被历次残留填满 → 找不到空闲槽，
 * 断点永不武装）。全清是自愈的：每个 CPU 在首次 switch 时即清干净。
 * 代价 = 每次上下文切换约 10 条 MSR；换来的是无残留。
 * 注：本模块假定独占调试寄存器（无并发调试器）；若有外部断点会被一并清掉。 */
static void hw_prog_clear(void)
{
    int i;
    for (i = 0; i < hw_num_brps(); i++) {
        hw_bcr_write(i, 0);
        hw_write_reg(0, i, 0);
    }
    for (i = 0; i < hw_num_wrps(); i++) {
        hw_wcr_write(i, 0);
        hw_write_reg(1, i, 0);
    }
    g_prog[hw_cpu_id()].n = 0;
}

/* 在目标 CPU 上清全部调试槽 + 调试状态（on_each_cpu 回调 / 本核直调）。
 * 清 SS 位同样重要：若卸载时恰有"命中→请求单步"残留，SS 置位会让该核
 * 每条指令都触发单步异常。 */
static void hw_cleanup_cpu(void *info)
{
    int i;
    (void)info;
    for (i = 0; i < hw_num_brps(); i++) {
        hw_bcr_write(i, 0);
        hw_write_reg(0, i, 0);
    }
    for (i = 0; i < hw_num_wrps(); i++) {
        hw_wcr_write(i, 0);
        hw_write_reg(1, i, 0);
    }
    hw_mdscr_write(hw_mdscr_read() & ~(HW_MDSCR_SS | HW_MDSCR_MDE));
}

/* 找本 CPU 上装着 bvr 的槽（先查记账，兜底扫硬件） */
static int hw_prog_find(u64 bvr, int *is_w)
{
    int id = hw_cpu_id(), i;
    for (i = 0; i < g_prog[id].n; i++) {
        int w = g_prog[id].is_w[i], s = g_prog[id].slot[i];
        if (hw_read_reg(w, s) == bvr) {
            if (is_w) *is_w = w;
            return s;
        }
    }
    for (i = 0; i < hw_num_brps(); i++)
        if (hw_read_reg(0, i) == bvr) { if (is_w) *is_w = 0; return i; }
    for (i = 0; i < hw_num_wrps(); i++)
        if (hw_read_reg(1, i) == bvr) { if (is_w) *is_w = 1; return i; }
    return -1;
}

/* ---------------- 注册表查找 ---------------- */

static struct hw_bp *bp_find_locked(u64 mm, u64 addr)
{
    int i;
    for (i = 0; i < HW_MAX_BPS; i++)
        if (g_bps[i].used && g_bps[i].mm == mm && g_bps[i].bp_addr == addr)
            return &g_bps[i];
    return (struct hw_bp *)0;
}

static struct hw_bp *bp_find_exec_locked(u64 mm, u64 bvr)
{
    int i;
    for (i = 0; i < HW_MAX_BPS; i++)
        if (g_bps[i].used && g_bps[i].mm == mm &&
            g_bps[i].kind == HW_BP_EXECUTE && g_bps[i].bvr == bvr)
            return &g_bps[i];
    return (struct hw_bp *)0;
}

static struct hw_bp *bp_find_watch_locked(u64 mm, u64 far)
{
    int i;
    for (i = 0; i < HW_MAX_BPS; i++) {
        struct hw_bp *b = &g_bps[i];
        if (!b->used || b->mm != mm || b->kind == HW_BP_EXECUTE) continue;
        if (far >= b->bp_addr && far < b->bp_addr + (b->len ? b->len : 1))
            return b;
    }
    return (struct hw_bp *)0;
}

static void bp_free(struct hw_bp *b)
{
    if (b) { b->used = 0; b->mm = 0; }
}

static void hw_forget_mm(u64 mm)
{
    int i;
    bp_lock();
    for (i = 0; i < HW_MAX_BPS; i++)
        if (g_bps[i].used && g_bps[i].mm == mm)
            bp_free(&g_bps[i]);
    bp_unlock();
}

/* ---------------- __switch_to 编程 ---------------- */

/* 切进 next：清本 CPU 全部槽，再装 next->mm 的断点 */
static void hw_program_next(void *next_task)
{
    struct hw_bp *b;
    int i;

    hw_step_pop((void *)current, (int *)0, (u64 *)0);
    hw_prog_clear();

    bp_lock();
    if (g_quiescing) { bp_unlock(); return; }
    {
        u64 mm = hw_task_mm_of(next_task);
        if (mm) {
            for (i = 0; i < HW_MAX_BPS; i++) {
                int is_w, slot;
                b = &g_bps[i];
                if (!b->used || b->mm != mm) continue;
                is_w = (b->kind != HW_BP_EXECUTE);
                slot = hw_slot_find_free(is_w);
                if (slot < 0) {
                    static u64 nf_n;
                    if (nf_n < 2) {
                        int k;
                        CK_DBG("caoin-hw: no free slot is_w=%d nbrp=%d nwrp=%d\n",
                                is_w, hw_num_brps(), hw_num_wrps());
                        for (k = 0; k < hw_num_brps(); k++)
                            CK_DBG("caoin-hw:  bvr%d=%llx bcr%d=%llx\n", k,
                                    (unsigned long long)hw_read_reg(0, k), k,
                                    (unsigned long long)hw_bcr_read(k));
                        nf_n++;
                    }
                    continue;
                }
                if (is_w) {
                    hw_write_reg(1, slot, b->bvr);
                    hw_wcr_write(slot, b->bcr);
                } else {
                    hw_write_reg(0, slot, b->bvr);
                    hw_bcr_write(slot, b->bcr);
                }
                hw_prog_record(is_w, slot);
                hw_debug_enable();
                {
                    static u64 ok_n;
                    if (ok_n < 10) {
                        CK_DBG("caoin-hw: ARMED cpu=%d mm=%llx slot=%d bvr=%llx bcr=%x reg_i=%d\n",
                                hw_cpu_id(), (unsigned long long)mm, slot,
                                (unsigned long long)b->bvr, b->bcr, i);
                        ok_n++;
                    }
                }
            }
        }
        {
            static u64 dbg_n;
            int match = 0;
            for (i = 0; i < HW_MAX_BPS; i++)
                if (g_bps[i].used && g_bps[i].mm == mm) { match = 1; break; }
            if (match && dbg_n < 8) {
                CK_DBG("caoin-hw: sw MATCH mm=%llx armed=%d\n",
                        (unsigned long long)mm, g_prog[hw_cpu_id()].n);
                dbg_n++;
            }
        }
    }
    bp_unlock();
}

static void *g_switch_to;
static void hw_switch_before(hook_fargs2_t *fargs, void *udata)
{
    static u64 sw_n;
    (void)udata;
    if (sw_n < 6) {
        CK_DBG("caoin-hw: __switch_to next=%lx\n",
                (unsigned long)fargs->arg1);
        sw_n++;
    }
    hw_program_next((void *)fargs->arg1);   /* 4.9: __switch_to(prev, next) */
}

/* ---------------- 异常接管 ---------------- */

static void *g_bp_h, *g_ss_h, *g_wp_h;
/* pt_regs 在 hook args 里的下标（按内核版本/handler 原型定，见 install） */
static int g_bp_regs = 2, g_ss_regs = 2, g_wp_regs = 2;

static int hw_cond_ok(struct hw_bp *b, struct pt_regs *regs)
{
    u64 v;
    if (!b->has_cond) return 1;
    if (b->cond_reg >= 0 && b->cond_reg <= 30) v = regs->regs[b->cond_reg];
    else if (b->cond_reg == HW_REG_SP) v = regs->sp;
    else if (b->cond_reg == HW_REG_PC) v = regs->pc;
    else v = 0;
    return v == b->cond_val;
}

static void hw_apply_regs(struct hw_bp *b, struct pt_regs *regs)
{
    int i;
    u64 mask = b->regmask;
    if (!mask) return;
    for (i = 0; i <= 30; i++)
        if (mask & (1ull << i)) regs->regs[i] = b->regs[i];
    if (mask & (1ull << HW_REG_SP)) regs->sp = b->regs[HW_REG_SP];
    if (mask & (1ull << HW_REG_PSTATE)) regs->pstate = b->regs[HW_REG_PSTATE];
}

static void hw_record_hit(struct hw_bp *b, struct pt_regs *regs)
{
    int i;
    for (i = 0; i <= 30; i++) b->last_regs[i] = regs->regs[i];
    b->last_regs[HW_REG_SP] = regs->sp;
    b->last_regs[HW_REG_PC] = regs->pc;
    b->last_regs[HW_REG_PSTATE] = regs->pstate;
    b->hits++;
}

static void hw_request_step(struct pt_regs *regs)
{
    hw_mdscr_write(hw_mdscr_read() | HW_MDSCR_SS);
    regs->pstate |= HW_SPSR_SS;
}

/* 4.9 pt_regs 在 args 里的位置：wxshadow 已实证
 * brk_handler(unused, esr, regs) => arg1=esr arg2=regs
 * single_step_handler(unused, esr, regs) => 同上 */
static void hw_brk_before(hook_fargs3_t *fargs, void *udata)
{
    struct pt_regs *regs = (struct pt_regs *)fargs->args[g_bp_regs];
    u64 mm, bvr;
    struct hw_bp *b;
    int is_w = 0, slot;

    (void)udata;
    fargs->ret = 0;

    if (!regs || !user_mode(regs)) return;
    mm = hw_current_mm();
    if (!mm) return;

    bvr = regs->pc & ~3ULL;

    bp_lock();
    b = bp_find_exec_locked(mm, bvr);
    if (!b) { bp_unlock(); return; }
    {
        static u64 hit_n;
        if (hit_n < 12) {
            CK_DBG("caoin-hw: HIT pc=%lx mm=%lx x0=%lx\n",
                    (unsigned long)regs->pc, (unsigned long)mm,
                    (unsigned long)regs->regs[0]);
            hit_n++;
        }
    }

    hw_record_hit(b, regs);

    if (hw_cond_ok(b, regs)) {
        hw_apply_regs(b, regs);
        if (b->regmask & (1ull << HW_REG_PC)) {
            /* pc 覆盖：槽保持使能，不单步 */
            bp_unlock();
            fargs->skip_origin = 1;
            return;
        }
    }

    slot = hw_prog_find(bvr, &is_w);
    if (slot >= 0) {
        hw_slot_set_enable(is_w, slot, 0);
        hw_step_push((void *)current, is_w, slot, bvr);
        hw_request_step(regs);
    }
    bp_unlock();
    fargs->skip_origin = 1;
}

static void hw_ss_before(hook_fargs3_t *fargs, void *udata)
{
    struct pt_regs *regs = (struct pt_regs *)fargs->args[g_ss_regs];
    int is_w = 0, slot;
    u64 val = 0, cur;

    (void)udata;
    fargs->ret = 0;

    if (!regs || !user_mode(regs)) return;   /* 内核态 step（如 kprobe 单步）不是我们的 */

    slot = hw_step_pop((void *)current, &is_w, &val);
    if (slot < 0) return;   /* 不是我们的 step：原 handler 跑 */

    cur = hw_read_reg(is_w, slot);
    if (cur == val)
        hw_slot_set_enable(is_w, slot, 1);  /* 仅当槽还是我们的断点才重装 */
    hw_mdscr_write(hw_mdscr_read() & ~HW_MDSCR_SS);
    regs->pstate &= ~HW_SPSR_SS;
    fargs->ret = 0;                 /* DBG_HOOK_HANDLED */
    fargs->skip_origin = 1;
}

/* 观察点：4.9 = watchpoint_handler(unused, esr, regs)，far 从 FAR_EL1 读 */
static void hw_wp_before(hook_fargs3_t *fargs, void *udata)
{
    struct pt_regs *regs = (struct pt_regs *)fargs->args[g_wp_regs];
    u64 far, mm;
    struct hw_bp *b;
    int is_w = 1, slot;

    (void)udata;
    fargs->ret = 0;
    if (!regs) return;
    asm volatile("mrs %0, far_el1" : "=r"(far));
    mm = hw_current_mm();
    if (!mm) return;

    bp_lock();
    b = bp_find_watch_locked(mm, far);
    if (!b) { bp_unlock(); return; }

    if (!user_mode(regs)) {
        /* EL0 观察点在内核 uaccess 期间命中：4.9 原生 handler 找不到
         * wp_on_reg 槽会直接返回 → uaccess 永久重试（软锁死）。关槽放行，
         * 下次 __switch_to 重装。 */
        slot = hw_prog_find(b->bvr, &is_w);
        if (slot >= 0) hw_slot_set_enable(is_w, slot, 0);
        bp_unlock();
        fargs->skip_origin = 1;
        return;
    }

    hw_record_hit(b, regs);
    if (hw_cond_ok(b, regs)) {
        hw_apply_regs(b, regs);
        if (b->regmask & (1ull << HW_REG_PC)) {
            bp_unlock();
            fargs->skip_origin = 1;
            return;
        }
    }

    slot = hw_prog_find(b->bvr, &is_w);
    if (slot >= 0) {
        hw_slot_set_enable(is_w, slot, 0);
        hw_step_push((void *)current, is_w, slot, b->bvr);
        hw_request_step(regs);
    }
    bp_unlock();
    fargs->skip_origin = 1;
}

static int hw_exc_install(void)
{
    hook_err_t err;

    /* 硬件断点（EC 0x30）异常入口。
     * 4.9: breakpoint_handler(unused, esr, regs) —— static，wrap3，regs=arg2
     *      （注意不是 brk_handler：那是 BRK 指令 EC 0x3C 的入口，收不到硬件断点）
     * 6.x: do_breakpoint(esr, regs) —— wrap2，regs=arg1 */
    g_bp_h = (void *)kallsyms_lookup_name("breakpoint_handler");
    if (g_bp_h) {
        g_bp_regs = 2;
        err = hook_wrap3(g_bp_h, hw_brk_before, (void *)0, (void *)0);
    } else {
        g_bp_h = (void *)kallsyms_lookup_name("do_breakpoint");
        if (g_bp_h) {
            g_bp_regs = 1;
            err = hook_wrap2(g_bp_h, hw_brk_before, (void *)0, (void *)0);
        } else {
            err = (hook_err_t)-1;
        }
    }
    if (!g_bp_h || err != HOOK_NO_ERR) {
        pr_err("caoin-hw: hook breakpoint handler fail (sym=%px err=%d)\n",
               g_bp_h, err);
        g_bp_h = (void *)0;
        return -2;
    }

    /* 单步异常（EC 0x32）。
     * 4.9: single_step_handler(unused, esr, regs) —— wrap3，regs=arg2
     * 6.x: try_step_suspended_breakpoints(regs) —— wrap1，regs=arg0 */
    g_ss_h = (void *)kallsyms_lookup_name("single_step_handler");
    if (g_ss_h) {
        g_ss_regs = 2;
        err = hook_wrap3(g_ss_h, hw_ss_before, (void *)0, (void *)0);
    } else {
        g_ss_h = (void *)kallsyms_lookup_name("try_step_suspended_breakpoints");
        if (g_ss_h) {
            g_ss_regs = 0;
            err = hook_wrap1(g_ss_h, hw_ss_before, (void *)0, (void *)0);
        } else {
            err = (hook_err_t)-1;
        }
    }
    if (!g_ss_h || err != HOOK_NO_ERR) {
        pr_warn("caoin-hw: no step handler (sym=%px err=%d)\n", g_ss_h, err);
        g_ss_h = (void *)0;
    }

    /* 观察点（EC 0x32/0x34 写读）。
     * 4.9: watchpoint_handler(unused, esr, regs) —— wrap3，regs=arg2
     * 6.x: do_watchpoint(far, esr, regs) —— wrap3，regs=arg2 */
    g_wp_h = (void *)kallsyms_lookup_name("watchpoint_handler");
    if (!g_wp_h)
        g_wp_h = (void *)kallsyms_lookup_name("do_watchpoint");
    if (g_wp_h) {
        g_wp_regs = 2;
        err = hook_wrap3(g_wp_h, hw_wp_before, (void *)0, (void *)0);
        if (err != HOOK_NO_ERR) {
            pr_warn("caoin-hw: hook watchpoint handler fail %d\n", err);
            g_wp_h = (void *)0;   /* 观察点可选，不失败加载 */
        }
    }

    pr_info("caoin-hw: hooked bp=%px(r%d) ss=%px(r%d) wp=%px(r%d)\n",
            g_bp_h, g_bp_regs, g_ss_h, g_ss_regs, g_wp_h, g_wp_regs);
    return 0;
}

static void hw_exc_uninstall(void)
{
    if (g_wp_h) { hw_unhook(g_wp_h, hw_wp_before); g_wp_h = (void *)0; }
    if (g_ss_h) { hw_unhook(g_ss_h, hw_ss_before); g_ss_h = (void *)0; }
    if (g_bp_h) { hw_unhook(g_bp_h, hw_brk_before); g_bp_h = (void *)0; }
}

/* ---------------- exit_mmap 伴侣钩子 ---------------- */

static void *g_exit_mmap;
static void hw_exit_mmap_before(hook_fargs1_t *fargs, void *udata)
{
    (void)udata;
    hw_forget_mm(fargs->arg0);
}

/* ---------------- add/del/clear ---------------- */

static int hw_add(u32 pid, u32 kind, u32 len, u64 addr,
                  u64 regmask, const u64 *regvals,
                  int has_cond, int cond_reg, u64 cond_val)
{
    struct hw_bp *b = (struct hw_bp *)0;
    void *task;
    u64 mm, bvr;
    u32 bcr;
    int i, rc;

    if (!g_ready) return -1;
    if (hw_build(addr, kind, len, &bvr, &bcr)) return -3;

    task = hw_task_by_pid(pid);
    if (!task) return -4;
    mm = kfn_get_task_mm ? kfn_get_task_mm(task) : 0;   /* mm_users +1 */
    if (!mm) { hw_put_task(task); return -5; }

    bp_lock();
    if (bp_find_locked(mm, addr)) { bp_unlock(); rc = -17; goto out; }
    for (i = 0; i < HW_MAX_BPS; i++)
        if (!g_bps[i].used) { b = &g_bps[i]; break; }
    if (!b) { bp_unlock(); rc = -6; goto out; }
    b->used = 1;
    b->mm = mm;
    b->pid = pid;
    b->kind = kind;
    b->len = len;
    b->bp_addr = addr;
    b->bvr = bvr;
    b->bcr = bcr;
    b->regmask = regmask;
    if (regvals)
        for (i = 0; i < HW_REG_NUM; i++) b->regs[i] = regvals[i];
    b->has_cond = has_cond;
    b->cond_reg = cond_reg;
    b->cond_val = cond_val;
    b->hits = 0;
    bp_unlock();

    /* 目标正在本 CPU 上跑：立即武装 */
    if (mm == hw_current_mm())
        hw_program_next(current);

    CK_DBG("caoin-hw: add pid=%u addr=%llx kind=%u mm=%llx\n",
            pid, (unsigned long long)addr, kind, (unsigned long long)mm);

    hw_put_mm(mm);      /* 无长期引用；exit_mmap 钩子负责死 mm 回收 */
    hw_put_task(task);
    return 0;

out:
    hw_put_mm(mm);
    hw_put_task(task);
    return rc;
}

static int hw_del(u32 pid, u64 addr)
{
    void *task;
    u64 mm = 0;
    struct hw_bp *b = (struct hw_bp *)0;
    int is_cur;

    task = hw_task_by_pid(pid);
    if (!task) return -4;
    mm = kfn_get_task_mm ? kfn_get_task_mm(task) : 0;
    if (!mm) { hw_put_task(task); return -5; }

    bp_lock();
    b = bp_find_locked(mm, addr);
    if (b) bp_free(b);
    bp_unlock();

    is_cur = (mm == hw_current_mm());
    if (is_cur) hw_program_next(current);

    hw_put_mm(mm);
    hw_put_task(task);
    return b ? 0 : -2;
}

static int hw_clear(u32 pid)
{
    void *task;
    u64 mm;
    int n = 0, is_cur, i;

    task = hw_task_by_pid(pid);
    if (!task) return -4;
    mm = kfn_get_task_mm ? kfn_get_task_mm(task) : 0;
    if (!mm) { hw_put_task(task); return -5; }

    bp_lock();
    for (i = 0; i < HW_MAX_BPS; i++)
        if (g_bps[i].used && g_bps[i].mm == mm) { bp_free(&g_bps[i]); n++; }
    bp_unlock();

    is_cur = (mm == hw_current_mm());
    if (is_cur) hw_program_next(current);

    hw_put_mm(mm);
    hw_put_task(task);
    return n;
}

static int hw_set_cond(u32 pid, u64 addr, int has, int reg, u64 val)
{
    void *task;
    u64 mm;
    struct hw_bp *b;
    int rc = -2;

    task = hw_task_by_pid(pid);
    if (!task) return -4;
    mm = kfn_get_task_mm ? kfn_get_task_mm(task) : 0;
    if (!mm) { hw_put_task(task); return -5; }

    bp_lock();
    b = bp_find_locked(mm, addr);
    if (b) {
        b->has_cond = has;
        b->cond_reg = reg;
        b->cond_val = val;
        rc = 0;
    }
    bp_unlock();

    hw_put_mm(mm);
    hw_put_task(task);
    return rc;
}

/* ---------------- 偏移解析 ---------------- */

/* 探针为主（可靠，不依赖 KP 表布局）：current->mm 与 get_task_mm(current)
 * 返回值相等处即 task_struct.mm 偏移。KP 兼容表仅作对照打印。
 * 注意 KP 导出的是 int16 序列（pid/tgid/.../tasks/mm/active_mm），
 * 不是 long 数组——早先按 long 索引读是错的。 */
static int hw_resolve_offsets(void)
{
    unsigned long cur_mm = 0, i;
    short *kp_tab;

    off_task_mm = -1;
    off_task_tgid = -1;

    if (kfn_get_task_mm) {
        cur_mm = kfn_get_task_mm(current);
        if (cur_mm) {
            for (i = 0; i < 0x1800; i += 8) {
                if (rd64((u64)current + i) == cur_mm) {
                    off_task_mm = (long)i;
                    break;
                }
            }
            if (kfn_mmput) kfn_mmput((void *)cur_mm);
        }
    }

    kp_tab = (short *)kallsyms_lookup_name("task_struct_offset");
    if (kp_tab) {
        pr_info("caoin-hw: kp_tab tgid=%d mm=%d (probe mm=%ld)\n",
                kp_tab[1], kp_tab[15], off_task_mm);
        off_task_tgid = kp_tab[1];
        if (off_task_mm < 0 && kp_tab[15] > 0)
            off_task_mm = kp_tab[15];
    } else {
        pr_info("caoin-hw: kp_tab absent (probe mm=%ld)\n", off_task_mm);
    }

    return (off_task_mm < 0) ? -1 : 0;
}

/* ---------------- ctl0 命令解析 ---------------- */

static u64 parse_hex(const char *s)
{
    u64 v = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    while (1) {
        char c = *s;
        if (c >= '0' && c <= '9') v = v * 16 + (c - '0');
        else if (c >= 'a' && c <= 'f') v = v * 16 + (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v = v * 16 + (c - 'A' + 10);
        else break;
        s++;
    }
    return v;
}

static int parse_reg(const char *s)
{
    if (s[0] != 'x' && s[0] != 'X') {
        if (s[0] == 's' && s[1] == 'p') return HW_REG_SP;
        if (s[0] == 'p' && s[1] == 'c') return HW_REG_PC;
        return -1;
    }
    return (int)parse_hex(s + 1);
}

/* "add 1234 0x401440 x0=1122 x1=33" 风格命令。buf 可被改写（分词）。 */
static long hw_ctl_exec(char *buf)
{
    char *tok[12];
    int ntok = 0, i;
    char *p = buf;

    while (p && ntok < 12) {
        while (*p == ' ') p++;
        if (!*p) break;
        tok[ntok++] = p;
        p = strchr(p, ' ');
        if (p) { *p = 0; p++; }
    }
    if (!ntok) return -1;

    if (!strncmp(tok[0], "verbose", 7)) {
        if (tok[0][7] == '=')
            g_verbose = parse_hex(tok[0] + 8);
        else
            g_verbose = (ntok >= 2) ? parse_hex(tok[1]) : 1;
        return 0;
    }

    if (!strcmp(tok[0], "slots")) {
        int nb = hw_num_brps(), nw = hw_num_wrps();
        pr_info("caoin-hw: brps=%d wrps=%d MDE=%d\n", nb, nw,
                (int)((hw_mdscr_read() & HW_MDSCR_MDE) ? 1 : 0));
        for (i = 0; i < nb; i++)
            pr_info("caoin-hw: BVR%d=%llx BCR%d=%llx\n", i,
                    (unsigned long long)hw_read_reg(0, i), i,
                    (unsigned long long)hw_bcr_read(i));
        for (i = 0; i < nw; i++)
            pr_info("caoin-hw: WVR%d=%llx WCR%d=%llx\n", i,
                    (unsigned long long)hw_read_reg(1, i), i,
                    (unsigned long long)hw_wcr_read(i));
        return 0;
    }

    if (!strcmp(tok[0], "add") || !strcmp(tok[0], "addw")) {
        u64 vals[HW_REG_NUM];
        u64 mask = 0, addr;
        u32 pid, kind, len = 0;
        int has_cond = 0, cond_reg = -1, j;
        u64 cond_val = 0;

        if (ntok < 3) return -1;
        pid = (u32)parse_hex(tok[1]);
        addr = parse_hex(tok[2]);
        kind = (tok[0][3] == 'w') ? HW_BP_RW : HW_BP_EXECUTE;
        for (j = 3; j < ntok; j++) {
            char *eq = strchr(tok[j], '=');
            if (eq && tok[j][0] == 'x') {
                int r = parse_reg(tok[j]);
                if (r >= 0 && r < HW_REG_SP) {
                    *eq = 0;
                    vals[r] = parse_hex(eq + 1);
                    mask |= 1ull << r;
                }
            } else if (!strcmp(tok[j], "if") && j + 1 < ntok) {
                char *eq2 = strchr(tok[j + 1], '=');
                if (eq2) {
                    *eq2 = 0;
                    cond_reg = parse_reg(tok[j + 1]);
                    cond_val = parse_hex(eq2 + 1);
                    has_cond = 1;
                }
                j++;
            } else if (tok[0][3] == 'w') {
                len = (u32)parse_hex(tok[j]);   /* 观察点长度 */
            }
        }
        return hw_add(pid, kind, len, addr, mask,
                      mask ? vals : (const u64 *)0,
                      has_cond, cond_reg, cond_val);
    }

    if (!strcmp(tok[0], "del") && ntok >= 3)
        return hw_del((u32)parse_hex(tok[1]), parse_hex(tok[2]));

    if (!strcmp(tok[0], "clear") && ntok >= 2)
        return hw_clear((u32)parse_hex(tok[1]));

    if (!strcmp(tok[0], "cond") && ntok >= 4) {
        char *eq = strchr(tok[3], '=');
        if (eq) {
            *eq = 0;
            return hw_set_cond((u32)parse_hex(tok[1]), parse_hex(tok[2]),
                               1, parse_reg(tok[3]), parse_hex(eq + 1));
        }
        return -1;
    }

    if (!strcmp(tok[0], "uncond") && ntok >= 3)
        return hw_set_cond((u32)parse_hex(tok[1]), parse_hex(tok[2]), 0, 0, 0);

    if (!strcmp(tok[0], "hit") && ntok >= 3) {
        void *task;
        u64 mm;
        struct hw_bp *b;
        int rc = -2;
        task = hw_task_by_pid((u32)parse_hex(tok[1]));
        if (!task) return -4;
        mm = kfn_get_task_mm ? kfn_get_task_mm(task) : 0;
        if (!mm) { hw_put_task(task); return -5; }
        bp_lock();
        b = bp_find_locked(mm, parse_hex(tok[2]));
        if (b) {
            pr_info("caoin-hw: hits=%llu pc=%llx sp=%llx\n",
                    (unsigned long long)b->hits,
                    (unsigned long long)b->last_regs[HW_REG_PC],
                    (unsigned long long)b->last_regs[HW_REG_SP]);
            for (i = 0; i <= 30; i++)
                pr_info("caoin-hw: x%d=%llx\n", i,
                        (unsigned long long)b->last_regs[i]);
            rc = 0;
        }
        bp_unlock();
        hw_put_mm(mm);
        hw_put_task(task);
        return rc;
    }

    if (!strcmp(tok[0], "list")) {
        u32 pid = ntok >= 2 ? (u32)parse_hex(tok[1]) : 0;
        void *task = hw_task_by_pid(pid);
        u64 mm;
        int n = 0;
        if (!task) return -4;
        mm = hw_task_mm_of(task);   /* 无引用读，仅枚举 */
        bp_lock();
        for (i = 0; i < HW_MAX_BPS; i++) {
            if (!g_bps[i].used || (pid && g_bps[i].mm != mm)) continue;
            pr_info("caoin-hw: bp[%d] pid=%u addr=%llx kind=%u len=%u hits=%llu cond=%d\n",
                    i, g_bps[i].pid, (unsigned long long)g_bps[i].bp_addr,
                    g_bps[i].kind, g_bps[i].len,
                    (unsigned long long)g_bps[i].hits, g_bps[i].has_cond);
            n++;
        }
        bp_unlock();
        hw_put_task(task);
        return n;
    }

    if (!strcmp(tok[0], "peek") && ntok >= 4) {
        void *task;
        u8 tmp[64];
        int len, r;
        task = hw_task_by_pid((u32)parse_hex(tok[1]));
        if (!task) return -4;
        len = (int)parse_hex(tok[3]);
        if (len > 64) len = 64;
        r = hw_read_mem(task, parse_hex(tok[2]), tmp, len);
        hw_put_task(task);
        if (r) return r;
        pr_info("caoin-hw: peek:");
        for (i = 0; i < len; i++)
            pr_info(" %02x", tmp[i]);
        pr_info("\n");
        return 0;
    }

    return -1;
}

/* ---------------- KPM 入口 ---------------- */

static long caoin_hw_init(const char *args, const char *event, void *__user reserved)
{
    hook_err_t err;

    (void)event;
    (void)args;
    (void)reserved;

    if (g_ready) return -1;

    kfn_find_task = (void *)kallsyms_lookup_name("find_task_by_vpid");
    if (!kfn_find_task)
        kfn_find_task = (void *)kallsyms_lookup_name("find_get_task_by_vpid");
    kfn_put_task = (void *)kallsyms_lookup_name("put_task_struct");
    kfn_get_task_mm = (void *)kallsyms_lookup_name("get_task_mm");
    kfn_mmput = (void *)kallsyms_lookup_name("mmput");
    kfn_vmalloc = (void *)kallsyms_lookup_name("vmalloc");
    kfn_vfree = (void *)kallsyms_lookup_name("vfree");
    kfn_apv = (void *)kallsyms_lookup_name("access_process_vm");
    kfn_on_each_cpu = (void *)kallsyms_lookup_name("on_each_cpu");
    if (!kfn_find_task || !kfn_get_task_mm || !kfn_mmput) {
        pr_err("caoin-hw: missing task helpers (find=%px gmm=%px mmput=%px)\n",
               (void *)kfn_find_task, (void *)kfn_get_task_mm,
               (void *)kfn_mmput);
        return -1;
    }

    if (hw_resolve_offsets()) {
        pr_err("caoin-hw: task_struct.mm offset unresolved\n");
        return -1;
    }
    pr_info("caoin-hw: offsets mm=%ld tgid=%ld\n", off_task_mm, off_task_tgid);

    /* exit_mmap 强制：装不上拒绝加载（否则死 mm 留悬空记录） */
    g_exit_mmap = (void *)kallsyms_lookup_name("exit_mmap");
    if (!g_exit_mmap) {
        pr_err("caoin-hw: exit_mmap not found\n");
        return -1;
    }
    err = hook_wrap1(g_exit_mmap, hw_exit_mmap_before, (void *)0, (void *)0);
    if (err != HOOK_NO_ERR) {
        pr_err("caoin-hw: hook exit_mmap fail %d\n", err);
        return -1;
    }

    /* __switch_to 编程引擎 */
    g_switch_to = (void *)kallsyms_lookup_name("__switch_to");
    if (!g_switch_to) {
        pr_err("caoin-hw: __switch_to not found\n");
        hw_unhook(g_exit_mmap, hw_exit_mmap_before);
        return -1;
    }
    err = hook_wrap2(g_switch_to, hw_switch_before, (void *)0, (void *)0);
    if (err != HOOK_NO_ERR) {
        pr_err("caoin-hw: hook __switch_to fail %d\n", err);
        hw_unhook(g_exit_mmap, hw_exit_mmap_before);
        return -1;
    }

    /* 异常接管最后装（引擎就绪后才有槽可查） */
    err = hw_exc_install();
    if (err) {
        pr_err("caoin-hw: exc install fail %d\n", err);
        hw_unhook(g_switch_to, hw_switch_before);
        hw_unhook(g_exit_mmap, hw_exit_mmap_before);
        return err;
    }

    g_quiescing = 0;
    g_ready = 1;
    pr_info("caoin-hw: ready (brps=%d wrps=%d)\n", hw_num_brps(), hw_num_wrps());

    /* args = 命令串（';' 分隔多条），与 caoin 现有 load-args 工作流一致：
     *   kpatch su kpm load caoin-hw.kpm "add <pid> <addr> x0=777"
     * ctl0 通道在本机 kpatch 精简版不可用，故 args 为唯一配置入口。 */
    if (args && *args) {
        char cbuf[256];
        char *seg, *semi;
        int n = 0, rc;
        while (args[n] && n < (int)sizeof(cbuf) - 1) { cbuf[n] = args[n]; n++; }
        cbuf[n] = 0;
        seg = cbuf;
        while (seg && *seg) {
            semi = strchr(seg, ';');
            if (semi) *semi = 0;
            rc = (int)hw_ctl_exec(seg);
            pr_info("caoin-hw: args[%s] rc=%d\n", seg, rc);
            seg = semi ? semi + 1 : (char *)0;
        }
    }
    return 0;
}

static long caoin_hw_ctl0(const char *args, char *__user out_msg, int outlen)
{
    char buf[256];
    int len;

    (void)out_msg;
    (void)outlen;
    if (!args) return -1;
    len = strlen(args);
    if (len <= 0 || len >= (int)sizeof(buf)) return -1;
    memcpy(buf, args, len + 1);
    return hw_ctl_exec(buf);
}

static long caoin_hw_exit(void *__user reserved)
{
    int id;

    (void)reserved;
    if (!g_ready) return 0;
    g_ready = 0;
    g_quiescing = 1;

    /* 清注册表（后续 switch 编程看到 quiescing 不会再装） */
    bp_lock();
    for (id = 0; id < HW_MAX_BPS; id++) bp_free(&g_bps[id]);
    bp_unlock();

    /* 卸异常钩子（先异常后引擎：避免有断点无 handler 的窗口） */
    hw_exc_uninstall();
    if (g_switch_to)
        hw_unhook(g_switch_to, hw_switch_before);
    if (g_exit_mmap)
        hw_unhook(g_exit_mmap, hw_exit_mmap_before);

    /* 清所有 CPU 的槽 + 调试状态。
     * 只清本 CPU 不够：其他 CPU 的槽 armed 且无人处理（handler 已卸），
     * 目标进程一旦迁移过去就撞断点 → 无限异常 → 该核卡死（watchdog）。
     * 用 on_each_cpu 在每个核上清（KPM exit 是进程上下文，可发 IPI；
     * caoin-shadow 记忆里的 "IPI 死亡陷阱" 是 fault handler 上下文，
     * 不适用于此处）。符号缺失则退回只清本核。 */
    if (kfn_on_each_cpu)
        kfn_on_each_cpu(hw_cleanup_cpu, (void *)0, 1);
    else
        hw_cleanup_cpu((void *)0);
    pr_info("caoin-hw: unloaded (slots cleared)\n");
    return 0;
}

KPM_NAME("caoin-hw");
KPM_VERSION("0.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("caoin");
KPM_DESCRIPTION("caoin P3-v5 stealth hw-breakpoint hook (no perf_event)");

KPM_INIT(caoin_hw_init);
KPM_CTL0(caoin_hw_ctl0);
KPM_EXIT(caoin_hw_exit);
