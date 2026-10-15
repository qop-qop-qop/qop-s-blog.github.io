/*
 * caoin shadow KPM v5 — 无痕 hook 内核侧（dpf-hook shadow seesaw, 多 hook 点）
 *
 * 架构（P3-v3，LKM/VBAR 路线已退役，历史见仓库 README）：
 *  - KP hook do_page_fault（授权通道）接管目标进程受管页 fault：
 *      SHADOW（shadow 页 | AP=10 X-only）↔ STEP（original | RW+UXN）
 *      每个受管页独立跷跷板（hook 表驱动，CAOIN_MAX_HOOKS 个）
 *  - 执行走 shadow 页桩（内核侧直装：改返回值模板），读取走原页——
 *    代码段 CRC 自检不破
 *  - 哨兵页 fault（PROT_NONE）：发现 EL0 页表（TTBR0→表基址）并吃掉 SIGSEGV；
 *    分支位于 vbar_on 门之前——init 未 arm 完成时到达也安全（真机踩坑）
 *  - exit_mmap 伴侣钩子（wxshadow 同款）：目标退出时 zap 前恢复原 PTE，
 *    防 shadow 页双重 unmap → Bad page state → 无关进程内核死循环
 *  - 主路径带进程校验（sp_el0 → task->mm == mm_run），他进程同 VA fault 放行
 *  - 日志默认静音（无痕优先）：CK_ERR 错误常打，verbose=1 开流程日志，
 *    ctl0 dump 不受门控
 *
 * 内核触碰面：KP hook do_page_fault/exit_mmap + 目标进程 PTE 读写
 * （probe_* 走 KP 框架，不额外写内核内存）。
 *
 * 用法（args 全量传参；运行脚本从 tdyn4.out 解析后拼接）：
 *   kpatch <superkey> kpm load caoin-shadow.kpm \
 *     --args "pid=0x1bb3 tva=0x... shva=0x... sva=0x... sent=0x... \
 *             tva1=0x... shva1=0x... [tva2= shva2= tva3= shva3=] [verbose=1]"
 *   tva/shva 为 hook0，tva1/shva1 为 hook1…… 每对 = 受管页 + 影子页（页对齐，
 *   受管函数须在受管页页首 aligned(4096)；影子页内容 = 原页快照 + 桩由 KPM 安装）
 *   kpatch <superkey> kpm unload caoin-shadow
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <kallsyms.h>
#include <ktypes.h>
#include <linux/string.h>
#include <hook.h>

/* ---- PTE 位定义（arm64，自包含） ---- */
#define PTE_VALID      (1UL << 0)
#define PTE_AF         (1UL << 10)
#define PTE_AP_MASK    0xC0UL
#define PTE_UXN        (1UL << 54)
#define CAOIN_PFN_MASK 0x0000FFFFFFFFF000UL
#define CAOIN_PAGE_MASK (~0xFFFUL)

/* ---- 视图三态 ---- */
#define VIEW_OFF     0UL
#define VIEW_SHADOW  1UL
#define VIEW_STEP    2UL

/* ---- fork 防护用（<linux/sched.h> 未引入，自包含定义） ---- */
#ifndef CLONE_VM
#define CLONE_VM 0x00000100UL
#endif

/* ---- 进程级配置与运行态 ---- */
static u64 cfg_pid;
static u64 cfg_sva, cfg_e2;    /* status 变量 VA / status 页 PFN（自推导） */
static u64 cfg_sent;           /* 哨兵页 VA */
static volatile u64 vbar_on;   /* 语义沿用：1 = 已接管 fault 入口 */
static u64 mm_run, mm_off, pgd_off;
static unsigned long mm_run_pgd;      /* 目标进程 pgd 指针(init 时锁定) */
static unsigned long el0_table_base;  /* EL0 页表基址（哨兵发现，PA；0=未发现） */
static volatile u64 ec20_cnt, ec24_cnt, sent_cnt;

/* ---- 注入请求协议 ----
 * 目标向 status 变量写 INJ_REQ → KPM 在目标 fault 上下文探测命中 →
 * 消费（inj_done 单次标记，跨核清零会被目标核脏行写回覆盖，不可靠）→
 * handled 块内（状态机处理完、视图已切）对所有 hook 内核侧安装桩。 */
#define INJ_REQ    0xCA0F0002ULL
static u64 inj_armed;   /* 请求已消费，等待 handled 劫持点 */

/* ---- hook 点表（P3-v3 多 hook）----
 * 跷跷板是页级的：每个受管页一对 (tva, shva)、独立视图状态。 */
#define CAOIN_MAX_HOOKS 4
struct caoin_hook {
    u64 tva, shva;              /* 受管页/影子页 VA（页对齐） */
    u64 shva_off;               /* 受管函数在 tva 页内偏移（=影子页内偏移） */
    u64 pte_addr, orig_pte;     /* mm->pgd 的 PTE 地址与原值 */
    u64 shadow_pte_val, origview_pte_val;
    u64 pte_addr2, orig_pte2, shadow2_val, origview2_val;  /* KPTI 副本兜底 */
    volatile u64 cur_view;
    u64 el0_pte_addr;           /* EL0 表里本 hook tva 的 PTE（发现后缓存） */
    u64 ret_val;                /* 桩模板：替换返回值（777+i） */
    u64 copy_size;              /* 原函数指令区大小（影子页 scratch 拷贝用，csizeN） */
};
static struct caoin_hook hooks[CAOIN_MAX_HOOKS];
static int hooks_n;
static int last_hit_hi;   /* 最近一次跷跷板处理的 hook 索引 */

/* ---- kallsyms 解析的内核函数 ---- */
static long (*kfn_probe_read)(void *, const void *, unsigned long);
static long (*kfn_probe_write)(void *, const void *, unsigned long);
static void *(*kfn_find_task_by_vpid)(int);
static s64 *kvar_memstart_addr;
static unsigned long page_offset_base;

static u64 g_verbose;   /* verbose=1 开流程日志；默认静音（无痕优先），错误路径仍打 */
static void *g_copy_process;   /* fork 防护 hook 目标（装不上为 NULL） */
static u64 g_stub_onload;      /* stub=1：加载即装桩（跳过 INJ_REQ 握手，
                                * 供 caoin_prep 自动化流程——目标不发请求） */

/* 日志双档：CK_ERR 永远打（加载失败必须可见）；CK_LOG 默认静音。
 * ctl0 dump 不受门控（显式查询动作）。 */
#define CK_ERR(...) pr_info(__VA_ARGS__)
#define CK_LOG(...) do { if (g_verbose) pr_info(__VA_ARGS__); } while (0)

/* ---- 地址换算 ---- */
static unsigned long caoin_va(unsigned long pa)
{
    return (unsigned long)((pa - (u64)*kvar_memstart_addr) + page_offset_base);
}

static void caoin_set_pte(u64 *ptep, u64 val)
{
    *(volatile u64 *)ptep = val;
    /* 硬件页表 walk 直接读内存不走 D-cache：必须 clean+invalidate 才可见
     * （wxshadow 同款修复——此前 tva_faults=0 的最终根因） */
    asm volatile("dc civac, %0" :: "r"(ptep) : "memory");
    asm volatile("dsb ish" ::: "memory");
}

static void caoin_tlb_flush(unsigned long va);

/* ---- 常规页表 walk（mm 的 pgd 内核 VA + VA → PTE 地址）----
 * 39 位 VA = 3 级（pgd[va>>30] → 中层[va>>21] → pte[va>>12]） */
static int caoin_walk_pgd(unsigned long pgd_virt, unsigned long va,
                          unsigned long *pte_a_out)
{
    unsigned long e0, e2, pte_v, pte_a;
    const unsigned long m = CAOIN_PFN_MASK;

    if (kfn_probe_read(&e0, (void *)(pgd_virt + ((va >> 30) & 0x1FF) * 8), 8))
        return 0;
    if (!(e0 & m))
        return 0;
    if (kfn_probe_read(&e2, (void *)caoin_va((e0 & m) + ((va >> 21) & 0x1FF) * 8), 8))
        return 0;
    if (!(e2 & m))
        return 0;
    pte_a = caoin_va((e2 & m) + ((va >> 12) & 0x1FF) * 8);
    if (kfn_probe_read(&pte_v, (void *)pte_a, 8))
        return 0;
    if (pte_a_out)
        *pte_a_out = pte_a;
    return 1;
}

/* 按 hook 的 mm_run_pgd 走任意 VA（存在证明/参数校验用） */
static int caoin_walk_pgd_via_mm(unsigned long va, unsigned long *pte_a_out)
{
    return caoin_walk_pgd(mm_run_pgd, va, pte_a_out);
}

static void status_mark(u64 v);
static void caoin_install_stub(int hi);
static void caoin_install_minstore(int hi);
static void caoin_install_recstub(int hi);
static int stub_mode = 0;   /* 0=替换桩(777) 1=minstore 2=记录透传(recstub) */
static void caoin_sync_after_flip(void); /* 保留:占位 */

/* ---- EL0 页表 PTE flip（按 hook）----
 * 本机实测 TTBR0 == mm->pgd（无 KPTI 副本），故 EL0 表 PTE == mm->pgd 的
 * PTE；一般情形走 el0_table_base（哨兵发现）单独 walk。每 hook 独立缓存。 */
static void caoin_flip_el0(int hi, u64 view)
{
    struct caoin_hook *h = &hooks[hi];
    unsigned long t0, pa, pte_a = 0, pte_v = 0;
    u64 v;

    if (h->el0_pte_addr) {
        if (view == VIEW_SHADOW)
            v = h->shadow_pte_val;
        else if (view == VIEW_STEP)
            v = h->origview_pte_val;
        else
            v = h->orig_pte;
        caoin_set_pte((u64 *)h->el0_pte_addr, v);
        caoin_tlb_flush(h->tva);
        return;
    }
    if (!el0_table_base)
        return;   /* 哨兵未发现 EL0 表：跳过（mm->pgd 主路径已覆盖本机） */
    pa = el0_table_base;
    if (!caoin_walk_pgd(caoin_va(pa), h->tva, &pte_a))
        return;
    if (kfn_probe_read(&pte_v, (void *)pte_a, 8))
        return;
    if ((pte_v & CAOIN_PFN_MASK) != (h->orig_pte & CAOIN_PFN_MASK)
        && (pte_v & CAOIN_PFN_MASK) != (h->shadow_pte_val & CAOIN_PFN_MASK))
        return;   /* 不是本 hook 的页（别的进程/ASID） */
    h->el0_pte_addr = pte_a;
    if (view == VIEW_SHADOW)
        v = (pte_v & ~(CAOIN_PFN_MASK | PTE_AP_MASK | PTE_UXN))
          | (h->shadow_pte_val & CAOIN_PFN_MASK) | 0x80UL;
    else if (view == VIEW_STEP)
        v = (pte_v & ~(PTE_AP_MASK | PTE_UXN)) | 0x40UL | PTE_UXN;
    else
        v = pte_v;
    caoin_set_pte((u64 *)h->el0_pte_addr, v);
    caoin_tlb_flush(h->tva);
    CK_LOG("caoin-kpm: el0 table %lx hook%d pte=%lx view=%llu\n",
           pa, hi, pte_a, (unsigned long long)view);
}

/* ---- mm->pgd 侧 flip（按 hook）---- */
static void caoin_flip_hook(int hi, u64 view)
{
    struct caoin_hook *h = &hooks[hi];
    u64 v1, v2 = 0;

    if (view == VIEW_SHADOW) {
        v1 = h->shadow_pte_val;
        if (h->pte_addr2)
            v2 = h->shadow2_val;
    } else if (view == VIEW_STEP) {
        v1 = h->origview_pte_val;
        if (h->pte_addr2)
            v2 = h->origview2_val;
    } else {
        v1 = h->orig_pte;
        if (h->pte_addr2)
            v2 = h->orig_pte2;
    }
    caoin_set_pte((u64 *)h->pte_addr, v1);
    if (h->pte_addr2)
        caoin_set_pte((u64 *)h->pte_addr2, v2);
}

/* ---- do_page_fault 官方 hook（KP 授权通道，不触发反篡改） ----
 * 4.9 arm64: static int do_page_fault(unsigned long addr, unsigned int esr,
 *                                     struct pt_regs *regs)
 * 命中处理完后 skip_origin=1：原 fault 处理（发信号）不执行，
 * 异常路径 eret 回用户态重执行——这正是跷跷板需要的语义。
 * 注意：不要在此路径上做 pc 大跨度劫持——eret 语义与内核框架冲突（真机踩坑：
 * EL1 取指 abort + 目标卡死），执行流替换由 shadow 页桩完成。 */

struct pt_regs_49 {
    u64 regs[31];
    u64 sp;
    u64 pc;
    u64 pstate;
};

int caoin_fault_check(unsigned long addr, unsigned long pc,
                      unsigned int esr, unsigned long *spsr_p);
static void caoin_tlb_flush(unsigned long va);
static void before_page_fault(hook_fargs3_t *args, void *udata);
static int caoin_is_target_proc(void);

/* ---- do_page_fault hook 主体 ---- */
static void before_page_fault(hook_fargs3_t *args, void *udata)
{
    unsigned long addr = args->arg0;
    unsigned int esr = (unsigned int)args->arg1;
    struct pt_regs_49 *regs = (struct pt_regs_49 *)(unsigned long)args->arg2;
    int handled = 0;
    int hit_hi = -1;
    int i;
    static u64 seen_n;

    /* 取证：fault 发生时的 TTBR0（前 3 条，含他进程） */
    if (seen_n < 3) {
        u64 t0;
        asm volatile("mrs %0, ttbr0_el1" : "=r"(t0));
        CK_LOG("caoin-kpm: pf-regs#%llu ttbr0=%lx far=%lx esr=%x pc=%lx\n",
               seen_n, t0, addr, esr, regs->pc);
        seen_n++;
    }

    /* 哨兵页 fault——放在 vbar_on 门之前：status=5 即唤醒目标，[F]/vfork/读哨兵
     * 可能抢在 arm 完成之前到达（真机实证）。未 arm 时只跳过读 + 吞 SIGSEGV
     * 保住 vfork 共享栈。职责收敛为：发现 EL0 表基址（一次性）。 */
    if (cfg_sent && regs && (addr >> 12) == (cfg_sent >> 12)) {
        unsigned long cur = 0, cmm = 0;
        unsigned long t0, pa;
        asm volatile("mrs %0, sp_el0" : "=r"(cur));
        if (cur && mm_run && kfn_probe_read
            && !kfn_probe_read(&cmm, (void *)(cur + mm_off), 8)
            && cmm == mm_run) {
            if (!el0_table_base) {
                asm volatile("mrs %0, ttbr0_el1" : "=r"(t0));
                pa = t0 & CAOIN_PFN_MASK;
                el0_table_base = pa;
                CK_LOG("caoin-kpm: el0 table via sentinel %lx\n", pa);
            }
            regs->pc += 4;      /* 跳过哨兵读指令 */
            args->skip_origin = 1;
            args->ret = 0;
            sent_cnt++;
            return;
        }
        return;   /* 他进程的哨兵同 VA fault：原生处理 */
    }

    if (!vbar_on || !regs)
        return;

    /* 注入请求探测——必须在跷跷板状态机之前（目标自身 fault 全被 handled
     * 短路，放后面永远不在目标上下文执行）。命中只置标记不劫持：劫持挪到
     * handled 块内（状态机处理完、视图已切）。 */
    if (!inj_armed && kfn_probe_read && cfg_e2) {
        u64 req = 0;
        u64 slot = caoin_va(cfg_e2 + ((unsigned long)cfg_sva & ~CAOIN_PAGE_MASK));
        if (!kfn_probe_read(&req, (void *)slot, 8) && req == INJ_REQ
            && caoin_is_target_proc())
            inj_armed = 1;
    }

    handled = caoin_fault_check(addr, regs->pc, esr, &regs->pstate);
    if (handled) {
        hit_hi = last_hit_hi;
        if (hit_hi >= 0)
            caoin_flip_el0(hit_hi, hooks[hit_hi].cur_view);
        args->skip_origin = 1;
        args->ret = 0;
        /* 状态机处理完（视图已切）再安装：对全部 hook 内核侧直装桩 */
        if (inj_armed && caoin_is_target_proc()) {
            int k;
            inj_armed = 0;
            for (k = 0; k < hooks_n; k++) {
                if (stub_mode == 0)
                    caoin_install_stub(k);
                else if (stub_mode == 1)
                    caoin_install_minstore(k);
                else
                    caoin_install_recstub(k);
            }
        }
        return;
    }
    /* recstub 卡死定位：受管页/影子页取指 fault 现场寄存器 dump（限 4 条） */
    if (regs) {
        static u64 df_n;
        int hit2 = 0, k2;
        for (k2 = 0; k2 < hooks_n; k2++)
            if ((addr >> 12) == (hooks[k2].shva >> 12)
                || (addr >> 12) == (hooks[k2].tva >> 12)
                || (regs->pc >> 12) == (hooks[k2].shva >> 12))
                { hit2 = 1; break; }
        if (hit2 && df_n < 4) {
            CK_ERR("caoin-kpm: DUMP pc=%lx far=%lx esr=%x x0=%lx x16=%lx x19=%lx\n",
                   regs->pc, addr, esr, regs->regs[0], regs->regs[16],
                   regs->regs[19]);
            df_n++;
        }
    }
}

/* ---- 目标进程判别（sp_el0 = current，4.9 THREAD_INFO_IN_TASK）----
 * 主跷跷板路径的进程校验：任何进程对受管页同 VA 的 fault 都会被吞
 * （skip_origin + eret 重试权限未变 → 他进程活锁），flt 取证日志也被
 * 同 VA 噪声污染。 */
static int caoin_is_target_proc(void)
{
    unsigned long cur = 0, cmm = 0;
    asm volatile("mrs %0, sp_el0" : "=r"(cur));
    if (!cur || !mm_run || !kfn_probe_read)
        return 0;
    if (kfn_probe_read(&cmm, (void *)(cur + mm_off), 8))
        return 0;
    return cmm == mm_run;
}

/* ---- 异常过滤（多 hook：2 态直返桩跷跷板） ----
 * SHADOW（shadow | AP=10 X-only）↔ STEP（original | RW+UXN）。
 * SHADOW 下：执行 = 替换桩，读 = fault → 切 STEP；
 * STEP 下：读 = 原页 OK，取指 = UXN fault → 切 SHADOW（eret 重执行取指）。
 * 每个 hook 独立视图状态（cur_view per hook），按 far 页帧匹配分发。 */

static int last_hit_hi = -1;   /* 最近一次处理的 hook 索引（EL0 flip 用） */

int caoin_fault_hook_idx(void)
{
    return last_hit_hi;
}

int caoin_fault_check(unsigned long addr, unsigned long pc,
                      unsigned int esr, unsigned long *spsr_p)
{
    unsigned int ec = esr >> 26;
    int i;
    (void)spsr_p;

    /* 取证：受管页/哨兵页 fault 限速记录。SENT 标记区分哨兵页；
     * 前 30 条无条件记录是系统杂散噪声 */
    {
        static u64 flt_n;
        int managed = 0, sent = (cfg_sent && (addr >> 12) == (cfg_sent >> 12));
        for (i = 0; i < hooks_n; i++)
            if ((addr >> 12) == (hooks[i].tva >> 12)) { managed = 1; break; }
        if (flt_n < 100 && (managed || sent || flt_n < 30)) {
            CK_LOG("caoin-kpm: flt#%llu ec=%x dfsc=%x pc=%lx far=%lx%s\n",
                   flt_n, ec, esr & 0x3f, pc, addr, sent ? " SENT" : "");
            flt_n++;
        }
    }

    /* 找到受管页对应的 hook（多 hook 点按 far 页帧分发） */
    for (i = 0; i < hooks_n; i++) {
        struct caoin_hook *h = &hooks[i];
        if ((addr >> 12) != (h->tva >> 12))
            continue;
        if (!caoin_is_target_proc())
            return 0;   /* 他进程同 VA：放行（勿吞勿翻，防活锁与视图污染） */

        if (ec == 0x24)
            ec24_cnt++;
        else if (ec == 0x20)
            ec20_cnt++;

        /* SHADOW 视图：EL0 数据 fault → 切 STEP（orig 页 RW+UXN）。
         * 不能检查 WnR——DC CIVAC 等 cache 维护指令 fault 时 WnR=1，
         * 放行会让它落进原生路径卡死。STEP 下 eret 重试必成。 */
        if (h->cur_view == VIEW_SHADOW) {
            if (ec != 0x24)
                return 0;   /* 非数据 fault：放行 */
            caoin_flip_hook(i, VIEW_STEP);
            h->cur_view = VIEW_STEP;
            caoin_tlb_flush(h->tva);
            last_hit_hi = i;
            return 1;   /* eret 重试 → orig 页成功 */
        }

        /* STEP 视图：取指 fault（UXN）→ 切 SHADOW 恢复桩执行；
         * 数据 fault（TLB 陈旧命中 SHADOW 翻译）→ 重刷 TLBI 后 eret 重试 */
        if (h->cur_view == VIEW_STEP) {
            if (ec == 0x24) {
                caoin_tlb_flush(h->tva);
                last_hit_hi = i;
                return 1;
            }
            if (ec != 0x20)
                return 0;
            caoin_flip_hook(i, VIEW_SHADOW);
            h->cur_view = VIEW_SHADOW;
            caoin_tlb_flush(h->tva);
            last_hit_hi = i;
            return 1;   /* eret 重取指 → 替换桩 */
        }

        return 0;
    }

    return 0;   /* 非受管页：放行 */
}

static void caoin_tlb_flush(unsigned long va)
{
    /* 实测：vaae1is 在此上下文无效（活锁）；alle1is 清全局项会毁掉
     * KP trampoline 映射（undefined instruction panic）。改用 vmalle1is
     * （清当前 VMID 全 ASID 的非全局项，内核 local_flush_tlb_all 同款） */
    (void)va;
    asm volatile("dsb ish" ::: "memory");
    asm volatile("tlbi vmalle1is" ::: "memory");
    asm volatile("dsb ish" ::: "memory");
    asm volatile("isb" ::: "memory");
}

/* ---- 探测引擎（v1/v2b 验证版复用） ---- */

static int caoin_probe_walk(unsigned long mm_cand, unsigned long pgd_off_cand,
                            unsigned long va, unsigned long expect_phys,
                            unsigned long *pte_a_out)
{
    unsigned long pgd_p, e0, e2, pte_v, pte_a;
    const unsigned long m = CAOIN_PFN_MASK;

    if (kfn_probe_read(&pgd_p, (void *)(mm_cand + pgd_off_cand), 8))
        return 0;
    /* user_pgd（KPTI）由 vmalloc 分配，位于 vmalloc 区（< PAGE_OFFSET），
     * 不能用 page_offset_base 过滤——用内核高段下限 */
    if (pgd_p < 0xffffff8000000000UL || (pgd_p & 0xFFF))
        return 0;
    if (kfn_probe_read(&e0, (void *)(pgd_p + ((va >> 30) & 0x1FF) * 8), 8))
        return 0;
    if (!(e0 & m))
        return 0;
    if (kfn_probe_read(&e2, (void *)caoin_va((e0 & m) + ((va >> 21) & 0x1FF) * 8), 8))
        return 0;
    if (!(e2 & m))
        return 0;
    pte_a = caoin_va((e2 & m) + ((va >> 12) & 0x1FF) * 8);
    if (kfn_probe_read(&pte_v, (void *)pte_a, 8))
        return 0;
    if (expect_phys && (pte_v & m) != expect_phys)
        return 0;
    if (pte_a_out)
        *pte_a_out = pte_a;
    return 1;
}

static int caoin_locate(unsigned long task, unsigned long va, unsigned long expect_phys,
                        unsigned long va2, unsigned long expect2,
                        unsigned long *mm_off_out, unsigned long *pgd_off_out,
                        unsigned long *mm_out, unsigned long *pte_a_out)
{
    unsigned long mm_c, pgd_p, moff, poff;
    for (moff = 0; moff < 0x1800; moff += 8) {
        if (kfn_probe_read(&mm_c, (void *)(task + moff), 8))
            continue;
        if (mm_c < page_offset_base || (mm_c & 0x7))
            continue;
        for (poff = 0x20; poff < 0x400; poff += 8) {
            if (kfn_probe_read(&pgd_p, (void *)(mm_c + poff), 8))
                continue;
            if (pgd_p < page_offset_base || (pgd_p & 0xFFF))
                continue;
            if (caoin_probe_walk(mm_c, poff, va, expect_phys, pte_a_out)
                && caoin_probe_walk(mm_c, poff, va2, expect2, 0)) {
                *mm_off_out = moff;
                *pgd_off_out = poff;
                if (mm_out)
                    *mm_out = mm_c;
                return 1;
            }
        }
    }
    return 0;
}

static void caoin_write_status(unsigned long va, u64 val)
{
    unsigned long pte_a = 0, pte_v, phys, before = 0, after = 0;
    if (!caoin_probe_walk(mm_run, pgd_off, va, 0, &pte_a))
        { CK_LOG("caoin-kpm: wstat walk fail va=%lx\n", va); return; }
    if (kfn_probe_read(&pte_v, (void *)pte_a, 8))
        return;
    phys = pte_v & CAOIN_PFN_MASK;
    {
        u64 *slot = (u64 *)caoin_va(phys + (va & ~CAOIN_PAGE_MASK));
        /* slot 无效（phys 垃圾）时绝不能走到 dc civac——cache 维护指令对
         * 无映射地址无 exception fixup，直接 panic（真机多次实证）。
         * probe_read 成功 = slot 可翻译，才允许写 + civac。 */
        if (kfn_probe_read(&before, (void *)slot, 8))
            { CK_LOG("caoin-kpm: wstat slot unreadable %p\n", slot); return; }
        if (!kfn_probe_write || kfn_probe_write(slot, &val, 8) != 0)
            { CK_ERR("caoin-kpm: wstat write fail %p\n", slot); return; }
        asm volatile("dc civac, %0" :: "r"(slot) : "memory");
        kfn_probe_read(&after, (void *)slot, 8);
        CK_LOG("caoin-kpm: wstat va=%lx slot=%llx %llx->%llx (want %llx)\n",
               va, (unsigned long long)(unsigned long)slot,
               (unsigned long long)before, (unsigned long long)after,
               (unsigned long long)val);
    }
    asm volatile("dsb ish" ::: "memory");
}

/* ---- 参数解析 ---- */

static u64 parse_hex(const char *s)
{
    u64 v = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;
    while (1) {
        char ch = *s;
        u64 d;
        if (ch >= '0' && ch <= '9') d = ch - '0';
        else if (ch >= 'a' && ch <= 'f') d = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F') d = ch - 'A' + 10;
        else break;
        v = v * 16 + d;
        s++;
    }
    return v;
}

static void parse_args(const char *args)
{
    const char *p = args;
    while (p && *p) {
        if (!strncmp(p, "pid=", 4)) cfg_pid = parse_hex(p + 4);
        else if (!strncmp(p, "sva=", 4)) cfg_sva = parse_hex(p + 4);
        else if (!strncmp(p, "e2=", 3)) cfg_e2 = parse_hex(p + 3);
        else if (!strncmp(p, "sent=", 5)) cfg_sent = parse_hex(p + 5);
        else if (!strncmp(p, "csize0=", 7)) hooks[0].copy_size = parse_hex(p + 7);
        else if (!strncmp(p, "csize1=", 7)) hooks[1].copy_size = parse_hex(p + 7);
        else if (!strncmp(p, "csize2=", 7)) hooks[2].copy_size = parse_hex(p + 7);
        else if (!strncmp(p, "csize3=", 7)) hooks[3].copy_size = parse_hex(p + 7);
        else if (!strncmp(p, "verbose=", 8)) g_verbose = parse_hex(p + 8);
        else if (!strncmp(p, "stub=", 5)) g_stub_onload = parse_hex(p + 5);
        else if (!strncmp(p, "tva=", 4)) hooks[0].tva = parse_hex(p + 4);
        else if (!strncmp(p, "shva=", 5)) hooks[0].shva = parse_hex(p + 5);
        else if (!strncmp(p, "tva1=", 5)) hooks[1].tva = parse_hex(p + 5);
        else if (!strncmp(p, "shva1=", 6)) hooks[1].shva = parse_hex(p + 6);
        else if (!strncmp(p, "tva2=", 5)) hooks[2].tva = parse_hex(p + 5);
        else if (!strncmp(p, "shva2=", 6)) hooks[2].shva = parse_hex(p + 6);
        else if (!strncmp(p, "tva3=", 5)) hooks[3].tva = parse_hex(p + 5);
        else if (!strncmp(p, "shva3=", 6)) hooks[3].shva = parse_hex(p + 6);
        p = strchr(p, ' ');
        if (p) p++;
    }
}

/* 注：cfg_from_file（内核态 kernel_read 读 tdyn4.out）已移除。
 * 理由：① args 全量传参时它完全冗余（运行脚本先解析 tdyn4.out 再传 args）；
 * ② kernel_read 在部分 KP 环境的 supercall 上下文挂死（历史踩坑）；
 * ③ 0.4.1 真机实证：本函数参与时 kpm load 在 KP loader 分配区特定基址下
 *    内核 panic（fault = .bss 地址 + 2^44，ADRP/重定位级错位，两次开机必现），
 *    禁用后同环境全绿。若未来需要文件配置，走用户态解析后传 args。 */

/* ---- exit_mmap 伴侣钩子（wxshadow 同款）----
 * zap_pte_range 按 PTE 释放物理页：目标进程退出时 PTE 若停在 SHADOW
 * （PFN = shadow anon 页），shadow 页会被双重 unmap + rss 记账错位 →
 * "Bad page state / Bad rss-counter" → 坏页流入后续分配 → 无关进程内核
 * 态死循环（SIGKILL 不可杀，重启才恢复；真机实证）。exit_mmap 入口
 * mmap_sem 未持有、mm 仍活——此刻恢复全部受管页原 PTE，zap 走原页。 */
static void exit_mmap_before(hook_fargs1_t *args, void *udata)
{
    void *mm = (void *)(unsigned long)args->arg0;
    int i;

    (void)udata;
    if (!vbar_on || (void *)mm_run != mm)
        return;
    for (i = 0; i < hooks_n; i++) {
        caoin_set_pte((u64 *)hooks[i].pte_addr, hooks[i].orig_pte);
        if (hooks[i].el0_pte_addr && hooks[i].el0_pte_addr != hooks[i].pte_addr)
            caoin_set_pte((u64 *)hooks[i].el0_pte_addr, hooks[i].orig_pte);
        hooks[i].cur_view = VIEW_OFF;
    }
    caoin_tlb_flush(0);
    CK_LOG("caoin-kpm: exit_mmap: %d hook PTEs restored for dying mm=%lx\n",
           hooks_n, (unsigned long)mm);
}

/* ---- copy_process fork 防护（wxshadow 同款）----
 * fork 时 copy_process 快照父进程页表：受管页 PTE 若停在 SHADOW/STEP，
 * 子进程会继承 shadow 页 PFN，内核按 shadow 页记账子进程 RSS/rmap →
 * 后续 teardown 触发 "Bad rss-counter / Bad page map"。
 * 防护 = fork 前把受管页 PTE 恢复原值（pause），copy_process 返回后翻回
 * 原视图（resume）。只处理非 CLONE_VM（线程共享 mm，无页表快照）。
 * 状态经 args->local.data[0] 在 before/after 间传递（KP 保证同一次调用共享）。
 * 与 caoin_fault_check 的并发：pause/resume 都只在本线程（fork 者）上下文
 * 执行，其他线程对受管页的 fault 由状态机独立处理，不冲突。 */
static void before_copy_process(hook_fargs8_t *args, void *udata)
{
    unsigned long clone_flags = (unsigned long)args->arg0;
    int i;

    (void)udata;
    args->local.data[0] = 0;
    if (!vbar_on)
        return;
    if (clone_flags & CLONE_VM)      /* 线程：共享 mm，无页表快照 */
        return;
    if (!caoin_is_target_proc())     /* 只处理目标进程的 fork */
        return;
    args->local.data[0] = 1;
    for (i = 0; i < hooks_n; i++) {
        caoin_flip_hook(i, VIEW_OFF);
        if (hooks[i].el0_pte_addr && hooks[i].el0_pte_addr != hooks[i].pte_addr)
            caoin_set_pte((u64 *)hooks[i].el0_pte_addr, hooks[i].orig_pte);
    }
    caoin_tlb_flush(0);
    CK_LOG("caoin-kpm: fork pause (%d hooks)\n", hooks_n);
}

static void after_copy_process(hook_fargs8_t *args, void *udata)
{
    int i;

    (void)udata;
    if (!args->local.data[0])
        return;
    args->local.data[0] = 0;
    for (i = 0; i < hooks_n; i++) {
        caoin_flip_hook(i, hooks[i].cur_view);
        caoin_flip_el0(i, hooks[i].cur_view);
    }
    caoin_tlb_flush(0);
    CK_LOG("caoin-kpm: fork resume (%d hooks)\n", hooks_n);
}

/* ---- 卸载：非 hotpatch 摘链 ----
 * hook_unwrap() 最终走 hotpatch()（正常选 stop_machine，睡眠调用），而 KP
 * 在 rcu_read_lock() 下调模块 exit()；即便不锁死，恢复原指令的窗口也会被
 * 其他 CPU 取指命中。caoin-hw 真机实证：卸载 __switch_to 时
 *   Internal error: undefined instruction: 0, PC is at __switch_to+0x8
 * → panic。do_page_fault/exit_mmap 同为高频/关键路径，同样风险。
 * hook_unwrap_remove(...,0) 只把链项置空（不 sleep、不恢复指令），函数保留
 * 跳 KP trampoline（空链 → tail-call 原函数），无竞态。before/after 必须与
 * hook 时一致（用于匹配链项）。 */
static void caoin_unhook(void *func, void *before, void *after)
{
    if (func)
        hook_unwrap_remove(func, before, after, 0);
}

static long caoin_restore(void)
{
    void *dpf, *em;
    int i;
    if (!vbar_on)
        return 0;
    /* 先断流：vbar_on=0 后 hook 入口对一切 fault 纯放行，
     * 之后 unwrap/恢复动作不再有并发 hook 竞态 */
    vbar_on = 0;
    /* 目标存活校验：目标已死则页表随 mm 释放，写悬挂 pte_addr = 随机
     * 内存写（页表页可能已复用）。死亡时 exit_mmap 钩子已恢复过 PTE，
     * 此处跳过即是正确语义。 */
    if (kfn_find_task_by_vpid) {
        void *task = kfn_find_task_by_vpid((int)cfg_pid);
        unsigned long cmm = 0;
        if (task && !kfn_probe_read(&cmm, (void *)(task + mm_off), 8)
            && cmm == mm_run) {
            for (i = 0; i < hooks_n; i++) {
                caoin_flip_hook(i, VIEW_OFF);
                if (hooks[i].el0_pte_addr && hooks[i].el0_pte_addr != hooks[i].pte_addr)
                    caoin_set_pte((u64 *)hooks[i].el0_pte_addr, hooks[i].orig_pte);
                hooks[i].cur_view = VIEW_OFF;
            }
        } else {
            CK_LOG("caoin-kpm: target gone, PTE left to dying mm\n");
        }
    }
    caoin_tlb_flush(0);
    dpf = (void *)(unsigned long)kallsyms_lookup_name("do_page_fault");
    if (dpf)
        caoin_unhook(dpf, before_page_fault, NULL);
    em = (void *)(unsigned long)kallsyms_lookup_name("exit_mmap");
    if (em)
        caoin_unhook(em, exit_mmap_before, NULL);
    if (g_copy_process)
        caoin_unhook(g_copy_process, before_copy_process, after_copy_process);
    caoin_write_status(cfg_sva, 0xF);
    CK_LOG("caoin-kpm: off, restored (%d hooks)\n", hooks_n);
    return 0;
}

/* ---- 内核侧桩安装（按 hook）----
 * 在目标线程上下文（current 已验证）经页表 walk 取 tva/shva 物理帧 →
 * 内核线性地址直写桩（movz w0,#ret_val; ret）→ dc cvau/ic ivau
 * （线性地址；I-cache PIPT，同物理帧等效）。
 * 注意：绝不能对用户 VA 直接做 dc cvau/ic ivau——SW_TTBR0_PAN 机器上
 * EL1 的 TTBR0 为空表，这些指令直接 translation fault（真机实证）。 */
static void caoin_install_stub(int hi)
{
    struct caoin_hook *h = &hooks[hi];
    unsigned long pte_a = 0, pte_v = 0, kva;
    volatile u32 *stub;
    u32 enc;

    if (caoin_walk_pgd_via_mm(h->shva, &pte_a)
        && !kfn_probe_read(&pte_v, (void *)pte_a, 8)
        && (pte_v & CAOIN_PFN_MASK)) {
        kva = caoin_va(pte_v & CAOIN_PFN_MASK) + h->shva_off;
        enc = 0x52800000u | ((u32)(h->ret_val & 0xFFFF) << 5);
        stub = (volatile u32 *)kva;
        stub[0] = enc;                       /* movz w0, #ret_val */
        stub[1] = 0xD65F03C0u;               /* ret */
        {
            unsigned long o2;
            for (o2 = 0; o2 < 0x1000; o2 += 64) {
                asm volatile("dc cvau, %0" :: "r"(kva - h->shva_off + o2));
                asm volatile("ic ivau, %0" :: "r"(kva - h->shva_off + o2));
            }
            asm volatile("dsb ish" ::: "memory");
            asm volatile("isb" ::: "memory");
        }
        status_mark(0xCA0FCA03ULL);
        CK_ERR("caoin-kpm: hook%d stub installed shva=%lx off=%lx val=%d\n",
               hi, h->shva, h->shva_off, (int)(h->ret_val & 0xFFFF));
    } else {
        CK_ERR("caoin-kpm: hook%d shva walk fail\n", hi);
    }
}

/* ---- 记录 + 透传桩安装（真实 hook 语义，按 hook）----
 * 布局（影子页内）：
 *   shva+off     : 序言 —— x16=报告地址(shva+0xF00)；str x0..x3 → 报告区；
 *                  b scratch(+0x800)
 *   shva+0x800   : 原函数指令拷贝（scratch，从 tva 线性地址读原页拷贝）
 *   shva+0xF00   : 报告区 x0..x3 快照（tdyn4 每轮读取打印）
 * 执行流：调用进桩(SHADOW 可执行) → 记录参数 → b 同页 scratch 跑原逻辑
 * → 原函数自身 ret 返回调用者。全程影子页内，无 fault 依赖。
 * 限制：scratch 内 PC 相对指令（adrp/b/bl）不做重定位——目标函数须为
 * 寄存器运算型（真实场景接 P2 reloc.c 的重定位器）。 */

/* 模式1:最小 store 桩 —— movz/movk x16=shva+0xF00, x17=魔数, str x17,[x16], ret
 * 与 777 桩只差"装载+一条 store":隔离 store 类桩是否可行 */
static void caoin_install_minstore(int hi)
{
    struct caoin_hook *h = &hooks[hi];
    unsigned long pte_a = 0, pte_v = 0, kva, report;
    volatile u32 *stub;
    u64 magic = 0xCA0FCA51ULL;

    if (!caoin_walk_pgd_via_mm(h->shva, &pte_a)
        || kfn_probe_read(&pte_v, (void *)pte_a, 8)
        || !(pte_v & CAOIN_PFN_MASK))
        { CK_ERR("caoin-kpm: hook%d minstore walk fail\n", hi); return; }
    kva = caoin_va(pte_v & CAOIN_PFN_MASK) + h->shva_off;
    report = h->shva + 0xF00;
    stub = (volatile u32 *)kva;
    stub[0] = 0xD2800000u | ((u32)((report >> 0)  & 0xFFFF) << 5) | 16;
    stub[1] = 0xF2A00000u | ((u32)((report >> 16) & 0xFFFF) << 5) | 16;
    stub[2] = 0xF2C00000u | ((u32)((report >> 32) & 0xFFFF) << 5) | 16;
    stub[3] = 0xF2E00000u | ((u32)((report >> 48) & 0xFFFF) << 5) | 16;
    stub[4] = 0xD2800000u | ((u32)(magic & 0xFFFF) << 5) | 17;
    stub[5] = 0xF2A00000u | ((u32)((magic >> 16) & 0xFFFF) << 5) | 17;
    stub[6] = 0xF9000220u;               /* str x17, [x16] */
    stub[7] = 0xD65F03C0u;               /* ret */
    {
        unsigned long o2;
        for (o2 = 0; o2 < 0x1000; o2 += 64) {
            asm volatile("dc cvau, %0" :: "r"(kva - h->shva_off + o2));
            asm volatile("ic ivau, %0" :: "r"(kva - h->shva_off + o2));
        }
        asm volatile("dsb ish" ::: "memory");
        asm volatile("isb" ::: "memory");
        for (o2 = 0; o2 < 200; o2++)     /* 自旋排空:本核流水线/写缓冲 */
            asm volatile("nop");
        asm volatile("dsb ish" ::: "memory");
    }
    /* ic iallu: 失效本核全部 I-cache(install 核=目标 fault 核,eret 后目标
     * 就在本核执行)——比逐行 ic ivau 更彻底,消除行内陈旧混合 */
    asm volatile("ic iallu" ::: "memory");
    asm volatile("dsb ish" ::: "memory");
    asm volatile("isb" ::: "memory");
    status_mark(0xCA0FCA51ULL);
    CK_ERR("caoin-kpm: hook%d minstore installed shva=%lx report=%lx\n",
           hi, h->shva, report);
}

static void caoin_install_recstub(int hi)
{
    struct caoin_hook *h = &hooks[hi];
    unsigned long tpte_a = 0, tpte_v = 0, spte_a = 0, spte_v = 0;
    unsigned long tl, sl, off = h->shva_off;
    u64 report = h->shva + 0xF00;
    u32 enc[16];
    int n = 0;
    unsigned long o2, i2;

    if (!caoin_walk_pgd_via_mm(h->tva, &tpte_a)
        || kfn_probe_read(&tpte_v, (void *)tpte_a, 8)
        || !(tpte_v & CAOIN_PFN_MASK))
        { CK_ERR("caoin-kpm: hook%d tva walk fail\n", hi); return; }
    if (!caoin_walk_pgd_via_mm(h->shva, &spte_a)
        || kfn_probe_read(&spte_v, (void *)spte_a, 8)
        || !(spte_v & CAOIN_PFN_MASK))
        { CK_ERR("caoin-kpm: hook%d shva walk fail\n", hi); return; }
    tl = caoin_va(tpte_v & CAOIN_PFN_MASK);
    sl = caoin_va(spte_v & CAOIN_PFN_MASK);

    /* 原函数指令 → 影子页 scratch（+0x800） */
    for (i2 = 0; i2 < h->copy_size; i2 += 4) {
        u64 insn = 0;
        if (!kfn_probe_read(&insn, (void *)(tl + off + i2), 4))
            *(u32 *)(sl + 0x800 + i2) = (u32)insn;
    }

    /* 序言：x16 = 报告地址（4 条 movz/movk），x0..x3 入报告区，b scratch */
    enc[n++] = 0xD2800000u | ((u32)((report >> 0)  & 0xFFFF) << 5) | 16;
    enc[n++] = 0xF2A00000u | ((u32)((report >> 16) & 0xFFFF) << 5) | 16;
    enc[n++] = 0xF2C00000u | ((u32)((report >> 32) & 0xFFFF) << 5) | 16;
    enc[n++] = 0xF2E00000u | ((u32)((report >> 48) & 0xFFFF) << 5) | 16;
    enc[n++] = 0xF9000200u;   /* str x0, [x16] */
    enc[n++] = 0xF9000401u;   /* str x1, [x16, #8] */
    enc[n++] = 0xF9000802u;   /* str x2, [x16, #16] */
    enc[n++] = 0xF9000C03u;   /* str x3, [x16, #24] */
    /* magic 探针:x17=0xCA0FCA11 -> [x16,#0x40] —— 区分"报告区不可见"与"写 0" */
    enc[n++] = 0xD2994231u;   /* movz x17, #0xCA11 */
    enc[n++] = 0xF2B941F1u;   /* movk x17, #0xCA0F, lsl #16 */
    enc[n++] = 0xF9000A11u;   /* str x17, [x16, #0x40] */
    {
        long delta = (long)(((0x800 - off) >> 2) & 0x03FFFFFF);
        enc[n++] = 0x14000000u | (u32)delta;   /* b scratch */
    }
    for (o2 = 0; o2 < (unsigned long)n; o2++)
        *(volatile u32 *)(sl + off + o2 * 4) = enc[o2];

    /* cache 维护：桩区 + scratch 区（线性地址，I-cache PIPT 等效） */
    for (o2 = 0; o2 < 0x1000; o2 += 64) {
        asm volatile("dc cvau, %0" :: "r"(sl + o2));
        asm volatile("ic ivau, %0" :: "r"(sl + o2));
    }
    asm volatile("dsb ish" ::: "memory");
    asm volatile("isb" ::: "memory");
    status_mark(0xCA0FCA03ULL);
    CK_ERR("caoin-kpm: hook%d recstub installed shva=%lx off=%lx scratch=800 report=f00 csize=%lx\n",
           hi, h->shva, off, h->copy_size);
}

/* status 打标（经 status 页物理帧线性地址；帧 PFN=cfg_e2，init 自推导） */
static void status_mark(u64 v)
{
    u64 *statusp = (u64 *)(caoin_va(cfg_e2 & CAOIN_PFN_MASK)
                           + ((unsigned long)cfg_sva & 0xFFUL));
    statusp[0] = v;
    asm volatile("dc civac, %0" :: "r"(statusp) : "memory");
}

/* ---- KPM 入口 ---- */

static long caoin_init(const char *args, const char *event, void *__user reserved)
{
    unsigned long mm_off_out, pgd_off_out, pte_a = 0, mmv = 0, orig_pte_v = 0;
    void *task;
    int i;

    (void)event;
    (void)reserved;

    if (vbar_on) {
        CK_LOG("caoin-kpm: already active\n");
        return -1;
    }
    parse_args(args);
    /* hook 数量统计（tva 非零即有效） */
    hooks_n = 0;
    for (i = 0; i < CAOIN_MAX_HOOKS; i++)
        if (hooks[i].tva && hooks[i].shva)
            hooks_n = i + 1;
    if (!cfg_pid || !cfg_sva || !hooks_n) {
        CK_ERR("caoin-kpm: missing args (pid/sva + tva/shva per hook)\n");
        return -1;
    }
    /* shva_off：受管函数页内偏移。自动 = tva & 0xFFF——实战目标函数通常不在
     * 页首（tdyn4 的 aligned(4096) 只是测试简化），tva 可直接传符号地址。
     * copy_size：原函数指令区大小（csize0/csize1…，默认 0x40） */
    for (i = 0; i < CAOIN_MAX_HOOKS; i++) {
        hooks[i].copy_size = 0x40;
        if (hooks[i].tva)
            hooks[i].shva_off = hooks[i].tva & 0xFFFUL;
    }
    for (i = hooks_n; i < CAOIN_MAX_HOOKS; i++) {
        hooks[i].tva = 0;
        hooks[i].shva = 0;
    }

    /* PAGE_OFFSET：TCR_EL1.T1SZ */
    {
        u64 tcr, t1sz;
        asm volatile("mrs %0, tcr_el1" : "=r"(tcr));
        t1sz = (tcr >> 16) & 0x3f;
        page_offset_base = ~0UL << (64 - t1sz - 1);
        CK_LOG("caoin-kpm: tcr=%lx t1sz=%llu page_off=%lx\n",
               (unsigned long)tcr, (unsigned long long)t1sz,
               page_offset_base);
    }
    kvar_memstart_addr = (s64 *)kallsyms_lookup_name("memstart_addr");
    kfn_probe_read = (void *)kallsyms_lookup_name("probe_kernel_read");
    kfn_probe_write = (void *)kallsyms_lookup_name("probe_kernel_write");
    kfn_find_task_by_vpid = (void *)kallsyms_lookup_name("find_task_by_vpid");
    if (!kvar_memstart_addr || !kfn_probe_read || !kfn_find_task_by_vpid) {
        CK_ERR("caoin-kpm: symbol resolve failed (memstart=%lx probe=%lx find=%lx)\n",
               (unsigned long)kvar_memstart_addr,
               (unsigned long)kfn_probe_read,
               (unsigned long)kfn_find_task_by_vpid);
        return -1;
    }
    CK_LOG("caoin-kpm: memstart=%llx hooks=%d args ok\n",
           (unsigned long long)(s64)*kvar_memstart_addr, hooks_n);

    task = kfn_find_task_by_vpid((int)cfg_pid);
    if (!task) {
        CK_ERR("caoin-kpm: pid %llu not found\n",
               (unsigned long long)cfg_pid);
        return -1;
    }

    /* hook0 定位（拿 mm_off/pgd_off/mm_run；其余 hook 复用同一 mm/pgd） */
    if (!caoin_locate((unsigned long)task, hooks[0].tva, 0,
                      cfg_sva, 0, &mm_off_out, &pgd_off_out, &mmv, &pte_a)) {
        CK_ERR("caoin-kpm: locate fail\n");
        return -1;
    }
    mm_off = mm_off_out;
    pgd_off = pgd_off_out;
    mm_run = mmv;
    kfn_probe_read(&mm_run_pgd, (void *)(mmv + pgd_off_out), 8);
    hooks[0].pte_addr = pte_a;
    caoin_write_status(cfg_sva, 0x5);
    CK_LOG("caoin-kpm: combo locked mm=%lx pgd=%lx pte=%lx\n",
           mm_off_out, pgd_off_out, pte_a);

    /* status 页 PFN 自推导 */
    if (!cfg_e2) {
        unsigned long stpte = 0, stv = 0;
        if (caoin_probe_walk(mmv, pgd_off_out, cfg_sva, 0, &stpte)
            && !kfn_probe_read(&stv, (void *)stpte, 8))
            cfg_e2 = stv & CAOIN_PFN_MASK;
    }

    /* 逐 hook：orig PTE / phys 自推导 / shadow+origview PTE 值 */
    for (i = 0; i < hooks_n; i++) {
        struct caoin_hook *h = &hooks[i];
        unsigned long orig_v = 0, spte = 0, spv = 0;

        if (i != 0) {
            if (!caoin_probe_walk(mmv, pgd_off_out, h->tva, 0, &pte_a))
                { CK_ERR("caoin-kpm: hook%d pte walk fail\n", i); return -1; }
            h->pte_addr = pte_a;
        }
        if (kfn_probe_read(&orig_v, (void *)h->pte_addr, 8))
            return -1;
        h->orig_pte = orig_v;

        /* sphys 自推导（pagemap PFN 被 CAP_SYS_ADMIN 剥离的备胎） */
        if (caoin_probe_walk(mmv, pgd_off_out, h->shva, 0, &spte)
            && !kfn_probe_read(&spv, (void *)spte, 8))
            h->shadow_pte_val = spv & CAOIN_PFN_MASK;   /* 暂存 PFN */
        if (!h->shadow_pte_val || !orig_v) {
            CK_ERR("caoin-kpm: hook%d derive fail\n", i);
            return -1;
        }
        /* shadow 视图：PFN→shadow，AP=10（EL0 数据 fault，取指走 X-only） */
        h->shadow_pte_val = (orig_v & ~(CAOIN_PFN_MASK | PTE_AP_MASK | PTE_UXN))
                          | (h->shadow_pte_val & CAOIN_PFN_MASK) | 0x80UL;
        /* original 视图：AP=01 = EL0 RW（不是 RO！dc civac 等 WnR=1 的
         * cache 维护指令在 STEP 视图必须成功，真 RO 会死循环）+ UXN=1 */
        h->origview_pte_val = (orig_v & ~(PTE_AP_MASK | PTE_UXN))
                            | 0x40UL | PTE_UXN;
        h->ret_val = 777 + i;   /* 桩模板：777/778/779…（区分 hook 点） */
        CK_LOG("caoin-kpm: hook%d tva=%lx shva=%lx pte=%lx ret=%d\n",
               i, h->tva, h->shva, h->pte_addr, (int)(h->ret_val & 0xFFFF));
    }

    /* KPTI 副本兜底扫描：只对 hook0 做一次性扫描（本机 TTBR0==mm->pgd 无副本；
     * 若找到 pte_addr2，其余 hook 在同一张副本表里 walk 同表得各自 PTE） */
    hooks[0].pte_addr2 = 0;
    {
        unsigned long off, upgd, uptea = 0, uppte;
        for (off = 0x40; off < 0x1000; off += 8) {
            if (kfn_probe_read(&upgd, (void *)(mmv + off), 8))
                continue;
            if (upgd < page_offset_base || (upgd & 0xFFF))
                continue;
            if (!caoin_probe_walk(mmv + off, 0, hooks[0].tva, 0, &uptea))
                continue;
            if (!kfn_probe_read(&uppte, (void *)uptea, 8))
                continue;
            if ((uppte & CAOIN_PFN_MASK) != (hooks[0].orig_pte & CAOIN_PFN_MASK))
                continue;
            if (uptea == hooks[0].pte_addr)
                continue;
            hooks[0].pte_addr2 = uptea;
            hooks[0].orig_pte2 = uppte;
            hooks[0].shadow2_val = (uppte & ~(CAOIN_PFN_MASK | PTE_AP_MASK | PTE_UXN))
                                 | (hooks[0].shadow_pte_val & CAOIN_PFN_MASK) | 0x80UL;
            hooks[0].origview2_val = (uppte & ~(PTE_AP_MASK | PTE_UXN))
                                   | 0x40UL | PTE_UXN;
            /* 其余 hook：同一张副本表里走各自 tva */
            for (i = 1; i < hooks_n; i++) {
                unsigned long upte_a = 0, upte_v = 0;
                if (caoin_walk_pgd(caoin_va(upgd), hooks[i].tva, &upte_a)
                    && !kfn_probe_read(&upte_v, (void *)upte_a, 8)) {
                    hooks[i].pte_addr2 = upte_a;
                    hooks[i].orig_pte2 = upte_v;
                    hooks[i].shadow2_val = (upte_v & ~(CAOIN_PFN_MASK | PTE_AP_MASK | PTE_UXN))
                                         | (hooks[i].shadow_pte_val & CAOIN_PFN_MASK) | 0x80UL;
                    hooks[i].origview2_val = (upte_v & ~(PTE_AP_MASK | PTE_UXN))
                                           | 0x40UL | PTE_UXN;
                }
            }
            CK_LOG("caoin-kpm: user_pgd@%lx found (KPTI copy)\n", mmv + off);
            break;
        }
        if (!hooks[0].pte_addr2)
            CK_LOG("caoin-kpm: user_pgd NOT found (TTBR0==mm->pgd)\n");
    }

    /* ---- 官方 hook do_page_fault ---- */
    {
        void *dpf = (void *)(unsigned long)kallsyms_lookup_name("do_page_fault");
        hook_err_t err;
        if (!dpf) {
            CK_ERR("caoin-kpm: do_page_fault not found\n");
            return -1;
        }
        err = hook_wrap3(dpf, before_page_fault, NULL, NULL);
        if (err != HOOK_NO_ERR) {
            CK_ERR("caoin-kpm: hook dpf fail err=%d\n", err);
            return -1;
        }
        CK_LOG("caoin-kpm: dpf hooked @%lx\n", (unsigned long)dpf);
    }
    /* 伴侣钩子：目标退出时 zap 前恢复原 PTE（防 shadow 页双重 unmap →
     * 坏页 → 无关进程内核死循环）。找不到/hook 失败则拒绝 arm（不安全）；
     * 此时尚未 vbar_on=1，须手动拆 dpf hook。 */
    {
        void *em = (void *)(unsigned long)kallsyms_lookup_name("exit_mmap");
        void *dpf2 = (void *)(unsigned long)kallsyms_lookup_name("do_page_fault");
        hook_err_t err;
        if (!em) {
            CK_ERR("caoin-kpm: exit_mmap not found\n");
            if (dpf2) caoin_unhook(dpf2, before_page_fault, NULL);
            return -1;
        }
        err = hook_wrap1(em, exit_mmap_before, NULL, NULL);
        if (err != HOOK_NO_ERR) {
            CK_ERR("caoin-kpm: hook exit_mmap fail err=%d\n", err);
            if (dpf2) caoin_unhook(dpf2, before_page_fault, NULL);
            return -1;
        }
        CK_LOG("caoin-kpm: exit_mmap hooked @%lx\n", (unsigned long)em);
    }
    /* fork 防护（安全增强，可选）：装不上只 warn——缺它不影响主链路，
     * 只在目标 fork 时留 RSS 记账风险（见 before_copy_process 注释）。 */
    {
        g_copy_process = (void *)(unsigned long)kallsyms_lookup_name("copy_process");
        if (g_copy_process) {
            hook_err_t e2 = hook_wrap8(g_copy_process, before_copy_process,
                                       after_copy_process, NULL);
            if (e2 != HOOK_NO_ERR) {
                CK_ERR("caoin-kpm: hook copy_process fail err=%d (fork 防护关闭)\n", e2);
                g_copy_process = NULL;
            } else {
                CK_LOG("caoin-kpm: copy_process hooked @%lx (fork 防护开)\n",
                       (unsigned long)g_copy_process);
            }
        } else {
            CK_ERR("caoin-kpm: copy_process not found (fork 防护关闭)\n");
        }
    }
    vbar_on = 1;

    /* PTE 预检 + 全部 hook 翻 SHADOW */
    for (i = 0; i < hooks_n; i++) {
        unsigned long cur_v = 0;
        kfn_probe_read(&cur_v, (void *)hooks[i].pte_addr, 8);
        if (kfn_probe_write((void *)hooks[i].pte_addr, &cur_v, 8) != 0) {
            CK_ERR("caoin-kpm: hook%d pte slot not writable, bail\n", i);
            caoin_restore();
            return -1;
        }
        caoin_flip_hook(i, VIEW_SHADOW);
        hooks[i].cur_view = VIEW_SHADOW;
    }
    caoin_write_status(cfg_sva, 0x6);
    {
        unsigned long back = 0;
        kfn_probe_read(&back, (void *)hooks[0].pte_addr, 8);
        CK_LOG("caoin-kpm: pte want=%lx back=%lx @%lx\n",
               hooks[0].shadow_pte_val, back, hooks[0].pte_addr);
    }
    caoin_write_status(cfg_sva, 0x7);
    /* stub=1：加载即装桩（跳过 INJ_REQ 握手）。caoin_prep 自动化流程用——
     * 目标不发注入请求，工具已备好影子页（原页快照）与 status 页。
     * 桩经目标 mm 的页表 walk 写入 shadow 页，不需要目标 fault 上下文。 */
    if (g_stub_onload) {
        for (i = 0; i < hooks_n; i++)
            caoin_install_stub(i);
        CK_LOG("caoin-kpm: stub=1 → %d stubs installed at load\n", hooks_n);
    }
    CK_LOG("caoin-kpm: on (%d hooks, dpf hooked, seesaw armed)\n", hooks_n);
    return 0;
}

/* 运行时控制：args="restore" 手动恢复 */
static long caoin_ctl0(const char *args, char *__user out_msg, int outlen)
{
    int i;
    (void)out_msg;
    (void)outlen;
    if (args && !strcmp(args, "restore"))
        return caoin_restore();
    pr_info("caoin-kpm: armed=%llu hooks=%d mm=%lx\n",
            (unsigned long long)vbar_on, hooks_n, mm_run);
    for (i = 0; i < hooks_n; i++)
        pr_info("caoin-kpm: hook%d tva=%lx view=%s pte=%lx ec20=%llu ec24=%llu\n",
                i, hooks[i].tva,
                hooks[i].cur_view == VIEW_SHADOW ? "shadow" :
                hooks[i].cur_view == VIEW_STEP ? "stepping" : "orig",
                hooks[i].pte_addr,
                (unsigned long long)ec20_cnt, (unsigned long long)ec24_cnt);
    pr_info("caoin-kpm: sent=%llu el0tab=%lx\n",
            (unsigned long long)sent_cnt, el0_table_base);
    return 0;
}

static long caoin_exit(void *__user reserved)
{
    (void)reserved;
    return caoin_restore();
}

KPM_NAME("caoin-shadow");
KPM_VERSION("0.5.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("caoin");
KPM_DESCRIPTION("caoin traceless hook - multi-hook dpf shadow seesaw (muted logs)");

KPM_INIT(caoin_init);
KPM_CTL0(caoin_ctl0);
KPM_EXIT(caoin_exit);
