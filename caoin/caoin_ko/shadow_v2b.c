/*
 * caoin shadow v2b — 无痕读写分离（VBAR 路线）
 *
 * 对内核的全部触碰 = 一次 msr vbar_el1（可逆）。不写内核任何内存。
 *
 * 结构：
 *  - 模块 .text 内建 2KB 新向量表（16×128B 槽，B 相对跳编译期编码）
 *  - EL0 AArch64 Sync 槽（+0x400）→ caoin_el0_entry：保存全部用户现场，
 *    读 FAR/ESR 调过滤器；命中则切视图后 eret（重执行 fault 指令），
 *    未命中恢复现场后跳旧表入口（状态等价直接异常进入）
 *  - 其余 15 槽 → 各自 passthru：LDR x17 旧入口（地址在 .data 数组，运行时填）+ BR
 *  - 切换：mrs 旧 VBAR → msr 新 VBAR → isb；恢复反向
 */
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/sched.h>
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
    u64 find_task, probe_read, printk;   /* printk：KP 干扰，仅应急 */
    u64 status_phys;   /* 第二判据：status 页物理（双 expect 防假阳性） */
    u64 unused[7];
    /* 运行态 */
    u64 orig_pte;
    u64 mm_off, pgd_off;
    u64 pte_addr;
    u64 shadow_pte_val;
    u64 origview_pte_val;
    u64 cur_view;
    u64 old_vbar;
    u64 vbar_on;
};

static struct caoin_cfg caoin_cfg_block = {
    .marker = CAOIN_CFG_MARKER,
    .magic = 0,
};

static long (*caoin_probe)(void *, void *, unsigned long);
static int (*caoin_printk)(const char *fmt, ...);
#define CK_LOG(...) do { if (caoin_printk) caoin_printk(__VA_ARGS__); } while (0)

static void caoin_tlb_flush(unsigned long va)
{
    unsigned long addr = va >> 12;
    asm volatile("dsb ish" ::: "memory");
    asm volatile("tlbi vae1is, %0" :: "r"(addr));
    asm volatile("isb" ::: "memory");
}

/* ---- 探测引擎（v1 验证版复用） ---- */

static int caoin_probe_walk(unsigned long mm_cand, unsigned long pgd_off_cand,
                            unsigned long va, unsigned long expect_phys,
                            unsigned long *pte_a_out)
{
    unsigned long pgd_p, e0, e2, pte_v, pte_a;
    const unsigned long m = PHYS_MASK & PAGE_MASK;

    if (caoin_probe(&pgd_p, (void *)(mm_cand + pgd_off_cand), 8))
        return 0;
    if (pgd_p < 0xffffff8000000000UL || (pgd_p & 0xFFF))
        return 0;
    if (caoin_probe(&e0, (void *)(pgd_p + ((va >> 30) & 0x1FF) * 8), 8))
        return 0;
    if (!(e0 & m))
        return 0;
    if (caoin_probe(&e2, (void *)__va((e0 & m) + ((va >> 21) & 0x1FF) * 8), 8))
        return 0;
    if (!(e2 & m))
        return 0;
    pte_a = (unsigned long)__va((e2 & m) + ((va >> 12) & 0x1FF) * 8);
    if (caoin_probe(&pte_v, (void *)pte_a, 8))
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
        if (caoin_probe(&mm_c, (void *)(task + moff), 8))
            continue;
        if (mm_c < 0xffffff8000000000UL || (mm_c & 0x7))
            continue;
        for (poff = 0x20; poff < 0x400; poff += 8) {
            if (caoin_probe(&pgd_p, (void *)(mm_c + poff), 8))
                continue;
            if (pgd_p < 0xffffff8000000000UL || (pgd_p & 0xFFF))
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

static void caoin_write_status2(unsigned long mm, unsigned long pgd_off,
                                unsigned long va, u64 val)
{
    unsigned long pte_a = 0, pte_v, phys;
    if (!caoin_probe_walk(mm, pgd_off, va, 0, &pte_a))
        return;
    if (caoin_probe(&pte_v, (void *)pte_a, 8))
        return;
    phys = pte_v & PHYS_MASK & PAGE_MASK;
    u64 *slot = (u64 *)__va(phys + (va & ~PAGE_MASK));
    *slot = val;
    asm volatile("dsb ish" ::: "memory");
}

/* ---- fault 过滤器（addr=FAR, esr=ESR_EL1） ---- */

int caoin_fault_check(unsigned long addr, unsigned int esr)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    unsigned int ec = esr >> 26;

    if ((addr >> 12) != ((unsigned long)c->target_va >> 12))
        return 0;

    if (c->cur_view) {
        if (ec != 0x24 || (esr & (1 << 6)))   /* EL0 data abort 且非写 */
            return 0;
        set_pte((pte_t *)(unsigned long)c->pte_addr,
                __pte((unsigned long)c->origview_pte_val));
        c->cur_view = 0;
        caoin_tlb_flush((unsigned long)c->target_va);
        return 1;
    } else {
        if (ec != 0x20)
            return 0;
        set_pte((pte_t *)(unsigned long)c->pte_addr,
                __pte((unsigned long)c->shadow_pte_val));
        c->cur_view = 1;
        caoin_tlb_flush((unsigned long)c->target_va);
        return 1;
    }
}

/* ---- 向量表与入口（全部编译期编码；旧入口地址在 .data 数组运行时填） ---- */

/* 旧表 16 个入口地址 + EL0 Sync 旧入口（.data：init 运行时填，可写） */
volatile unsigned long caoin_slot_tab[16];
volatile unsigned long caoin_old_el0_sync;

/* 每槽独立跳板：烧 x16（IP0 scratch）取目标，x17 完整恢复。 */
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
/* 槽 0-7：B 各自 pass + nop 填满 128B */
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
/* 槽 8（0x400，Lower EL AArch64 Sync）→ 过滤器 */
"    b caoin_el0_entry\n"
"    .rept 31\n nop\n .endr\n"
/* 槽 9-15 */
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

/* ---- EL0 Sync 入口 ---- */
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
"    mrs x1, esr_el1\n"
"    bl caoin_fault_check\n"
"    cbnz w0, 2f\n"
"    /* 未命中：恢复现场，跳旧 EL0 Sync 入口（状态等价直接异常进入） */\n"
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
"    /* 已处理：恢复现场，eret 重执行 fault 指令 */\n"
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



static int __init caoin_init(void)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    unsigned long mm_off, pgd_off, mmv, pte_a, orig_pte_v;
    const unsigned long m = PHYS_MASK & PAGE_MASK;
    unsigned long old_vbar;
    unsigned long *tab = (unsigned long *)caoin_slot_tab;
    struct task_struct *(*find_task)(int);
    struct task_struct *task;

    if (c->magic != CAOIN_CFG_MAGIC || !c->find_task || !c->probe_read)
        return -EINVAL;

    caoin_probe = (void *)(unsigned long)c->probe_read;
    caoin_printk = (void *)(unsigned long)c->printk;
    find_task = (void *)(unsigned long)c->find_task;
    task = find_task((int)c->target_pid);
    if (!task)
        return -ESRCH;

    if (!caoin_locate((unsigned long)task, (unsigned long)c->target_va,
                      (unsigned long)c->expect_phys,
                      (unsigned long)c->status_va, (unsigned long)c->status_phys,
                      &mm_off, &pgd_off, &mmv, &pte_a))
        return -ENOENT;
    c->mm_off = mm_off;
    c->pgd_off = pgd_off;
    c->pte_addr = pte_a;

    if (caoin_probe(&orig_pte_v, (void *)pte_a, 8))
        return -ENOENT;
    c->orig_pte = orig_pte_v;

    c->shadow_pte_val = (orig_pte_v & ~(m | PTE_AP_MASK | (1UL << 54)))
                      | ((unsigned long)c->shadow_phys & m)
                      | 0x80UL;                 /* AP=10: EL0 数据访问 fault */
    c->origview_pte_val = (orig_pte_v & ~(PTE_AP_MASK | (1UL << 54)))
                        | 0x40UL | (1UL << 54); /* AP=01 RO, UXN=1 */

    /* 旧向量表地址数组（.data 可写，无需解锁任何页） */
    {
        int i;
        asm volatile("mrs %0, vbar_el1" : "=r"(old_vbar));
        c->old_vbar = old_vbar;
        for (i = 0; i < 16; i++)
        for (i = 0; i < 16; i++)
            tab[i] = old_vbar + i * 0x80;
        caoin_old_el0_sync = old_vbar + 0x400;
    }
    /* 切 VBAR（对内核的全部触碰） */
    asm volatile("msr vbar_el1, %0" :: "r"((unsigned long)caoin_vbar));
    asm volatile("isb" ::: "memory");
    c->vbar_on = 1;

    /* 切 shadow 视图 */
    set_pte((pte_t *)(unsigned long)c->pte_addr, __pte((unsigned long)c->shadow_pte_val));
    c->cur_view = 1;
    caoin_tlb_flush((unsigned long)c->target_va);

    /* 读回验证：PTE 实际值编码写 status（0xA0000000 + 低 20 位） */
    {
        unsigned long back = 0;
        caoin_probe(&back, (void *)(unsigned long)c->pte_addr, 8);
        caoin_write_status2(mmv, pgd_off, (unsigned long)c->status_va,
                            0xA0000000u | (back & 0xFFFFF));
        CK_LOG("caoin2b: pte want=%lx back=%lx @%lx\n",
               (unsigned long)c->shadow_pte_val, back, (unsigned long)c->pte_addr);
    }

    caoin_write_status2(mmv, pgd_off, (unsigned long)c->status_va, 0x1);
    CK_LOG("caoin2b: on (vbar %lx -> %lx)\n", old_vbar, (unsigned long)caoin_vbar);
    return 0;
}

static void __exit caoin_exit(void)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    if (c->magic != CAOIN_CFG_MAGIC || !c->pte_addr)
        return;
    caoin_probe = (void *)(unsigned long)c->probe_read;

    /* 视图合一 */
    set_pte((pte_t *)(unsigned long)c->pte_addr, __pte((unsigned long)c->orig_pte));
    c->cur_view = 0;
    caoin_tlb_flush((unsigned long)c->target_va);

    /* 恢复 VBAR */
    if (c->vbar_on && c->old_vbar) {
        asm volatile("msr vbar_el1, %0" :: "r"((unsigned long)c->old_vbar));
        asm volatile("isb" ::: "memory");
        c->vbar_on = 0;
    }

    struct task_struct *(*find_task)(int) =
        (void *)(unsigned long)c->find_task;
    struct task_struct *task = find_task((int)c->target_pid);
    if (task) {
        unsigned long mmv = 0;
        caoin_probe(&mmv, (void *)((unsigned long)task + c->mm_off), 8);
        if (mmv)
            caoin_write_status2(mmv, c->pgd_off, (unsigned long)c->status_va, 0xF);
    }
    CK_LOG("caoin2b: off, restored\n");
}

module_init(caoin_init);
module_exit(caoin_exit);
MODULE_LICENSE("GPL");
