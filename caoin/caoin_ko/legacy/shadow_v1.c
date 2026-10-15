/*
 * caoin shadow v1 — 零内核符号引用的 PTE 换页模块
 *
 * 目标：把目标进程某虚拟页的 PTE 指到新物理页（内容 = 原页 + hook 桩），
 * 全程不改目标进程任何内存、不分配内核内存、不调用任何导出符号。
 *
 * 零符号手段：
 *   - find_task_by_vpid 经 cfg 传入的地址函数指针调用（用户态 kallsyms 解析）
 *   - 页表 walk 全内联宏；__va 线性映射宏
 *   - TLB 失效用内联 tlbi 汇编
 *   - 无 printk（状态码直接写目标进程用户页）
 *
 * 配置经构建期 patch：用户态工具找 .data 里的 CAOIN_CFG_MAGIC，
 * 后续 u64 字段按需覆写。运行时自校验：walk 出的原 PTE 物理地址必须
 * 等于 expect_phys（用户态 pagemap 已知值），不符则不动任何东西——
 * 结构偏移（task->mm）来自近似源码树，靠此校验兜底。
 */
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <asm/pgtable.h>

/* 本 ROM 内核实测为 39 位 VA（task_struct 落 0xffffffca... vmalloc 区）：
 * 3 级页表，PAGE_OFFSET=0xffffffc000000000。覆盖基座树（48 位）的宏。 */
#undef PAGE_OFFSET
#define PAGE_OFFSET 0xffffffC000000000UL
#define CAOIN_VA39 1

#define CAOIN_CFG_MAGIC 0xCA01CA01CA01CA01ULL
#define CAOIN_CFG_MARKER 0xDEADCA01DEADCA01ULL

struct caoin_cfg {
    u64 marker;           /* 永真定位标记（patch 脚本搜索用） */
    u64 magic;            /* patch 写入 MAGIC 后配置才生效 */
    u64 target_pid;
    u64 target_va;       /* 页对齐的目标虚拟地址 */
    u64 shadow_phys;     /* 新物理页 */
    u64 expect_phys;     /* 自校验：原物理页（pagemap 真值，偏移探测的判据） */
    u64 status_va;       /* 状态码虚拟地址（目标进程内，内核 walk 后写） */
    u64 find_task;       /* find_task_by_vpid 地址 */
    u64 probe_read;      /* probe_kernel_read 地址（安全读野指针不 panic） */
    u64 printk_addr;     /* printk 地址（诊断输出） */
    u64 orig_pte;        /* 模块写回：原 PTE 值 */
    u64 mm_off;          /* 探测结果写回：task->mm 偏移（诊断/复用） */
    u64 pgd_off;         /* 探测结果写回：mm->pgd 偏移 */
};

static struct caoin_cfg caoin_cfg_block = {
    .marker = CAOIN_CFG_MARKER,
    .magic = 0,   /* 0 = 未 patch；打包脚本写入 CAOIN_CFG_MAGIC 后配置才生效 */
};

/* 只用编译期常量与内存访问，禁止任何外部函数调用 */
#define caoin_membarrier() asm volatile("dsb ish" ::: "memory")

static void caoin_tlb_flush(unsigned long va)
{
    unsigned long addr = va >> 12;
    caoin_membarrier();
    asm volatile("tlbi vae1is, %0" :: "r"(addr));
    asm volatile("isb" ::: "memory");
}

/*
 * 结构偏移运行时探测（源码树近似，偏移可能漂移）：
 *   task->mm 与 mm->pgd 双未知 → 用 probe_kernel_read 安全读候选地址，
 *   以 expect_phys（pagemap 已知真值）为判据锁定组合。
 *   全程无裸解引用，读野指针只返回 -EFAULT。
 */
static long (*caoin_probe)(void *, void *, unsigned long);
static int (*caoin_printk)(const char *fmt, ...);

/* 探测分级计数（诊断） */
static unsigned long cnt_mm, cnt_pgd, cnt_l0, cnt_l1, cnt_l2, cnt_pte;
unsigned long caoin_mm_off_dbg;   /* 当前探测的 moff（诊断输出用） */

#define CK_LOG(...) do { if (caoin_printk) caoin_printk(__VA_ARGS__); } while (0)

/* 强 pgd 判据：用户槽与内核槽同时为有效表描述符（垃圾组合极难满足） */
static int caoin_pgd_strong(unsigned long pgd_p)
{
    const unsigned long m = PHYS_MASK & PAGE_MASK;
    unsigned long eu, ek;
    if (caoin_probe(&eu, (void *)(pgd_p + 0), 8))
        return 0;
    if (caoin_probe(&ek, (void *)(pgd_p + 256 * 8), 8))
        return 0;
    if (!(eu & m) || !(ek & m))
        return 0;
    if ((eu & m) == (ek & m))
        return 0;
    if (!(eu & 2) || !(ek & 2))
        return 0;    /* 均为表描述符 */
    return 1;
}

static int caoin_probe_walk(unsigned long mm_cand, unsigned long pgd_off_cand,
                            unsigned long va, unsigned long expect_phys,
                            pte_t **pte_out)
{
    extern unsigned long caoin_mm_off_dbg;
    unsigned long pgd_p, e0, e1, e2, pte_v, pte_a;
    unsigned long mm_off_dbg = caoin_mm_off_dbg;
    const unsigned long m = PHYS_MASK & PAGE_MASK;

    if (caoin_probe(&pgd_p, (void *)(mm_cand + pgd_off_cand), 8))
        return 0;
    if (pgd_p < 0xffffff8000000000UL || (pgd_p & 0xFFF))
        return 0;    /* 内核高半区（线性或 vmalloc slab）、页对齐 */
    cnt_pgd++;
    if (caoin_pgd_strong(pgd_p))
        CK_LOG("caoin strong pgd: moff=%lx poff=%lx pgd=%lx\n",
               caoin_mm_off_dbg, pgd_off_cand, pgd_p);

    if (caoin_probe(&e0, (void *)(pgd_p + ((va >> 30) & 0x1FF) * 8), 8))
        return 0;
    if (!(e0 & m))
        return 0;
    cnt_l0++;
    /* 3 级页表（39 位 VA）：L0=PGD(va>>30) → L1=PMD(va>>21) → L2=PTE(va>>12) */
    if (caoin_probe(&e2, (void *)__va((e0 & m) + ((va >> 21) & 0x1FF) * 8), 8))
        return 0;
    if (!(e2 & m))
        return 0;
    cnt_l1++;
    cnt_l2++;
    pte_a = (unsigned long)__va((e2 & m) + ((va >> 12) & 0x1FF) * 8);
    if (caoin_probe(&pte_v, (void *)pte_a, 8))
        return 0;
    cnt_pte++;
    if (expect_phys && (pte_v & m) != expect_phys) {
        CK_LOG("caoin walk pte_v=%lx want=%lx (pgd_off=%lx mm=%lx)\n",
               pte_v, expect_phys, pgd_off_cand, mm_cand);
        return 0;
    }
    if (pte_out)
        *pte_out = (pte_t *)pte_a;
    return 1;
}

static int caoin_locate(unsigned long task, unsigned long va, unsigned long expect_phys,
                        unsigned long *mm_off_out, unsigned long *pgd_off_out,
                        unsigned long *mm_out, pte_t **pte_out)
{
    unsigned long mm_c, pgd_p;
    unsigned long moff, poff;
    /* task->mm 候选范围：0 ~ 0x1800；mm->pgd 候选：0x20 ~ 0x400 */
    for (moff = 0; moff < 0x1800; moff += 8) {
        if (caoin_probe(&mm_c, (void *)(task + moff), 8))
            continue;
        if (mm_c < 0xffffff8000000000UL || (mm_c & 0x7))
            continue;    /* 内核高半区（本 ROM slab 在 vmalloc 区）、8 对齐 */
        cnt_mm++;
        caoin_mm_off_dbg = moff;
        for (poff = 0x20; poff < 0x400; poff += 8) {
            if (caoin_probe(&pgd_p, (void *)(mm_c + poff), 8))
                continue;
            if (pgd_p < 0xffffff9000000000UL || (pgd_p & 0xFFF))
                continue;    /* pgd 页对齐且线性区 */
            if (caoin_probe_walk(mm_c, poff, va, expect_phys, pte_out)) {
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

/* 用已锁定的偏移走 status 页并写值（probe 读，pte 验证后直写物理） */
static void caoin_write_status2(unsigned long mm, unsigned long pgd_off,
                                 unsigned long va, u64 val)
{
    pte_t *pte = 0;
    if (!caoin_probe_walk(mm, pgd_off, va, 0, &pte) || !pte)
        return;
    unsigned long phys = pte_val(*pte) & PHYS_MASK & PAGE_MASK;
    u64 *slot = (u64 *)__va(phys + (va & ~PAGE_MASK));
    *slot = val;
    caoin_membarrier();
}


static int __init caoin_init(void)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    unsigned long mm_off, pgd_off;
    pte_t *pte;
    unsigned long orig_phys, new_pte;

    if (c->magic != CAOIN_CFG_MAGIC || !c->find_task || !c->probe_read)
        return -EINVAL;    /* 未 patch 或配置不全：空载 */

    caoin_probe = (void *)(unsigned long)c->probe_read;
    caoin_printk = (void *)(unsigned long)c->printk_addr;
    struct task_struct *(*find_task)(int) =
        (void *)(unsigned long)c->find_task;
    struct task_struct *task = find_task((int)c->target_pid);
    if (!task)
        return -ESRCH;
    CK_LOG("caoin: task=%px pid=%llx\n", task, c->target_pid);

    /* 偏移探测（安全读 + expect_phys 判据） */
    unsigned long mmv;
    if (!caoin_locate((unsigned long)task, (unsigned long)c->target_va,
                      (unsigned long)c->expect_phys, &mm_off, &pgd_off,
                      &mmv, &pte)) {
        CK_LOG("caoin probe fail: mm=%lu pgd=%lu l0=%lu l1=%lu l2=%lu pte=%lu\n",
               cnt_mm, cnt_pgd, cnt_l0, cnt_l1, cnt_l2, cnt_pte);
        return -ENOENT;   /* 探测失败：不动任何东西 */
    }
    c->mm_off = mm_off;
    c->pgd_off = pgd_off;

    /* 复用探测到的 pte（已验证物理 == expect_phys） */
    orig_phys = pte_val(*pte) & PHYS_MASK & PAGE_MASK;
    if (orig_phys != (unsigned long)c->expect_phys) {
        return -EINVAL;
    }

    /* 只换物理页号，保留全部属性位 */
    new_pte = (pte_val(*pte) & ~(PHYS_MASK & PAGE_MASK))
            | ((unsigned long)c->shadow_phys & (PHYS_MASK & PAGE_MASK));
    c->orig_pte = pte_val(*pte);
    set_pte(pte, __pte(new_pte));
    caoin_tlb_flush((unsigned long)c->target_va);

    /* 状态写回：直接用探测成功的 (mm, pgd_off)，不二次定位
       （此时目标 PTE 已换成 shadow，旧 expect 判据必然失配） */
    caoin_write_status2(mmv, pgd_off, (unsigned long)c->status_va, 0x1);
    CK_LOG("caoin: shadow on (mm_off=%lx pgd_off=%lx)\n", mm_off, pgd_off);
    return 0;
}

static void __exit caoin_exit(void)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    if (c->magic != CAOIN_CFG_MAGIC || !c->find_task || !c->orig_pte)
        return;
    caoin_probe = (void *)(unsigned long)c->probe_read;
    caoin_printk = (void *)(unsigned long)c->printk_addr;
    struct task_struct *(*find_task)(int) =
        (void *)(unsigned long)c->find_task;
    struct task_struct *task = find_task((int)c->target_pid);
    if (!task)
        return;
    /* 用 init 已验证的偏移直接取 mm，不再全扫（换页后旧判据已失效） */
    unsigned long mmv = 0;
    pte_t *pte = 0;
    if (caoin_probe(&mmv, (void *)((unsigned long)task + c->mm_off), 8))
        return;
    if (!caoin_probe_walk(mmv, c->pgd_off, (unsigned long)c->target_va,
                          0 /* 不判物理 */, &pte) || !pte) {
        CK_LOG("caoin exit: walk fail mm=%lx\n", mmv);
        return;
    }
    set_pte(pte, __pte(c->orig_pte));
    caoin_tlb_flush((unsigned long)c->target_va);
    caoin_write_status2(mmv, c->pgd_off, (unsigned long)c->status_va, 0xF);
    CK_LOG("caoin: shadow off, restored\n");
}

module_init(caoin_init);
module_exit(caoin_exit);
MODULE_LICENSE("GPL");
