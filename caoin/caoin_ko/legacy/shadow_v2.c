/*
 * caoin shadow v2 — 无痕读写分离（跷跷板）
 *
 * 原理：ARM64 取指不检查 AP 位。两个 PTE 视图：
 *   shadow 视图  = shadow_phys | AP=10(EL1 only) | UXN=0 → EL0 可执行不可读
 *   original 视图 = 原物理   | AP=01(RO)        | UXN=1 → 可读不可执行
 * EL0 读 hook 页 → data abort → 过滤器切 original 视图 → 重执行读到原始字节
 * EL0 执行 hook 页 → insn abort → 过滤器切 shadow 视图 → 重执行走桩
 * 进程内 CRC 自检读到的一字不差的原始页，执行走的是桩。
 *
 * fault 钩子：do_mem_abort 入口内联桩（LDR X17,#8; BR X17; <filter 地址>，
 * 16 字节恰好）。stop_machine 同步安装，原 4 条指令备份后在过滤器 trampoline
 * 中执行转发。内核 text 写入用 set_memory_rw/ro（kallsyms 地址调用）。
 *
 * 已知边界（v2 接受）：EL1/GUP 读路径不堵（/proc/pid/mem 等读到的是当前
 * 视图）；多线程竞态不处理（页级切换全局生效）。
 * 用户态桩必须用 MOVZ/MOVK 纯立即数拼地址——LDR literal 的数据读会切到
 * original 视图读到错误字节。
 */
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <asm/pgtable.h>

#undef PAGE_OFFSET
#define PAGE_OFFSET 0xffffffC000000000UL

#define CAOIN_CFG_MAGIC 0xCA02CA02CA02CA02ULL
#define CAOIN_CFG_MARKER 0xDEADCA02DEADCA02ULL

#define PTE_AP_MASK 0xC0UL          /* bits[7:6] AP[2:1] */
/* PTE_UXN 由 <asm/pgtable-hwdef.h> 提供（bit 54），不重定义 */

struct caoin_cfg {
    u64 marker, magic;
    u64 target_pid;
    u64 target_va;        /* 受管页（页对齐） */
    u64 shadow_phys;
    u64 expect_phys;
    u64 status_va;
    u64 find_task, probe_read, printk;
    u64 p_abort;          /* do_mem_abort */
    u64 p_setrw, p_setro; /* （弃用，保留布局兼容） */
    u64 p_stop;           /* stop_machine */
    u64 p_probe_write;    /* probe_kernel_write（安全写：失败 -EFAULT 不 panic） */
    u64 p_swapper;        /* swapper_pg_dir（内核页表基座，kallsyms VA 直接可读） */
    /* 以下模块运行态 */
    u64 orig_pte;
    u64 mm_off, pgd_off;
    u64 pte_addr;         /* 受管页 pte 内核地址 */
    u64 shadow_pte_val;   /* 执行视图 */
    u64 origview_pte_val; /* 读取视图 */
    u64 cur_view;         /* 1=shadow 0=original */
    u64 hooked;           /* do_mem_abort 桩已装 */
    u32 saved_abort[4];   /* do_mem_abort 原入口指令 */
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

/* ---- v1 沿用的探测引擎 ---- */

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
    /* 3 级页表（39 位 VA）：L0=va>>30 → L1=va>>21 → L2=va>>12 */
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
            if (caoin_probe_walk(mm_c, poff, va, expect_phys, pte_a_out)) {
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

/* ---- fault 过滤器 ----
 * 入口由内联汇编保存 do_mem_abort 的原始参数（x0=addr, x1=esr），
 * 调 C 判断；返回 1 = 已切换视图（fault 已消除），0 = 转发原函数。
 * 转发路径先执行被桩覆盖的 4 条原指令，再跳 do_mem_abort+16。 */

/* 非 static：顶层 asm 的 bl 需要模块内可见符号 */
int caoin_fault_check(unsigned long addr, unsigned int esr)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    unsigned int ec = esr >> 26;

    if ((addr >> 12) != ((unsigned long)c->target_va >> 12))
        return 0;    /* 非受管页 */

    if (c->cur_view) {
        /* shadow 视图：等 EL0 data abort（读 fault，WnR=0）→ 切读取视图 */
        if (ec != 0x24 || (esr & (1 << 6)))   /* EL0 data abort 且非写 */
            return 0;
        set_pte((pte_t *)(unsigned long)c->pte_addr,
                __pte((unsigned long)c->origview_pte_val));
        c->cur_view = 0;
        caoin_tlb_flush((unsigned long)c->target_va);
        return 1;
    } else {
        /* original 视图：等 EL0 instruction abort → 切执行视图 */
        if (ec != 0x20)
            return 0;
        set_pte((pte_t *)(unsigned long)c->pte_addr,
                __pte((unsigned long)c->shadow_pte_val));
        c->cur_view = 1;
        caoin_tlb_flush((unsigned long)c->target_va);
        return 1;
    }
}

/* 过滤器入口 + 转发 trampoline（全部在模块 .text，可执行）。
 * 帧只压 x29/x30 + 保存 x0/x1；x2(x3-x7) 全程不动。 */
asm(
".global caoin_filter_entry\n"
"caoin_filter_entry:\n"
"    stp x29, x30, [sp, #-128]!\n"
"    mov x29, sp\n"
"    stp x0, x1, [sp, #16]\n"
"    bl caoin_fault_check\n"
"    cbnz w0, 2f\n"
"    /* 未处理：恢复参数，进入转发槽（原 4 条 + 跳 p_abort+16，线性流入） */\n"
"    ldp x0, x1, [sp, #16]\n"
"    ldp x29, x30, [sp], #128\n"
"    ldr x17, =caoin_replay\n"
"    br x17\n"
"2:\n"
"    ldp x29, x30, [sp], #128\n"
"    ret\n"
".align 3\n"
".global caoin_replay\n"
"caoin_replay:\n"               /* init 填 4 条 do_mem_abort 原指令 */
"    .word 0, 0, 0, 0\n"
".global caoin_jmp_slot\n"
"caoin_jmp_slot:\n"             /* init 填 MOVZ/MOVK X16 跳 p_abort+16（5 条） */
"    .word 0, 0, 0, 0, 0\n"
);

extern char caoin_filter_entry[], caoin_replay[], caoin_jmp_slot[];

/* MOVZ/MOVK X16 拼装 64 位地址（5 条指令）写入 buf */
static void caoin_emit_abs_jump(u32 *buf, unsigned long target)
{
    buf[0] = 0xD2800010u | (unsigned)((target & 0xFFFF) << 5);
    buf[1] = 0xF2A00010u | (unsigned)(((target >> 16) & 0xFFFF) << 5);
    buf[2] = 0xF2C00010u | (unsigned)(((target >> 32) & 0xFFFF) << 5);
    buf[3] = 0xF2E00010u | (unsigned)(((target >> 48) & 0xFFFF) << 5);
    buf[4] = 0xD61F0200u;   /* BR X16 */
}

/* 内核页表属性改写 v2：swapper_pg_dir 基座 + 自适应层级（3/4 级）+
 * 决定性自校验（改 RW 后试写原值字节，写不进 = walk 错，恢复并返回错误）。 */
static int caoin_ktext_perm(unsigned long va, int rw)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    unsigned long cur, e, pte_a, pte_v, phys;
    const unsigned long m = PHYS_MASK & PAGE_MASK;
    unsigned char v0;

    if (!c->p_swapper)
        return -10;
    cur = (unsigned long)c->p_swapper;

    /* 层级探测：va>>39 项是表描述符 → 4 级；否则 3 级 */
    if (caoin_probe(&e, (void *)(cur + ((va >> 39) & 0x1FF) * 8), 8))
        return -11;
    if ((e & 3) == 3) {
        cur = (unsigned long)__va(e & m);
        CK_LOG("caoin2: ktext 4-level, L0=%lx\n", e);
    }

    /* 逐级下钻：每级必须表描述符（block 不能页粒度改权限） */
    {
        int shifts[2] = { 30, 21 };
        int i;
        for (i = 0; i < 2; i++) {
            if (caoin_probe(&e, (void *)(cur + ((va >> shifts[i]) & 0x1FF) * 8), 8))
                return -12 - i;
            if ((e & 3) != 3) {
                CK_LOG("caoin2: ktext block at shift %d: %lx\n", shifts[i], e);
                return -14 - i;   /* block 映射：本 walk 不适用 */
            }
            cur = (unsigned long)__va(e & m);
        }
    }
    pte_a = cur + ((va >> 12) & 0x1FF) * 8;
    if (caoin_probe(&pte_v, (void *)pte_a, 8))
        return -16;
    CK_LOG("caoin2: perm va=%lx pte=%lx@%lx\n", va, pte_v, pte_a);
    if (!(pte_v & 3))
        return -17;

    if (!rw) {
        pte_v &= ~PTE_AP_MASK;
        pte_v |= 0x40;
        set_pte((pte_t *)pte_a, __pte(pte_v));
        caoin_tlb_flush(va);
        return 0;
    }

    /* RW：先改属性，再决定性自校验（试写首字节原值） */
    pte_v &= ~PTE_AP_MASK;
    set_pte((pte_t *)pte_a, __pte(pte_v));
    caoin_tlb_flush(va);
    if (caoin_probe(&v0, (void *)va, 1))
        goto revert;
    if (caoin_pwrite && caoin_pwrite((void *)va, &v0, 1) != 0) {
        CK_LOG("caoin2: ktext verify-write failed (walk wrong), revert\n");
        goto revert;
    }
    return 0;

revert:
    pte_v = 0;
    caoin_probe(&pte_v, (void *)pte_a, 8);
    pte_v &= ~PTE_AP_MASK;
    pte_v |= 0x40;
    set_pte((pte_t *)pte_a, __pte(pte_v));
    caoin_tlb_flush(va);
    return -18;
}

/* stop_machine 回调：写 do_mem_abort 入口桩（probe_kernel_write 安全写） */
static int caoin_install_stub(void *unused)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    u32 *abort_body = (u32 *)(unsigned long)c->p_abort;
    u32 words[2] = { 0x58000051u, 0xD61F0220u };   /* LDR X17,#8; BR X17 */
    u64 fa = (u64)(unsigned long)caoin_filter_entry;
    long r1, r2;

    if (!caoin_pwrite)
        return -EINVAL;
    r1 = caoin_pwrite(abort_body, words, 8);
    r2 = caoin_pwrite(&abort_body[2], &fa, 8);
    CK_LOG("caoin2: stub write r1=%ld r2=%ld\n", r1, r2);

    asm volatile("ic iallu" ::: "memory");
    asm volatile("dsb ish" ::: "memory");
    asm volatile("isb" ::: "memory");
    return (r1 == 0 && r2 == 0) ? 0 : -EINVAL;
}

/* 指令是否 PC 相对（搬运安全性检查） */
static int insn_pc_relative(u32 insn)
{
    if ((insn & 0x7C000000) == 0x14000000) return 1;   /* B/BL */
    if ((insn & 0x1F000000) == 0x10000000) return 1;   /* ADR/ADRP */
    if ((insn & 0x7E000000) == 0x34000000) return 1;   /* CBZ */
    if ((insn & 0x7E000000) == 0x36000000) return 1;   /* TBZ */
    if ((insn & 0x1F000000) == 0x18000000) return 1;   /* LDR literal */
    return 0;
}

/* stop_machine 回调：恢复 do_mem_abort 原入口（卸载必须与安装同样同步） */
static int caoin_remove_stub(void *unused)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    u32 *abort_body = (u32 *)(unsigned long)c->p_abort;
    int i;
    for (i = 0; i < 4; i++)
        abort_body[i] = c->saved_abort[i];
    asm volatile("ic iallu" ::: "memory");
    asm volatile("dsb ish" ::: "memory");
    asm volatile("isb" ::: "memory");
    return 0;
}

static int __init caoin_init(void)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    unsigned long mm_off, pgd_off, mmv, pte_a, orig_pte_v;
    const unsigned long m = PHYS_MASK & PAGE_MASK;
    int (*stopm)(int (*)(void *), void *, const void *);
    u32 *abort_body;
    struct task_struct *(*find_task)(int);

    if (c->magic != CAOIN_CFG_MAGIC || !c->find_task || !c->probe_read)
        return -EINVAL;

    caoin_probe = (void *)(unsigned long)c->probe_read;
    caoin_printk = (void *)(unsigned long)c->printk;
    caoin_pwrite = (void *)(unsigned long)c->p_probe_write;
    find_task = (void *)(unsigned long)c->find_task;

    /* p_setrw!=0：ktext_perm 单元测试模式（printk 被 KP 干扰，结果走 status 写回） */
    if (c->p_setrw) {
        unsigned long mm_off_t, pgd_off_t, mmv_t, pte_a_t = 0;
        struct task_struct *t2;
        int u;
        t2 = find_task((int)c->target_pid);
        if (!t2)
            return -ESRCH;
        if (!caoin_locate((unsigned long)t2, (unsigned long)c->target_va,
                          (unsigned long)c->expect_phys,
                          &mm_off_t, &pgd_off_t, &mmv_t, &pte_a_t))
            return -ENOENT;
        u = caoin_ktext_perm((unsigned long)c->p_abort, 1);
        caoin_write_status2(mmv_t, pgd_off_t, (unsigned long)c->status_va,
                            0xE000u | (unsigned)(u & 0xFFF));
        if (!u) {
            caoin_ktext_perm((unsigned long)c->p_abort, 0);
            caoin_write_status2(mmv_t, pgd_off_t, (unsigned long)c->status_va, 0xE100);
        }
        return -EINVAL;   /* 测试模式必返回错误（模块不驻留） */
    }

    struct task_struct *task = find_task((int)c->target_pid);
    if (!task)
        return -ESRCH;
    CK_LOG("caoin2: task=%px\n", task);

    if (!caoin_locate((unsigned long)task, (unsigned long)c->target_va,
                      (unsigned long)c->expect_phys,
                      &mm_off, &pgd_off, &mmv, &pte_a)) {
        CK_LOG("caoin2: probe fail\n");
        return -ENOENT;
    }
    c->mm_off = mm_off;
    c->pgd_off = pgd_off;
    c->pte_addr = pte_a;

    if (caoin_probe(&orig_pte_v, (void *)pte_a, 8))
        return -ENOENT;
    c->orig_pte = orig_pte_v;
    CK_LOG("caoin2: pte_a=%lx orig=%lx\n", pte_a, orig_pte_v);

    /* 双视图 PTE：只改 AP[2:1]/UXN/物理位，其余属性（attrindx/SH/AF/NG）保留 */
    c->shadow_pte_val = (orig_pte_v & ~(m | PTE_AP_MASK | PTE_UXN))
                      | ((unsigned long)c->shadow_phys & m)
                      | 0x80UL;                 /* AP=10: EL1-only，EL0 数据访问 fault */
    c->origview_pte_val = (orig_pte_v & ~(PTE_AP_MASK | PTE_UXN))
                        | 0x40UL | PTE_UXN;    /* AP=01: RO，UXN=1 不可执行 */

    /* ---- do_mem_abort 钩子 ---- */
    {
        int i;
        abort_body = (u32 *)(unsigned long)c->p_abort;
        for (i = 0; i < 4; i++) {
            if (insn_pc_relative(abort_body[i])) {
                CK_LOG("caoin2: abort entry pc-relative, bail\n");
                return -EINVAL;    /* 不可安全搬运 */
            }
            c->saved_abort[i] = abort_body[i];
        }
    }

    stopm = (void *)(unsigned long)c->p_stop;
    {
        long rc_stop;
        int u1, u2;
        /* 自行解锁（set_memory_rw 对 kimage 区 -EINVAL）：
           do_mem_abort 页 + 模块转发槽页 */
        u1 = caoin_ktext_perm((unsigned long)c->p_abort, 1);
        u2 = caoin_ktext_perm((unsigned long)caoin_replay, 1);
        CK_LOG("caoin2: unlock abort=%d replay=%d\n", u1, u2);
        /* 填转发槽（probe_kernel_write：perm 未生效时只 EFAULT 不 panic） */
        {
            int i;
            long wr = 0;
            for (i = 0; i < 4; i++)
                wr |= caoin_pwrite(((u32 *)caoin_replay) + i, &c->saved_abort[i], 4);
            {
                u32 jmp[5];
                caoin_emit_abs_jump(jmp, (unsigned long)c->p_abort + 16);
                wr |= caoin_pwrite(caoin_jmp_slot, jmp, sizeof(jmp));
            }
            CK_LOG("caoin2: replay fill wr=%ld\n", wr);
            asm volatile("ic iallu" ::: "memory");
            asm volatile("dsb ish" ::: "memory");
        }
        rc_stop = stopm(caoin_install_stub, 0, 0);
        CK_LOG("caoin2: stopm=%ld\n", rc_stop);
        caoin_ktext_perm((unsigned long)c->p_abort, 0);
        caoin_ktext_perm((unsigned long)caoin_replay, 0);
        if (u1 || u2 || rc_stop) {
            CK_LOG("caoin2: hook install failed, bail out safely\n");
            return -EINVAL;   /* 未装上：不切视图，安全退出 */
        }
    }
    c->hooked = 1;

    /* ---- 切到 shadow 视图 ---- */
    set_pte((pte_t *)(unsigned long)c->pte_addr, __pte((unsigned long)c->shadow_pte_val));
    c->cur_view = 1;
    caoin_tlb_flush((unsigned long)c->target_va);
    {
        unsigned long back = 0;
        caoin_probe(&back, (void *)(unsigned long)c->pte_addr, 8);
        CK_LOG("caoin2: shadow_pte=%lx readback=%lx\n",
               (unsigned long)c->shadow_pte_val, back);
    }

    caoin_write_status2(mmv, pgd_off, (unsigned long)c->status_va, 0x1);
    CK_LOG("caoin2: seesaw on (mm=%lx pgd_off=%lx)\n", mm_off, pgd_off);
    return 0;
}

static void __exit caoin_exit(void)
{
    struct caoin_cfg *c = &caoin_cfg_block;
    if (c->magic != CAOIN_CFG_MAGIC || !c->pte_addr)
        return;
    caoin_probe = (void *)(unsigned long)c->probe_read;
    caoin_printk = (void *)(unsigned long)c->printk;

    /* 先回原 PTE（视图合一），再拆钩子 */
    set_pte((pte_t *)(unsigned long)c->pte_addr, __pte((unsigned long)c->orig_pte));
    c->cur_view = 0;
    caoin_tlb_flush((unsigned long)c->target_va);

    if (c->hooked) {
        int (*stopm)(int (*)(void *), void *, const void *) =
            (void *)(unsigned long)c->p_stop;
        /* 视图已合一（过滤器对受管页恒否），但拆钩子必须停机同步：
           do_mem_abort 是全系统 fault 高频路径，半写状态被其他 CPU 执行 = 野跳 panic */
        caoin_ktext_perm((unsigned long)c->p_abort, 1);
        stopm(caoin_remove_stub, 0, 0);
        caoin_ktext_perm((unsigned long)c->p_abort, 0);
        c->hooked = 0;
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
    CK_LOG("caoin2: seesaw off, restored\n");
}

module_init(caoin_init);
module_exit(caoin_exit);
MODULE_LICENSE("GPL");
