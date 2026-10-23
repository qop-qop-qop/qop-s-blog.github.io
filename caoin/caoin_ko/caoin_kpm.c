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
/* ---- capture 模式（stubmode=3）----
 * handler 入口先按原寄存器触发一次哨兵 fault，KPM 在 EL1 从目标 mm 读缓冲区
 * 拷到内核页，然后继续执行原逻辑。ctl0 "dump <off> <len>" 取回数据。 */
static u64 cfg_capmax;         /* 0 = 关闭 */
static int cfg_cap_ptr = -1;   /* 缓冲区指针所在寄存器 xN */
static int cfg_cap_len = -1;   /* 长度所在寄存器 xN */
static u64 cfg_cap_off;        /* 从指针再加的偏移（IL2CPP 数组数据在对象 +0x20） */
static u64 cfg_cap_min;        /* 只捕获长度 >= capmin 的缓冲区（过滤小字符串） */
static int cfg_cap_text;       /* 只捕获开头是可打印 ASCII 的缓冲区（Lua 源码） */
/* 多关键字过滤：capfind=<hex>，解码后可用 ',' 分隔多个关键字
 * （例如 Damage,Hurt,LoseLife）。最多 4 个，每个 <= 23 字节。 */
#define CAOIN_CAPKW_MAX 4
#define CAOIN_CAPKW_LEN 24
static unsigned char capkw[CAOIN_CAPKW_MAX][CAOIN_CAPKW_LEN];
static int capkw_len[CAOIN_CAPKW_MAX];
static int capkw_n;
static int capfind_dbg;                  /* 一次性日志：确认过滤路径真的在跑 */
static u64 kcap;               /* 内核 capture 页线性地址；前 8 字节存长度 */
static int cap_order;          /* kcap 的 __get_free_pages order */
static u64 cap_len;            /* 最近一次捕获长度 */
static u64 cap_cnt;            /* 捕获次数 */
/* status 页兼作 handler/trampoline 页时的 PTE 备份（改成 RWX 用） */
static u64 sva_pte_addr;
static u64 sva_orig_pte;
static volatile u64 vbar_on;   /* 语义沿用：1 = 已接管 fault 入口 */
static int g_hooks_installed;  /* do_page_fault/exit_mmap 等内核钩子已装 */
static u64 mm_run, mm_off, pgd_off;
static unsigned long mm_run_pgd;      /* 目标进程 pgd 指针(init 时锁定) */
static unsigned long el0_table_base;  /* EL0 页表基址（哨兵发现，PA；0=未发现） */
/* KPTI 副本扫描结果：1 = 没找到独立 user_pgd（TTBR0 == mm->pgd）。
 * 此时 caoin_flip_hook 已经改到 EL0 实际使用的那张表，caoin_flip_el0
 * 完全是冗余的；而它缓存的是**物理地址**，一旦页表页被回收复用就是
 * 悬空写。真机实测（2026-10-19）设备在 caoin 挂载约 7 分钟后于
 * surfaceflinger/sync_file_ioctl 触发内核 BUG，因此默认关掉这条冗余路径。 */
static int g_no_kpti;
static u64 g_force_el0flip;   /* el0flip=1 强制保留（仅调试用） */
static volatile u64 ec20_cnt, ec24_cnt, sent_cnt;
/* 方案 D 计数：selfread_ok = 自指访问被软件模拟成功（不翻转）；
 * selfread_fb = 形态不认识、回退到翻转（可能活锁，用于定位漏掉的编码） */
static volatile u64 selfread_ok_cnt, selfread_fb_cnt;

/* ---- 并发插桩 ----
 * 把"无锁竞态"从推演变成可数。前提：翻转是幂等的（每个状态写固定 PTE 值），
 * 所以同方向的并发翻转无害；危险的是反方向交错导致 cur_view 与 PTE 脱同步。
 * 脱同步的两个可观测特征（都走 caoin 现有的"非预期分支"）：
 *   desync_a：cur_view==SHADOW 却收到取指 fault（SHADOW 可执行，取指不该 fault）
 *   desync_b：cur_view==STEP  却收到数据 fault（STEP 可读，读不该 fault）
 * overlap：进入受管页 handler 时已有别的 CPU 在里面 —— 并发进入的直接证据。
 * 用法：verbose=1 时每 262144 条打一次；卸载时无条件打一次（不依赖 ctl0）。 */
static volatile u64 g_entries, g_overlap, g_desync_a, g_desync_b;
static volatile int g_in_mh;
/* engage 诊断：受管页帧上的 fault 总数（含被 is_target_proc 拒掉的）。
 * 非零但 entries==0 → 说明 fault 被"他进程"判据放行了（那会走 native 路径
 * 把 PTE 修回原页 → hook 静默失效）。两者都为 0 → 根本没有 fault → 是 TLB
 * 一直用旧翻译（PTE 已翻但没生效）。 */
static volatile u64 g_mf_seen, g_mf_nottarget;

/* ---- 自愈（路线 1）：mprotect/madvise/回收会用 VMA 的 vm_page_prot 重刷或
 * zap 受管页 PTE → 影子 PFN 被覆盖回原页 → 桩静默失效，且受管页从此不再
 * fault（可读可执行）→ handler 无从察觉。
 * 这里在目标进程的**任意** fault 上限频重 walk 受管 VA 的 PTE：发现 PFN 漂移
 * 且视图未 OFF → 重写影子 PTE + 翻回 SHADOW + flush，把 hook 拉回来。
 * 必须用目标的 fault 触发（失效后受管页不再 fault，所以不能把检查放在
 * 受管页分支里）。
 *
 * **默认关闭（rearm=1 才开）**：真机实测该自愈**救不回** madvise——重写确实
 * 触发了（日志 `re-arm hook0 pte 0 -> <shadow>`），但取指仍然 translation fault：
 * madvise 拆的是**页表结构**而不是单个 PTE 值，重写落空；更糟的是此时内核正在
 * 拆页表，walk 到的 L3 可能已被释放复用 → 往复用页里写 = 随机内核内存写。
 * 所以默认路径不放它，保留代码是为了记录这条路线已被实测否掉（DEVLOG P3-v6 §5）。 */
#define CAOIN_REARM_MASK 0x0F   /* 每 16 次目标 fault 查一次 */
static u64 g_rearm_on;          /* rearm=1 开自愈；**默认关**，见上 */
static u64 g_rearm_tick;
static volatile u64 g_rearm_cnt;
/* 内核侧页分配（方案：影子页/status 页下沉，消掉目标 maps 里的 2 条匿名 VMA）。
 * GFP_KERNEL=0xcc0：与 wxshadow 同生态实测值（__get_free_pages 的 flags 是
 * 数值宏，不在 kallsyms 里，只能取经验值——wxshadow 在同类内核上用同一个数）。 */
static unsigned long (*kfn_get_free_pages)(unsigned int, unsigned int);
static void (*kfn_free_pages)(unsigned long, unsigned int);
static u64 kstatus;            /* 内核分配的 status 页（线性地址）；0=用用户态 sva */
#define CAOIN_GFP_KERNEL 0xcc0u

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
    u64 kshadow;                /* 内核分配的影子页（线性地址）；0=用用户态 shva */
    u64 orig_pfn;               /* 原页 PFN（rmap/RSS 记账用） */
    u64 zap_acct;               /* 本轮 SHADOW 是否已为外部 zap 补过记账 */
    u64 pinned;                 /* 是否持有原页的额外引用（防止被回收） */
};
static struct caoin_hook hooks[CAOIN_MAX_HOOKS];
static int hooks_n;
static volatile int g_fork_pause;   /* >0 = fork 快照期间，fault 不翻 PTE */

/* ---- kallsyms 解析的内核函数 ---- */
static long (*kfn_probe_read)(void *, const void *, unsigned long);
static long (*kfn_probe_write)(void *, const void *, unsigned long);
static long (*kfn_copy_to_user)(void *, const void *, unsigned long);
static void *(*kfn_find_task_by_vpid)(int);
static s64 *kvar_memstart_addr;
static unsigned long page_offset_base;

/* ---- 页记账（修复 Bad page state / Bad rss-counter）----
 * shadow PTE 指向内核分配的页，内核不知道这个映射。zap（exit_mmap/
 * madvise/回收）会把 shadow 页当普通映射页 page_remove_rmap + put_page，
 * 于是 shadow 页被释放（UAF）并报 Bad page state。
 *
 * 修法（已在 vmlinux 上核对）：
 *  1. shadow PTE 置 PTE_SPECIAL(bit56) → __vm_normal_page 返回 NULL，
 *     zap 直接跳过该 PTE 的页记账，不会释放 shadow 页；
 *  2. PTE 指向 shadow 时原页不再被映射 → 翻转时 page_remove_rmap(原页)
 *     并 mm->rss_stat[MM_FILEPAGES]--；翻回原页时相反操作。
 *     （rss_stat 偏移由 __mmdrop 内联的 check_mm 反汇编得到：mm+0x2b0）
 *  3. 原页 struct page 由 pfn_to_page 得到（__vm_normal_page 反汇编：
 *     VMEMMAP_BASE + ((pa - memstart_addr) >> 6)，struct page=64B）。 */
#define CAOIN_PTE_SPECIAL   (1UL << 56)
#define CAOIN_VMEMMAP_BASE  0xffffffbf00000000ULL
static void (*kfn_page_remove_rmap)(void *, int);
static void (*kfn_page_add_file_rmap)(void *, int);
static void (*kfn___put_page)(void *);
static unsigned long g_rss_off = 0x2b0;   /* mm->rss_stat.count[0] */
static u64 g_acct_on = 1;                 /* acct=0 关闭（排障用） */

/* ---- mmap_sem 同步 ----
 * 我们的 do_page_fault 钩子挂在函数入口，内核是在函数内部才
 * down_read(&mm->mmap_sem) 的。所以翻转 PTE 时和 munmap/madvise
 * 拆页表没有互斥 → 可能往已释放/复用的页表页写（真机 Bad page map）。
 * 这里自己在受管页 fault 时拿读锁，和写锁互斥。
 * 偏移 0x70 来自 vmlinux do_page_fault 反汇编：
 *   add x25, x24, #0x70; bl down_read
 * （可用 msem=<hex> 覆盖）。 */
static void (*kfn_down_read)(void *);
static void (*kfn_up_read)(void *);
static unsigned long g_mmap_sem_off = 0x70;

static int caoin_mm_lock(void)
{
    if (!kfn_down_read || !kfn_up_read || !mm_run || !g_mmap_sem_off)
        return 0;
    kfn_down_read((void *)(mm_run + g_mmap_sem_off));
    return 1;
}

static void caoin_mm_unlock(void)
{
    kfn_up_read((void *)(mm_run + g_mmap_sem_off));
}

static u64 g_verbose;   /* verbose=1 开流程日志；默认静音（无痕优先），错误路径仍打 */
static u64 g_quiet;     /* quiet=1 连错误日志也不打（生产无痕用） */
static u64 g_polymorph; /* polymorph=1 随机化入口桩寄存器/stub 值/status magic */
static u64 g_stub_seed; /* polymorph 的派生种子（init 时由 tva/pid/task 生成） */
static void *g_copy_process;   /* fork 防护 hook 目标（装不上为 NULL） */
static u64 g_stub_onload;      /* stub=1：加载即装桩（跳过 INJ_REQ 握手，
                                * 供 caoin_prep 自动化流程——目标不发请求） */
/* recstub 的"改参数"规格：argN=<val>（N=0..7）时 handler 先把 xN 改成该值再跑
 * 原函数。没给就退化成纯透传（handler 只剩一条 b trampoline）。
 * 注意这里刻意**不记录参数**：观察型需求走 caoin-hw（KPM 每次命中都能读寄存器，
 * 零足迹）；影子路线做"改行为"。理由是报告区在受管页内会矛盾——SHADOW 视图下
 * 该页 EL0 无数据访问，桩的 str 要么 fault、要么（翻到 STEP 后）写进原页污染
 * 代码段、破坏 CRC 自检。 */
#define CAOIN_MAX_ARGS 31       /* x0..x30（x31 是 SP，桩在 EL0 改它太危险，不做） */
static u64 g_args[CAOIN_MAX_ARGS];
static int g_has_arg[CAOIN_MAX_ARGS];
static int g_nargs_installed;

/* 按需生成 movz/movk 序列（高位全零的 movk 跳过）。movz 会清整个寄存器，
 * 所以跳过后面的零 movk 是正确的。返回写入的指令数。 */
static int caoin_emit_movx(u32 *dst, int rd, u64 v)
{
    int n = 0;
    dst[n++] = 0xD2800000u | ((u32)((v >>  0) & 0xFFFF) << 5) | (u32)rd;
    if (v >> 16)
        dst[n++] = 0xF2A00000u | ((u32)((v >> 16) & 0xFFFF) << 5) | (u32)rd;
    if (v >> 32)
        dst[n++] = 0xF2C00000u | ((u32)((v >> 32) & 0xFFFF) << 5) | (u32)rd;
    if (v >> 48)
        dst[n++] = 0xF2E00000u | ((u32)((v >> 48) & 0xFFFF) << 5) | (u32)rd;
    return n;
}

/* 日志双档：CK_ERR 永远打（加载失败必须可见）；CK_LOG 默认静音。
 * ctl0 dump 不受门控（显式查询动作）。 */
#define CK_ERR(...) do { if (!g_quiet) pr_info(__VA_ARGS__); } while (0)
#define CK_LOG(...) do { if (g_verbose) pr_info(__VA_ARGS__); } while (0)

/* ---- 地址换算 ---- */
static unsigned long caoin_va(unsigned long pa)
{
    return (unsigned long)((pa - (u64)*kvar_memstart_addr) + page_offset_base);
}

/* 线性地址 → 物理地址（caoin_va 的逆）。内核分配的页要靠它拿 PFN 填进目标 PTE。 */
static unsigned long caoin_pa(unsigned long va)
{
    return (unsigned long)((va - page_offset_base) + (u64)*kvar_memstart_addr);
}

/* ---- 内核分配影子页（消 maps 足迹）----
 * 必须在 orig_pte 已推导之后调用：orig_pte 给出原页 PFN，是拷贝源。
 * 拷贝一律走内核线性地址——绝不碰用户 VA（EL1 读用户 VA 在 SW_TTBR0_PAN 下
 * 直接 fault，README 有记录）。原页可能是 file-backed，线性映射读即可。 */
static int caoin_alloc_shadow(struct caoin_hook *h)
{
    unsigned long kva, opa, orig_pfn, i;

    if (!h || !kfn_get_free_pages || !kfn_probe_read)
        return -1;
    orig_pfn = h->orig_pte & CAOIN_PFN_MASK;
    if (!orig_pfn) {
        CK_ERR("caoin-kpm: alloc_shadow: orig_pfn unknown\n");
        return -1;
    }
    kva = kfn_get_free_pages(CAOIN_GFP_KERNEL, 0);
    if (!kva) {
        CK_ERR("caoin-kpm: alloc_shadow: __get_free_pages failed\n");
        return -1;
    }
    h->kshadow = kva;
    opa = caoin_va(orig_pfn);
    for (i = 0; i < 0x1000; i += 8) {
        u64 w = 0;
        if (kfn_probe_read(&w, (void *)(opa + i), 8)) {
            CK_ERR("caoin-kpm: alloc_shadow: copy fail off=%lx\n", i);
            return -1;
        }
        *(volatile u64 *)(kva + i) = w;
    }
    asm volatile("dsb ish" ::: "memory");
    CK_ERR("caoin-kpm: kshadow=%lx pfn=%lx (copy of orig pfn=%lx)\n",
           kva, caoin_pa(kva) & CAOIN_PFN_MASK, orig_pfn);
    return 0;
}

static void caoin_set_pte(u64 *ptep, u64 val)
{
    if (!ptep)
        return;
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
    if (!(e0 & 2))          /* 1GB block：本 walk 只处理 4K PTE */
        return 0;
    if (kfn_probe_read(&e2, (void *)caoin_va((e0 & m) + ((va >> 21) & 0x1FF) * 8), 8))
        return 0;
    if (!(e2 & m))
        return 0;
    if (!(e2 & 2))          /* 2MB block：同上 */
        return 0;
    pte_a = caoin_va((e2 & m) + ((va >> 12) & 0x1FF) * 8);
    if (kfn_probe_read(&pte_v, (void *)pte_a, 8))
        return 0;
    if (!(pte_v & 2))       /* level-3 必须是 page descriptor */
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

/* 读受管页当前 PTE（判断 AP/UXN 是否被 mprotect 改过）。 */
static int caoin_cur_pte(struct caoin_hook *h, u64 *out)
{
    unsigned long pte_a = 0;
    u64 cur = 0;

    if (!h || !out || !caoin_walk_pgd_via_mm(h->tva, &pte_a)
        || kfn_probe_read(&cur, (void *)pte_a, 8))
        return 0;
    *out = cur;
    return 1;
}

/* 读目标用户 VA：自己走页表（支持 4KB PTE 与 2MB/1GB block 映射），
 * 再经内核线性地址读。不能直接 probe_kernel_read(user_va)：PAN 下 EL1
 * 访问用户 VA 会失败（capture 实测 p=... l=0x10000 直接 READFAIL）。
 * 大页支持是必须的：il2cpp/Lua 堆常用 THP，2MB block 在 L2 的 bit1=0。 */
static int caoin_read_user(void *dst, unsigned long va, unsigned long n)
{
    unsigned char *d = (unsigned char *)dst;

    while (n) {
        unsigned long e0, e2, pte_v, pa, chunk;

        if (kfn_probe_read(&e0, (void *)(mm_run_pgd + ((va >> 30) & 0x1FF) * 8), 8))
            return -1;
        if (!(e0 & 1))
            return -1;
        if (!(e0 & 2)) {                       /* 1GB block */
            pa = (e0 & ~0x3FFFFFFFUL) + (va & 0x3FFFFFFFUL);
            chunk = 0x40000000UL - (va & 0x3FFFFFFFUL);
            if (chunk > n) chunk = n;
            if (kfn_probe_read(d, (void *)caoin_va(pa), chunk))
                return -1;
            d += chunk; va += chunk; n -= chunk;
            continue;
        }
        if (kfn_probe_read(&e2, (void *)(caoin_va(e0 & CAOIN_PFN_MASK)
                                         + ((va >> 21) & 0x1FF) * 8), 8))
            return -1;
        if (!(e2 & 1))
            return -1;
        if (!(e2 & 2)) {                       /* 2MB block */
            pa = (e2 & ~0x1FFFFFUL) + (va & 0x1FFFFFUL);
            chunk = 0x200000UL - (va & 0x1FFFFFUL);
            if (chunk > n) chunk = n;
            if (kfn_probe_read(d, (void *)caoin_va(pa), chunk))
                return -1;
            d += chunk; va += chunk; n -= chunk;
            continue;
        }
        if (kfn_probe_read(&pte_v, (void *)(caoin_va(e2 & CAOIN_PFN_MASK)
                                            + ((va >> 12) & 0x1FF) * 8), 8))
            return -1;
        if (!(pte_v & 1))
            return -1;
        pa = (pte_v & CAOIN_PFN_MASK) + (va & 0xFFF);
        chunk = 0x1000 - (va & 0xFFF);
        if (chunk > n) chunk = n;
        if (kfn_probe_read(d, (void *)caoin_va(pa), chunk))
            return -1;
        d += chunk; va += chunk; n -= chunk;
    }
    return 0;
}

/* 影子页的内核线性地址：内核分配直接用；用户态 mmap 则 walk 其 PTE 取 PFN。 */
static unsigned long caoin_shadow_kva(struct caoin_hook *h)
{
    unsigned long pte_a = 0, pte_v = 0;

    if (!h)
        return 0;
    if (h->kshadow)
        return h->kshadow;
    if (caoin_walk_pgd_via_mm(h->shva, &pte_a)
        && !kfn_probe_read(&pte_v, (void *)pte_a, 8)
        && (pte_v & CAOIN_PFN_MASK))
        return caoin_va(pte_v & CAOIN_PFN_MASK);
    return 0;
}

static void status_mark(u64 v);
static void caoin_install_stub(int hi);
static void caoin_install_minstore(int hi);
static void caoin_install_recstub(int hi);
static int stub_mode = 0;   /* 0=替换桩(777) 1=minstore 2=记录透传(recstub) */
static void caoin_sync_after_flip(void); /* 保留:占位 */

/* ---- KPM 侧指令重定位器（caoin_reloc.c，从 hook/reloc.c 移植）----
 * 用来重定位被入口桩覆盖的 4 条序言指令 —— 这是"记录+透传桩"能跑真实函数的
 * 前提（原版不做重定位，所以 README 说"目标函数须为寄存器运算型"）。 */
#define CAOIN_OFF_HANDLER  0x800UL
#define CAOIN_OFF_TRAMP    0xA00UL
#define CAOIN_OFF_REPORT   0xF00UL
/* handler 区 0x800..0xA00 = 128 条指令（31 个寄存器全给满、每个最多 4 条
 * movz/movk 也装得下；跳高位的 movk 会被跳过，实际远小于 128） */
#define CAOIN_HANDLER_INSN_MAX 128
extern unsigned long caoin_reloc_block(u32 *dst, unsigned long dst_addr,
                                       const u32 *src, unsigned long src_addr,
                                       int out_status[4]);

/* 入口桩（KPM 版）：adrp x16, <受管页> + add x16, x16, #<handler 页内偏移> + br x16。
 * 恰好 3 条（≤ 16 字节）。**刻意不用 `LDR X16,#8; BR X16; <handler>`** ——
 * 那个 literal 在受管页内，而 D 的自指读模拟是从**原页**读的（CRC 场景的正确
 * 语义：读必须看到原页字节），于是 LDR 拿到的是原页的指令字节 = 垃圾地址 →
 * BR 飞掉 → SIGSEGV（真机实测）。adrp+add 不读内存，绕开这个语义冲突。 */
static void caoin_make_entry_stub(u32 *dst, unsigned long handler_off, int reg)
{
    dst[0] = 0x90000000u | (u32)reg;                              /* adrp xN, page */
    dst[1] = 0x91000000u | ((u32)(handler_off & 0xFFF) << 10)
           | ((u32)reg << 5) | (u32)reg;
    dst[2] = 0xD61F0000u | ((u32)reg << 5);                       /* br xN */
}

/* 入口桩（跨页版）：adrp x16, <target_page> + add x16, x16, #<target_off> + br x16。
 * handler/trampoline 放在 status 页（与受管页不同页）时用；ADRP 范围 ±4GB。 */
static int caoin_make_entry_stub_far(u32 *dst, unsigned long stub_va,
                                     unsigned long target_va, int reg)
{
    /* 必须先转 signed 再减：两者都是 unsigned long，target < stub 时
     * 直接相减会下溢成 2^64-x，右移后变成巨大的正数（实测 pd=2^52-0xA23F）。 */
    long pd = ((long)(target_va & CAOIN_PAGE_MASK)
               - (long)(stub_va & CAOIN_PAGE_MASK)) >> 12;
    u32 immlo, immhi;

    CK_ERR("caoin-kpm: stub_far stub=%lx target=%lx pd=%ld\n",
           stub_va, target_va, pd);
    if (pd < -(1L << 20) || pd >= (1L << 20))
        return -1;
    immlo = (u32)(pd & 3);
    immhi = (u32)((pd >> 2) & 0x7FFFF);
    dst[0] = 0x90000000u | (immlo << 29) | (immhi << 5) | (u32)reg;
    dst[1] = 0x91000000u | ((u32)(target_va & 0xFFF) << 10)
           | ((u32)reg << 5) | (u32)reg;
    dst[2] = 0xD61F0000u | ((u32)reg << 5);
    return 0;
}

/* reloc 读 LDR literal 数据用。受管页 VA 内的读走影子页线性地址（影子页是
 * 原页忠实副本，数据一致）；其余地址用 probe_read 安全读，失败即返回非 0
 * （reloc 会放弃重定位）——绝不直接解引用用户 VA（EL1 下 PAN 必 fault）。 */
static unsigned long g_rd_va_base, g_rd_kva_base;

int caoin_kpm_read_va(void *dst, unsigned long va, unsigned long n)
{
    unsigned long src = va;
    unsigned char *d = (unsigned char *)dst;
    unsigned long i;

    if (g_rd_va_base && va >= g_rd_va_base && va < g_rd_va_base + 0x1000)
        src = g_rd_kva_base + (va - g_rd_va_base);
    for (i = 0; i < n; i++) {
        unsigned char c = 0;
        if (kfn_probe_read(&c, (void *)(src + i), 1))
            return -1;
        d[i] = c;
    }
    return 0;
}

/* ---- EL0 页表 PTE flip（按 hook）----
 * 本机实测 TTBR0 == mm->pgd（无 KPTI 副本），故 EL0 表 PTE == mm->pgd 的
 * PTE；一般情形走 el0_table_base（哨兵发现）单独 walk。每 hook 独立缓存。 */
static void caoin_flip_el0(int hi, u64 view, int force)
{
    struct caoin_hook *h = &hooks[hi];
    unsigned long pa, pte_a = 0, pte_v = 0;
    u64 v;
    int lk;

    /* 不做缓存快路径：每次重新 walk + PFN 校验。缓存的是页表页的物理地址，
     * 页表被回收复用后写进去就是随机内核内存写（2026-10-19 真机事故的
     * 头号嫌疑）。walk 成本只在每次视图翻转时付一次，可以接受。 */
    if (!el0_table_base)
        return;   /* 哨兵未发现 EL0 表：跳过（mm->pgd 主路径已覆盖本机） */
    if (!force && __atomic_load_n(&g_fork_pause, __ATOMIC_ACQUIRE))
        return;   /* fork 快照期间不写 EL0 表（主表已由 pause 恢复） */
    /* EL0 表写也必须和 munmap/madvise 的写锁互斥。 */
    lk = caoin_mm_lock();
    pa = el0_table_base;
    if (!caoin_walk_pgd(caoin_va(pa), h->tva, &pte_a))
        goto out;
    if (kfn_probe_read(&pte_v, (void *)pte_a, 8))
        goto out;
    if ((pte_v & CAOIN_PFN_MASK) != (h->orig_pte & CAOIN_PFN_MASK)
        && (pte_v & CAOIN_PFN_MASK) != (h->shadow_pte_val & CAOIN_PFN_MASK))
        goto out;   /* 不是本 hook 的页（别的进程/ASID） */
    /* 只有独立副本（KPTI）才记录：与 mm->pgd 同一张表时，restore/fork
     * 路径不该再单独写一遍。 */
    h->el0_pte_addr = (pte_a != h->pte_addr) ? pte_a : 0;
    if (!h->el0_pte_addr)
        goto out;   /* 与 mm->pgd 同一张表：主路径已写过，别再写 NULL */
    if (view == VIEW_SHADOW)
        v = (pte_v & ~(CAOIN_PFN_MASK | PTE_AP_MASK | PTE_UXN))
          | (h->shadow_pte_val & CAOIN_PFN_MASK) | 0x80UL | CAOIN_PTE_SPECIAL;
    else if (view == VIEW_STEP)
        v = (pte_v & ~(CAOIN_PFN_MASK | PTE_AP_MASK | PTE_UXN
                       | CAOIN_PTE_SPECIAL))
          | (h->origview_pte_val & (CAOIN_PFN_MASK | PTE_AP_MASK))
          | PTE_UXN;
    else
        v = pte_v;
    caoin_set_pte((u64 *)h->el0_pte_addr, v);
    caoin_tlb_flush(h->tva);
    CK_LOG("caoin-kpm: el0 table %lx hook%d pte=%lx view=%llu\n",
           pa, hi, pte_a, (unsigned long long)view);
out:
    if (lk)
        caoin_mm_unlock();
}

/* ---- 原页记账 ----
 * shadow PTE 指向内核页时，原页实际上不再被这个 VMA 映射。内核的
 * rmap/RSS 记账必须同步摘除，否则退出/munmap 时会对不上：
 *   - 不摘除 → 原页 mapcount 多 1，最终 free 时报 Bad page state；
 *   - 不恢复 → PTE 回到原页后 mapcount 少 1，同样报错。
 * PTE 指向 shadow 时带 PTE_SPECIAL，zap 会跳过 shadow 页本身（不会释放它），
 * 所以这里只需要维护原页。 */
static void caoin_flip_hook(int hi, u64 view);

static void *caoin_pfn_to_page(u64 pfn)
{
    unsigned long pa = (unsigned long)(pfn << 12);
    unsigned long ms = (unsigned long)(s64)*kvar_memstart_addr;
    return (void *)(CAOIN_VMEMMAP_BASE + ((pa - ms) >> 6));
}

static void caoin_acct_orig(struct caoin_hook *h, int add)
{
    void *pg;
    if (!g_acct_on || !h->orig_pfn || !kvar_memstart_addr)
        return;

    if (!add) {
        /* 进入 SHADOW 前重新确认当前 PTE：churn 线程的 madvise + 重新
         * fault 可能已经把映射换成另一个页。用缓存的 orig_pfn 记账会
         * 摘错页（mapcount 减成负数 → Bad page map）。 */
        unsigned long pte_a = 0, cur = 0;
        u64 sh_pfn = (h->shadow_pte_val & CAOIN_PFN_MASK) >> 12;
        if (!caoin_walk_pgd_via_mm(h->tva, &pte_a)
            || kfn_probe_read(&cur, (void *)pte_a, 8))
            return;
        if (!(cur & 1)) {
            /* PTE 当前不存在：原页没有映射，无需摘 rmap */
            h->pinned = 0;
            return;
        }
        {
            u64 pfn = (cur & CAOIN_PFN_MASK) >> 12;
            if ((cur & CAOIN_PTE_SPECIAL) || pfn == sh_pfn)
                return;   /* 已经是 shadow 视图 */
            if (pfn != h->orig_pfn) {
                h->orig_pfn = pfn;
                h->orig_pte = cur;
                h->origview_pte_val = (cur & ~PTE_UXN) | PTE_UXN;
                h->shadow_pte_val = (cur & ~(CAOIN_PFN_MASK | PTE_AP_MASK | PTE_UXN))
                                   | (sh_pfn << 12) | 0x80UL | CAOIN_PTE_SPECIAL;
            } else if ((cur & (PTE_AP_MASK | PTE_UXN))
                       != (h->orig_pte & (PTE_AP_MASK | PTE_UXN))) {
                /* 同一页但 mprotect 改了权限：更新缓存的 AP/UXN，
                 * 否则 STEP 的 RO/RW 判断会用旧权限。 */
                h->orig_pte = (h->orig_pte & ~(PTE_AP_MASK | PTE_UXN))
                            | (cur & (PTE_AP_MASK | PTE_UXN));
                h->origview_pte_val = (h->orig_pte & ~PTE_UXN) | PTE_UXN;
            }
        }
    }

    pg = caoin_pfn_to_page(h->orig_pfn);
    if (add) {
        /* 回到原页：先还 pin，再把 rmap/RSS 加回来 */
        if (h->pinned) {
            if (kfn___put_page
                && __atomic_sub_fetch((int *)((char *)pg + 0x1c), 1,
                                      __ATOMIC_RELEASE) == 0)
                kfn___put_page(pg);
            h->pinned = 0;
        }
        if (kfn_page_add_file_rmap)
            kfn_page_add_file_rmap(pg, 0);
        __atomic_add_fetch((long *)(mm_run + g_rss_off), 1, __ATOMIC_RELAXED);
    } else {
        /* 进入 SHADOW：原页不再被这个 VMA 映射 → 摘 rmap/RSS，
         * 并 get_page 钉住它（否则页缓存会回收原页，缓存的 orig_pte 悬空）。 */
        if (kfn_page_remove_rmap)
            kfn_page_remove_rmap(pg, 0);
        __atomic_add_fetch((int *)((char *)pg + 0x1c), 1, __ATOMIC_RELAXED);
        h->pinned = 1;
        __atomic_sub_fetch((long *)(mm_run + g_rss_off), 1, __ATOMIC_RELAXED);
    }
}

/* 外部 zap 把 SHADOW PTE 清掉时：原页的 rmap 已在进入 SHADOW 时摘除，
 * 原生 fault 会按原页重新映射并 +1；这里只需把 pin 还回去。 */
static void caoin_unpin_orig(struct caoin_hook *h)
{
    void *pg;
    if (!g_acct_on || !h->orig_pfn || !h->pinned || !kvar_memstart_addr)
        return;
    pg = caoin_pfn_to_page(h->orig_pfn);
    if (kfn___put_page
        && __atomic_sub_fetch((int *)((char *)pg + 0x1c), 1,
                              __ATOMIC_RELEASE) == 0)
        kfn___put_page(pg);
    h->pinned = 0;
}

/* 视图转换：PTE 写入幂等。
 *
 * 记账模型（关键）：
 *  - SHADOW/STEP 切换**不动**原页 rmap/RSS。原页始终被视为"这个 VMA 的映射"，
 *    这样页缓存不会把它回收掉，缓存的 orig_pte 不会悬空（实测：摘除后原页
 *    被回收，退出时写回 orig_pte → Bad page state）。
 *  - 只有外部 zap（madvise/回收）把 PTE 清掉时，才在 translation fault
 *    分支里把原页 rmap/RSS 摘一次（zap 因 PTE_SPECIAL 跳过了它）。 */
static void caoin_set_view(int hi, u64 view)
{
    struct caoin_hook *h = &hooks[hi];
    u64 old;

    for (;;) {
        old = __atomic_load_n(&h->cur_view, __ATOMIC_RELAXED);
        /* 已经是目标视图：不要再写 PTE。外部 zap 之后 cur_view=OFF，
         * 此时 PTE 已由内核重新建立（可能是新的原页），拿缓存的 orig_pte
         * 覆盖它 = 写回悬空 PFN（实测 Bad page map）。 */
        if (old == view)
            return;
        if (!__atomic_compare_exchange_n(&h->cur_view, &old, view, 0,
                                         __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            continue;
        if (view == VIEW_SHADOW) {
            /* 先摘原页 rmap/RSS（+pin），再写特殊 PTE。顺序反过来会留一个
             * 窗口：PTE 已指向 shadow、原页 rmap 还在 → 回收的 rmap walk
             * 看到 PTE 与 page 不匹配，报 Bad page map（真机实测）。 */
            caoin_acct_orig(h, 0);
            caoin_flip_hook(hi, view);
            return;
        }
        /* 离开 SHADOW：先恢复原页记账（还 pin + rmap/RSS），再写回 PTE */
        if (old == VIEW_SHADOW)
            caoin_acct_orig(h, 1);
        caoin_flip_hook(hi, view);
        return;
    }
}

/* 非 fault 上下文的视图切换（fork pause/resume、restore）也拿 mmap_sem，
 * 防止与并发的 munmap/madvise 拆页表相撞。 */
static void caoin_set_view_locked(int hi, u64 view)
{
    int lk = caoin_mm_lock();
    caoin_set_view(hi, view);
    if (lk)
        caoin_mm_unlock();
}

/* STEP 视图：保留 VMA 的 AP 权限（RO 页不能变成 EL0 可写），只加 UXN。
 * cur 是当前 PTE：
 *  - 原页 → 直接用它的 AP（mprotect 已经写进 PTE）
 *  - 影子页且 AP/UXN 不是我们的 0x80/0（mprotect 改过）→ 用它的 AP
 *  - 正常影子页 → 用缓存的 orig_pte 的 AP
 * 返回值同时更新 origview_pte_val，供 caoin_flip_el0 复用。 */
static u64 caoin_step_pte(struct caoin_hook *h, u64 cur)
{
    u64 base = h->orig_pte;
    u64 ap = h->orig_pte & PTE_AP_MASK;

    if ((cur & CAOIN_PFN_MASK) == (h->orig_pte & CAOIN_PFN_MASK)) {
        base = cur;
        ap = cur & PTE_AP_MASK;
    } else if ((cur & CAOIN_PFN_MASK) == (h->shadow_pte_val & CAOIN_PFN_MASK)
               && ((cur & PTE_AP_MASK) != 0x80UL || (cur & PTE_UXN) != 0)) {
        ap = cur & PTE_AP_MASK;
    }
    h->origview_pte_val = (base & ~(PTE_AP_MASK | PTE_UXN)) | ap | PTE_UXN;
    return h->origview_pte_val;
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
    /* 每次都重新 walk，不用缓存的 pte_addr：目标 mm 变化时页表页可能被
     * 释放并复用给别的进程（真机实测写进了 android.bg 的页表，报
     * "Bad page map"）。walk 后校验当前 PTE 的 PFN 必须是本 hook 的
     * 原页或影子页，否则放弃写入。 */
    {
        unsigned long pte_a = 0, cur = 0;
        if (!caoin_walk_pgd_via_mm(h->tva, &pte_a))
            return;
        if (kfn_probe_read(&cur, (void *)pte_a, 8))
            return;
        if ((cur & CAOIN_PFN_MASK) != (h->orig_pte & CAOIN_PFN_MASK)
            && (cur & CAOIN_PFN_MASK) != (h->shadow_pte_val & CAOIN_PFN_MASK))
            return;
        if (view == VIEW_STEP) {
            v1 = caoin_step_pte(h, cur);
            if (h->pte_addr2) {
                u64 ap = v1 & PTE_AP_MASK;
                v2 = (h->orig_pte2 & ~(PTE_AP_MASK | PTE_UXN))
                   | ap | PTE_UXN;
                h->origview2_val = v2;
            }
        }
        h->pte_addr = pte_a;
        caoin_set_pte((u64 *)pte_a, v1);
    }
    if (h->pte_addr2) {
        u64 cur2 = 0;
        if (!kfn_probe_read(&cur2, (void *)h->pte_addr2, 8)
            && ((cur2 & CAOIN_PFN_MASK) == (h->orig_pte2 & CAOIN_PFN_MASK)
                || (cur2 & CAOIN_PFN_MASK) == (h->shadow2_val & CAOIN_PFN_MASK)))
            caoin_set_pte((u64 *)h->pte_addr2, v2);
    }
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

int caoin_fault_check(unsigned long addr, struct pt_regs_49 *regs,
                      unsigned int esr, int *hit_out);
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
            /* capture：按 handler 约定寄存器取指针/长度，EL1 读目标 mm */
            if (cfg_capmax && kcap && cfg_cap_ptr >= 0 && cfg_cap_len >= 0) {
                u64 p = regs->regs[cfg_cap_ptr];
                u64 l = regs->regs[cfg_cap_len] & 0xFFFFFFFFULL;
                if (p)
                    p += cfg_cap_off;
                if (l > cfg_capmax)
                    l = cfg_capmax;
                if (l < cfg_cap_min)
                    l = 0;             /* 太小：多半是 "ForEndOfFrame" 这类字符串 */
                if (p && l && cfg_cap_text) {
                    unsigned char tmp[16];
                    unsigned long m = l < 16 ? l : 16;
                    unsigned long k;
                    int ok = 1;
                    if (caoin_read_user(tmp, p, m)) {
                        l = 0;
                    } else {
                        for (k = 0; k < m; k++) {
                            unsigned char c = tmp[k];
                            if (!(c == 9 || c == 10 || c == 13
                                  || (c >= 32 && c < 127))) {
                                ok = 0;
                                break;
                            }
                        }
                        if (!ok)
                            l = 0;     /* 二进制/对象数组：跳过 */
                    }
                }
                if (p && l) {
                    int keep = 1;
                    if (!caoin_read_user((void *)(kcap + 8), p, l)) {
                        /* 关键字过滤：不包含任一关键字就丢弃本次捕获 */
                        if (capkw_n) {
                            int ki, found = 0;
                            if (!capfind_dbg) {
                                capfind_dbg = 1;
                                CK_ERR("caoin-kpm: capfind active nkw=%d "
                                       "kw0=%02x%02x%02x%02x len=%d l=%llx\n",
                                       capkw_n, capkw[0][0], capkw[0][1],
                                       capkw[0][2], capkw[0][3], capkw_len[0],
                                       (unsigned long long)l);
                            }
                            for (ki = 0; ki < capkw_n && !found; ki++) {
                                unsigned long k, kl = (unsigned long)capkw_len[ki];
                                for (k = 0; k + kl <= l && !found; k++)
                                    if (!memcmp((void *)(kcap + 8 + k),
                                                capkw[ki], kl))
                                        found = 1;
                            }
                            if (!found)
                                keep = 0;
                        }
                        if (keep) {
                            *(volatile u64 *)kcap = l;
                            cap_len = l;
                            cap_cnt++;
                        }
                    } else {
                        CK_LOG("caoin-kpm: capture read fail p=%lx l=%llx\n",
                               (unsigned long)p, (unsigned long long)l);
                    }
                }
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

    /* ---- 自愈（路线 1）：限频重查受管 VA 的 PTE ----
     * mprotect / madvise(DONTNEED) / 页回收都会用 VMA 的 vm_page_prot 重写或
     * zap 受管页 PTE → 影子 PFN 被覆盖回原页 → 桩静默失效。失效后受管页变成
     * 可读可执行，**从此不再 fault** → handler 无从察觉，hook 一去不回。
     * 所以检查必须挂在目标进程的**任意** fault 上（这里），且限频。
     *
     * 判据（关键）：只有【cur_view == SHADOW 但 PTE 的 PFN 不是影子页】才算
     * 漂移 → 重写影子 PTE。注意 STEP 视图下 PTE 本来就是原页（合法状态），
     * 不能据此重 arm，否则会打断正常的跷跷板。 */
    if (g_rearm_on && vbar_on && hooks_n && regs && caoin_is_target_proc()
        && (g_rearm_tick++ & CAOIN_REARM_MASK) == 0) {
        int lk = caoin_mm_lock();

        for (i = 0; i < hooks_n; i++) {
            struct caoin_hook *h = &hooks[i];
            unsigned long wa = 0, wv = 0;

            if (h->cur_view != VIEW_SHADOW)
                continue;                 /* STEP/OFF 是合法状态，不动 */
            if (!caoin_walk_pgd_via_mm(h->tva, &wa)
                || kfn_probe_read(&wv, (void *)wa, 8))
                continue;
            if ((wv & CAOIN_PFN_MASK) == (h->shadow_pte_val & CAOIN_PFN_MASK))
                continue;                 /* 仍是影子页，未漂移 ✓ */

            /* 视图说 SHADOW 但 PTE 不是影子页 → 被外部改写 → 重 arm */
            caoin_set_pte((u64 *)wa, h->shadow_pte_val);
            caoin_tlb_flush(0);
            g_rearm_cnt++;
            CK_ERR("caoin-kpm: re-arm hook%d pte %lx -> %lx (view=SHADOW)\n",
                   i, wv, (unsigned long)h->shadow_pte_val);
        }
        if (lk)
            caoin_mm_unlock();
    }

    handled = caoin_fault_check(addr, regs, esr, &hit_hi);
    if (handled) {
        if (hit_hi >= 0 && (!g_no_kpti || g_force_el0flip))
            caoin_flip_el0(hit_hi, hooks[hit_hi].cur_view, 0);
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
    /* recstub 卡死定位：受管页/影子页取指 fault 现场寄存器 dump（限 4 条）。
     * 走到这里 = 状态机【未】接管（活锁的 fault 全被 caoin_fault_check 吃掉，
     * 永远到不了这里），所以这行日志记录的是【另一类】故障。
     * ec 用来看 EL0/EL1：0x20/0x24=EL0，0x21/0x25=EL1。
     * view 是当时该 hook 的视图（0=OFF 1=SHADOW 2=STEP），配合 ec 才能判断
     * "EL1 故障发生时页处于哪个状态"——这是区分 PAN/PTE 异常的唯一线索。 */
    if (regs) {
        static u64 df_n;
        int hit2 = -1, k2;
        for (k2 = 0; k2 < hooks_n; k2++)
            if ((addr >> 12) == (hooks[k2].shva >> 12)
                || (addr >> 12) == (hooks[k2].tva >> 12)
                || (regs->pc >> 12) == (hooks[k2].shva >> 12))
                { hit2 = k2; break; }
        if (hit2 >= 0 && df_n < 4) {
            CK_ERR("caoin-kpm: DUMP pc=%lx far=%lx esr=%x ec=%x view=%d "
                   "x0=%lx x16=%lx x19=%lx\n",
                   regs->pc, addr, esr, (unsigned)(esr >> 26),
                   (int)hooks[hit2].cur_view,
                   regs->regs[0], regs->regs[16], regs->regs[19]);
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
 * SHADOW（shadow | AP=10 X-only）↔ STEP（original | VMA AP + UXN）。
 * SHADOW 下：执行 = 替换桩，读 = fault → 切 STEP；
 * STEP 下：读 = 原页 OK，取指 = UXN fault → 切 SHADOW（eret 重执行取指）。
 * 每个 hook 独立视图状态（cur_view per hook），按 far 页帧匹配分发。 */

/* 受管页上的 DC/IC 维护指令：在只读页上会以 WnR=1 permission fault
 * 的形式打进来。这里在 EL1 用原页的内核线性地址代做，然后 pc+=4 跳过。
 * 返回 1 = 已处理；0 = 不是 cache 维护指令（交给调用方按普通写处理）。 */
static int caoin_emulate_cacheop(struct caoin_hook *h, struct pt_regs_49 *regs)
{
    u32 insn = 0, op;
    u64 va, kva;
    unsigned long orig_pa;
    int rt;

    if (!h || !regs || !kfn_probe_read)
        return 0;
    if (caoin_read_user(&insn, regs->pc, 4))
        return 0;
    op = insn & 0xFFFFFFE0u;
    if (op != 0xD50B7A20u &&   /* DC CVAC */
        op != 0xD50B7E20u &&   /* DC CIVAC */
        op != 0xD50B7B20u &&   /* DC CVAU */
        op != 0xD50B7C20u &&   /* DC CVAP */
        op != 0xD50B7520u)     /* IC IVAU */
        return 0;
    rt = insn & 0x1F;
    if (rt == 31)
        return 0;
    va = regs->regs[rt];
    if ((va >> 12) != (h->tva >> 12))
        return 0;              /* 操作的不是受管页：交给原生 */
    orig_pa = h->orig_pte & CAOIN_PFN_MASK;
    if (!orig_pa)
        return 0;
    {
        unsigned long pas[2];
        int n = 0, k;

        pas[n++] = orig_pa;
        if ((h->shadow_pte_val & CAOIN_PFN_MASK)
            && (h->shadow_pte_val & CAOIN_PFN_MASK) != orig_pa)
            pas[n++] = h->shadow_pte_val & CAOIN_PFN_MASK;
        for (k = 0; k < n; k++) {
            kva = caoin_va(pas[k]) + (va & 0xFFF);
            if (op == 0xD50B7520u)
                asm volatile("ic ivau, %0" :: "r"(kva) : "memory");
            else
                asm volatile("dc civac, %0" :: "r"(kva) : "memory");
        }
    }
    asm volatile("dsb ish" ::: "memory");
    asm volatile("isb" ::: "memory");
    regs->pc += 4;
    return 1;
}

/* ---- 方案 D：自指数据访问的软件模拟 ----
 * 实测（tests/selfread.c，2026-10-15 MI 8 Pro）：SHADOW 视图下若【取指所在页
 * == 受管页】，翻转会形成 SHADOW/STEP 无限振荡——dmesg 实测 ec=24 与 ec=20
 * 严格 35/35 交替、全部 fault 的 pc 与 far 同落受管页、进程 ~82% stime 烧满。
 * 根因：翻转后 eret 要重取指，而重取指被 STEP 的 UXN 挡住，两个状态互斥。
 *
 * 这里不翻转：在 handler 里代读原页、把值写进目标寄存器、pc += 4 跳过该指令。
 * 指令被跳过而不是重试 → 不需要重取指 → 振荡的另一支被拆掉。PTE 全程不动，
 * 于是【受管页不必独占】（页内可以有字面量池/跳转表这类自指读）。
 *
 * 只处理整数 load（含后/前变址写回，实测 selfread 用的是
 * `ldr x1, [x2], #8` 后变址）。store / SIMD / 缓存维护等返回 0，
 * 回退到原翻转路径——语义不变、不崩（可能活锁，用 selfread_fb 计数暴露）。 */
static int caoin_emulate_selfread(struct caoin_hook *h, struct pt_regs_49 *regs,
                                  unsigned long far)
{
    u32 insn;
    unsigned long sh_pfn, or_pfn, kva_sh, kva_or, eff;
    int size, v, opc, rt, rn, mode = -1, is_signed = 0;
    long imm = 0;
    u64 val = 0;

    if (!h || !regs || !kfn_probe_read)
        return 0;
    if ((far >> 12) != (h->tva >> 12))
        return 0;                 /* 数据地址不在受管页：不该走到这里 */

    sh_pfn = h->shadow_pte_val & CAOIN_PFN_MASK;
    or_pfn = h->orig_pte & CAOIN_PFN_MASK;
    if (!sh_pfn || !or_pfn)
        return 0;
    kva_sh = caoin_va(sh_pfn);
    kva_or = caoin_va(or_pfn);

    /* 取指令：从【影子页】线性地址读——CPU 实际执行的就是影子页的字节。
     * 绝不能用用户 VA 读：EL1 下 SW_TTBR0_PAN 会直接 fault（README 有记录）。 */
    if (kfn_probe_read(&insn, (void *)(kva_sh + (regs->pc & 0xFFF)), 4))
        return 0;

    /* ---- LDR (literal)：opc(2) 011 V(1) 00 imm19(19) Rt(5) ----
     * 入口桩的 `LDR X16, #8`（0x58000050）就是这条 —— 它要读的 handler 地址
     * 就在入口桩 +8，**同页 → 自指读**。原来的解码器只认"立即数寻址"那一族
     * （bits 29:27 = 111），这条落回翻转 → 真机实测活锁（ec=24/ec=20 在入口桩上
     * 交替：pc=入口桩、far=入口桩+8）。这一族必须单独处理。 */
    if ((insn & 0x3B000000) == 0x18000000) {
        int lopc = (int)((insn >> 30) & 3);
        int lv   = (int)((insn >> 26) & 1);
        int lrt  = (int)(insn & 0x1F);

        if (lv)
            return 0;                 /* SIMD/FP literal，不处理 */
        if (lopc == 3)
            return 1;                 /* PRFM：无副作用，直接跳过 */

        eff = far & 0xFFF;            /* far 已由硬件算好 = pc + (imm19<<2) */
        if (lopc == 0) {              /* LDR Wt：读 4，零扩展 */
            unsigned int v32 = 0;
            if (kfn_probe_read(&v32, (void *)(kva_or + eff), 4))
                return 0;
            val = (u64)v32;
        } else if (lopc == 1) {       /* LDR Xt：读 8 */
            if (kfn_probe_read(&val, (void *)(kva_or + eff), 8))
                return 0;
        } else {                      /* LDRSW：读 4，符号扩展到 64 */
            unsigned int v32 = 0;
            if (kfn_probe_read(&v32, (void *)(kva_or + eff), 4))
                return 0;
            val = (u64)(s64)(int)v32;
        }
        if (lrt != 31)
            regs->regs[lrt] = val;
        regs->pc += 4;
        return 1;
    }

    /* 只认整数 load/store 立即数类：bits 29:27 = 111 且 V(bit26) = 0 */
    if ((insn & 0x38000000) != 0x38000000)
        return 0;
    v = (insn >> 26) & 1;
    if (v)
        return 0;                 /* SIMD/FP，不处理 */
    size = (insn >> 30) & 3;
    opc  = (insn >> 22) & 3;
    if (opc == 0)
        return 0;                 /* STR：模拟 store 会让"读的人"和"执行的人"分叉，回退 */

    switch ((insn >> 24) & 3) {
    case 1:                       /* 无符号偏移：size 111 V 01 opc imm12 Rn Rt */
        mode = 0;
        imm  = (long)((insn >> 10) & 0xFFF) << size;
        break;
    case 0: {                     /* 未缩放/后变址/前变址：op2 = bits 11:10 */
        int op2 = (insn >> 10) & 3;
        if (op2 == 2)
            return 0;             /* 非特权 LDTR/STTR，不处理 */
        imm = (long)((insn >> 12) & 0x1FF);
        if (imm & 0x100)
            imm -= 0x200;         /* 符号扩展 imm9 */
        mode = (op2 == 0) ? 1 : (op2 == 1 ? 2 : 3);
        break;
    }
    default:
        return 0;
    }
    if (mode < 0)
        return 0;

    rn = (insn >> 5) & 0x1F;
    rt = insn & 0x1F;
    if (opc >= 2)
        is_signed = 1;

    /* 代读原页（走内核线性地址，绕过受管页的 EL0 权限） */
    eff = far & 0xFFF;
    if (size == 3) {
        if (kfn_probe_read(&val, (void *)(kva_or + eff), 8))
            return 0;
    } else if (size == 2) {
        unsigned int v32 = 0;
        if (kfn_probe_read(&v32, (void *)(kva_or + eff), 4))
            return 0;
        val = is_signed ? (u64)(s64)(int)v32 : (u64)v32;
    } else if (size == 1) {
        unsigned short v16 = 0;
        if (kfn_probe_read(&v16, (void *)(kva_or + eff), 2))
            return 0;
        val = is_signed ? (u64)(s64)(short)v16 : (u64)v16;
    } else {
        unsigned char v8 = 0;
        if (kfn_probe_read(&v8, (void *)(kva_or + eff), 1))
            return 0;
        val = is_signed ? (u64)(s64)(signed char)v8 : (u64)v8;
    }

    /* 变址写回：后变址时 far = 旧 Rn → Rn = far + imm；
     * 前变址时 far 已含 imm → Rn = far。Rn=31 是 SP，本路径不处理。 */
    if (rn != 31) {
        if (mode == 2)
            regs->regs[rn] = (u64)far + (u64)imm;
        else if (mode == 3)
            regs->regs[rn] = (u64)far;
    }

    if (rt != 31)                 /* Rt=31 是 XZR，写入丢弃 */
        regs->regs[rt] = val;

    regs->pc += 4;                /* 跳过这条指令：不重取指 → 无振荡 */
    return 1;
}

int caoin_fault_check(unsigned long addr, struct pt_regs_49 *regs,
                      unsigned int esr, int *hit_out)
{
    unsigned int ec = esr >> 26;
    unsigned long pc = regs ? regs->pc : 0;
    int i, ret = 0, locked = 0;

    if (hit_out)
        *hit_out = -1;

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
        g_mf_seen++;
        if (!caoin_is_target_proc()) {
            g_mf_nottarget++;
            return 0;   /* 他进程同 VA：放行（勿吞勿翻，防活锁与视图污染） */
        }

        /* fork 快照期间不翻 PTE。等 pause 完成（有界）再放行原生，
         * 避免原生路径看到 SHADOW 的 permission fault。 */
        if (__atomic_load_n(&g_fork_pause, __ATOMIC_ACQUIRE)) {
            int spin;

            for (spin = 0; spin < 100000
                 && __atomic_load_n(&g_fork_pause, __ATOMIC_ACQUIRE) != 0; spin++)
                asm volatile("yield" ::: "memory");
            return 0;
        }

        /* 与 munmap/madvise/mremap 的 mmap_sem 写锁互斥：我们的钩子在
         * do_page_fault 入口，早于内核自己 down_read，必须自己拿锁，
         * 否则翻 PTE 可能撞上页表页正在被拆/复用。 */
        locked = caoin_mm_lock();

        /* 并发插桩：进入受管页 handler（进出配平，统一从 mh_out 出去） */
        {
            u64 in_mh;

            __atomic_add_fetch(&g_entries, 1, __ATOMIC_RELAXED);
            in_mh = __atomic_add_fetch(&g_in_mh, 1, __ATOMIC_RELAXED);
            if (in_mh > 1)
                __atomic_add_fetch(&g_overlap, 1, __ATOMIC_RELAXED);
        }

        /* 拿锁后再确认一次：可能在第一个检查之后、拿锁之前 fork 才置位。 */
        if (__atomic_load_n(&g_fork_pause, __ATOMIC_ACQUIRE)) {
            ret = 0;
            goto mh_out;
        }
        if (g_verbose && (g_entries & 0x3FFFF) == 0)
            CK_LOG("caoin-kpm: conc entries=%llu overlap=%llu desync_a=%llu "
                   "desync_b=%llu ec20=%llu ec24=%llu\n",
                   (unsigned long long)g_entries, (unsigned long long)g_overlap,
                   (unsigned long long)g_desync_a, (unsigned long long)g_desync_b,
                   (unsigned long long)ec20_cnt, (unsigned long long)ec24_cnt);

        if (ec == 0x24)
            ec24_cnt++;
        else if (ec == 0x20)
            ec20_cnt++;

        /* SHADOW 视图：EL0 数据 fault → 切 STEP（orig 页保留 VMA AP + UXN）。
         * WnR=1 的 DC/IC 维护指令单独代做并跳过（不再把页改成 RW）；
         * PROT_NONE / 只读页上的普通写交给原生 SIGSEGV。
         *
         * 方案 D：若【取指也在受管页内】（自指访问），翻转必然造成
         * SHADOW/STEP 无限振荡（tests/selfread.c 实测 ec=24/ec=20 严格交替）
         * → 改为软件模拟这次读，PTE 保持 SHADOW 不动。形态不认识时回退翻转。 */
        if (h->cur_view == VIEW_SHADOW) {
            /* 外部 zap（madvise/munmap/回收）把 PTE 清掉了 → translation
             * fault。SHADOW 视图下 PTE 带 PTE_SPECIAL，zap 会跳过原页的
             * rmap/RSS；原生 fault 随后会按原页重新 fault-in 并 +1。
             * 这里先补摘一次，让"zap 跳过 + 我们摘除 + 原生加回"三者平衡。 */
            if ((ec == 0x24 || ec == 0x20)
                && (esr & 0x3F) >= 0x4 && (esr & 0x3F) <= 0x7) {
                /* 外部 zap 因 PTE_SPECIAL 跳过了原页；原页的 rmap 已在进入
                 * SHADOW 时摘除，原生 fault 会按原页重新映射并 +1。
                 * 这里只需还掉 pin，不再动 rmap/RSS。 */
                caoin_unpin_orig(h);
                __atomic_store_n(&h->cur_view, VIEW_OFF, __ATOMIC_RELEASE);
                ret = 0;   /* 交给原生 fault 处理（按原页重新映射） */
                goto mh_out;
            }
            /* EL1 data abort on the managed page：内核 uaccess（LDTR/STTR，
             * 例如 write()/read() 预取用户缓冲区、/proc/self/mem）虽然从 EL1
             * 发起，但硬件按 **EL0 权限**检查 AP[1]。SHADOW 视图 AP=10
             * （EL0 无权限）会让它 permission fault，原生路径又修不好 →
             * iov_iter 里无限重试（实测 1.2 亿次 entries）。
             * 处理：翻到 STEP（原页 AP=01），让这次 uaccess 成功；随后的
             * EL0 取指会撞上 STEP 的 UXN，再翻回 SHADOW。 */
            if (ec == 0x25) {
                u64 cur = 0;
                int have = caoin_cur_pte(h, &cur);
                int wn = (esr & 0x40) != 0;
                u64 ap = have ? (cur & PTE_AP_MASK)
                              : (h->orig_pte & PTE_AP_MASK);

                if (ap == 0x80UL)   /* 正常 SHADOW：用缓存的 VMA 权限 */
                    ap = h->orig_pte & PTE_AP_MASK;
                /* PROT_NONE 或只读页上的 EL1 写：交给原生 fixup
                 * （EFAULT/COW），不能翻成 STEP 把权限绕过。 */
                if (have && (ap == 0 || (wn && ap == 0xC0UL))) {
                    ret = 0;
                    goto mh_out;
                }
                caoin_set_view(i, VIEW_STEP);
                caoin_tlb_flush(h->tva);
                if (hit_out) *hit_out = i;
                ret = 1;
                goto mh_out;
            }
            if (ec != 0x24) {
                /* 视图说 SHADOW（可执行）却收到**取指 permission fault** → TLB 陈旧：
                 * 并发重填竞态让本核 TLB 里留着另一套翻译（指向原页），而原页既可读
                 * 又可取指 → 永不 fault → 陈旧项永不自愈。
                 * 原来这里 return 0 放行给原生路径，但原生路径不会 flush TLB（PTE
                 * 本来就是"对的"）→ 同一份陈旧翻译反复 fault → 活锁。
                 * 实测（tests/selfread.c mode=6，4 线程）：overlap 98.5%、
                 * desync_a 98.4%、目标 state=R 空转、selfread_ok=0。
                 * 改成 flush + eret 重试 —— 与下面 STEP+data 那条对称。
                 * 只处理 permission fault（0b0011xx）：translation fault 说明 PTE
                 * 真的无效，flush 救不了，仍然放行。 */
                if (ec == 0x20 && (esr & 0x3C) == 0x0C) {
                    u64 cur = 0;
                    if (caoin_cur_pte(h, &cur) && (cur & PTE_UXN)) {
                        /* mprotect 去掉了执行权限（PROT_NONE/RO）：
                         * 交给原生 SIGSEGV，不能当 TLB 陈旧重试。 */
                        ret = 0;
                        goto mh_out;
                    }
                    g_desync_a++;
                    caoin_tlb_flush(h->tva);
                    if (hit_out) *hit_out = i;
                    ret = 1;
                    goto mh_out;
                }
                ret = 0;
                goto mh_out;
            }
            {
                u64 cur = 0;
                int have = caoin_cur_pte(h, &cur);
                int wn = (esr & 0x40) != 0;
                u64 ap = have ? (cur & PTE_AP_MASK)
                              : (h->orig_pte & PTE_AP_MASK);

                if (ap == 0x80UL)   /* 正常 SHADOW：用缓存的 VMA 权限 */
                    ap = h->orig_pte & PTE_AP_MASK;
                /* PROT_NONE：交给原生 SIGSEGV，不要翻 STEP 绕过。 */
                if (have && ap == 0) {
                    ret = 0;
                    goto mh_out;
                }
                /* DC/IC 维护指令：代做 + 跳过，保持当前视图（不改 PTE）。 */
                if (wn && caoin_emulate_cacheop(h, regs)) {
                    if (hit_out) *hit_out = i;
                    ret = 1;
                    goto mh_out;
                }
                /* 只读页上的普通写：交给原生 SIGSEGV。 */
                if (have && wn && ap == 0xC0UL) {
                    ret = 0;
                    goto mh_out;
                }
            }
            if (regs && (regs->pc >> 12) == (h->tva >> 12)) {
                if (caoin_emulate_selfread(h, regs, addr)) {
                    selfread_ok_cnt++;
                    if (hit_out) *hit_out = i;
                    ret = 1;   /* 已代读 + pc+=4，视图保持 SHADOW */
                    goto mh_out;
                }
                selfread_fb_cnt++;   /* 未识别形态：回退翻转（可能活锁） */
            }
            caoin_set_view(i, VIEW_STEP);
            caoin_tlb_flush(h->tva);
            if (hit_out) *hit_out = i;
            ret = 1;   /* eret 重试 → orig 页成功 */
            goto mh_out;
        }

        /* STEP 视图：取指 fault（UXN）→ 切 SHADOW 恢复桩执行；
         * 数据 fault（TLB 陈旧命中 SHADOW 翻译）→ 重刷 TLBI 后 eret 重试 */
        if (h->cur_view == VIEW_STEP) {
            /* 外部 zap 把 STEP 的原页 PTE 清掉了 → translation fault。
             * 注意：STEP 的 PTE 是普通原页（非 SPECIAL），zap 已经正常
             * 做过 page_remove_rmap/RSS，所以这里**不能**再补记账；
             * 交给原生 fault 按原页重新映射即可。 */
            if ((ec == 0x24 || ec == 0x20)
                && (esr & 0x3F) >= 0x4 && (esr & 0x3F) <= 0x7) {
                __atomic_store_n(&h->cur_view, VIEW_OFF, __ATOMIC_RELEASE);
                ret = 0;
                goto mh_out;
            }
            if (ec == 0x24) {
                u64 cur = 0;
                int have = caoin_cur_pte(h, &cur);
                int wn = (esr & 0x40) != 0;
                u64 ap = have ? (cur & PTE_AP_MASK)
                              : (h->origview_pte_val & PTE_AP_MASK);

                if (have && ap == 0) {
                    ret = 0;   /* PROT_NONE：native SIGSEGV */
                    goto mh_out;
                }
                if (wn && caoin_emulate_cacheop(h, regs)) {
                    if (hit_out) *hit_out = i;
                    ret = 1;   /* cache 维护已代做，跳过指令 */
                    goto mh_out;
                }
                if (have && wn && ap == 0xC0UL) {
                    ret = 0;   /* 只读页写：native SIGSEGV */
                    goto mh_out;
                }
                g_desync_b++;   /* 可读页的数据 fault：脱同步/TLB 陈旧 */
                caoin_tlb_flush(h->tva);
                if (hit_out) *hit_out = i;
                ret = 1;
                goto mh_out;
            }
            if (ec != 0x20) {
                ret = 0;
                goto mh_out;
            }
            {
                u64 cur = 0;
                if (caoin_cur_pte(h, &cur) && (cur & PTE_AP_MASK) == 0) {
                    ret = 0;   /* PROT_NONE：native SIGSEGV */
                    goto mh_out;
                }
            }
            caoin_set_view(i, VIEW_SHADOW);
            caoin_tlb_flush(h->tva);
            if (hit_out) *hit_out = i;
            ret = 1;   /* eret 重取指 → 替换桩 */
            goto mh_out;
        }

        ret = 0;
mh_out:
        if (locked)
            caoin_mm_unlock();
        __atomic_sub_fetch(&g_in_mh, 1, __ATOMIC_RELAXED);
        return ret;
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
    if (!(e0 & 2))          /* 1GB block：本 walk 只处理 4K PTE */
        return 0;
    if (kfn_probe_read(&e2, (void *)caoin_va((e0 & m) + ((va >> 21) & 0x1FF) * 8), 8))
        return 0;
    if (!(e2 & m))
        return 0;
    if (!(e2 & 2))          /* 2MB block：同上 */
        return 0;
    pte_a = caoin_va((e2 & m) + ((va >> 12) & 0x1FF) * 8);
    if (kfn_probe_read(&pte_v, (void *)pte_a, 8))
        return 0;
    if (!(pte_v & 2))       /* level-3 必须是 page descriptor */
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
            /* va2 是"第二个数据点"，用来交叉确认 mm/pgd 偏移。内核分配 status 页
             * 时没有用户 VA 可 walk（va2=0），跳过这层校验——主证据仍是 va 那次
             * walk（它本身就要求 tva 能经候选 mm/pgd 走到 PTE）。 */
            if (caoin_probe_walk(mm_c, poff, va, expect_phys, pte_a_out)
                && (!va2 || caoin_probe_walk(mm_c, poff, va2, expect2, 0))) {
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

    /* 内核分配的 status 页：没有用户 VA 可 walk，直接走线性地址。
     * cfg_e2 在 init 里早于本函数第一次调用就已定好（见 init 的 kstatus 分支）。 */
    if (!va) {
        u64 *kslot;
        if (!cfg_e2)
            return;
        kslot = (u64 *)caoin_va(cfg_e2 & CAOIN_PFN_MASK);
        if (kfn_probe_read(&before, (void *)kslot, 8))
            { CK_ERR("caoin-kpm: wstat kslot unreadable %p\n", kslot); return; }
        if (!kfn_probe_write || kfn_probe_write(kslot, &val, 8) != 0)
            { CK_ERR("caoin-kpm: wstat kslot write fail %p\n", kslot); return; }
        asm volatile("dc civac, %0" :: "r"(kslot) : "memory");
        kfn_probe_read(&after, (void *)kslot, 8);
        CK_LOG("caoin-kpm: wstat kslot=%llx %llx->%llx (want %llx)\n",
               (unsigned long long)(unsigned long)kslot,
               (unsigned long long)before, (unsigned long long)after,
               (unsigned long long)val);
        asm volatile("dsb ish" ::: "memory");
        return;
    }

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
        else if (!strncmp(p, "quiet=", 6)) g_quiet = parse_hex(p + 6);
        else if (!strncmp(p, "polymorph=", 10)) g_polymorph = parse_hex(p + 10);
        else if (!strncmp(p, "stub=", 5)) g_stub_onload = parse_hex(p + 5);
        else if (!strncmp(p, "stubmode=", 9)) stub_mode = (int)parse_hex(p + 9);
        else if (!strncmp(p, "rearm=", 6)) g_rearm_on = parse_hex(p + 6);
        else if (!strncmp(p, "capmax=", 7)) cfg_capmax = parse_hex(p + 7);
        else if (!strncmp(p, "capptr=", 7)) cfg_cap_ptr = (int)parse_hex(p + 7);
        else if (!strncmp(p, "caplen=", 7)) cfg_cap_len = (int)parse_hex(p + 7);
        else if (!strncmp(p, "capoff=", 7)) cfg_cap_off = parse_hex(p + 7);
        else if (!strncmp(p, "capmin=", 7)) cfg_cap_min = parse_hex(p + 7);
        else if (!strncmp(p, "captext=", 8)) cfg_cap_text = (int)parse_hex(p + 8);
        else if (!strncmp(p, "el0flip=", 8)) g_force_el0flip = parse_hex(p + 8);
        else if (!strncmp(p, "acct=", 5)) g_acct_on = parse_hex(p + 5);
        else if (!strncmp(p, "rss=", 4)) g_rss_off = (unsigned long)parse_hex(p + 4);
        else if (!strncmp(p, "msem=", 5)) g_mmap_sem_off = (unsigned long)parse_hex(p + 5);
        else if (!strncmp(p, "capfind=", 8)) {
            /* hex 解码后按 ',' 切分成多个关键字，例如
             * Damage,Hurt,LoseLife = 44616d6167652c487572742c4c6f73654c696665 */
            unsigned char tmp[80];
            int tn = 0, i2, s = 0;
            const char *q = p + 8;
            while (tn < (int)sizeof(tmp) && q[0] && q[1]) {
                unsigned int v = 0;
                char hi = q[0], lo = q[1];
                if (hi >= '0' && hi <= '9') v = (unsigned int)(hi - '0') << 4;
                else if (hi >= 'a' && hi <= 'f') v = (unsigned int)(hi - 'a' + 10) << 4;
                else if (hi >= 'A' && hi <= 'F') v = (unsigned int)(hi - 'A' + 10) << 4;
                else break;
                if (lo >= '0' && lo <= '9') v |= lo - '0';
                else if (lo >= 'a' && lo <= 'f') v |= lo - 'a' + 10;
                else if (lo >= 'A' && lo <= 'F') v |= lo - 'A' + 10;
                else break;
                tmp[tn++] = (unsigned char)v;
                q += 2;
            }
            capkw_n = 0;
            for (i2 = 0; i2 <= tn && capkw_n < CAOIN_CAPKW_MAX; i2++) {
                if (i2 == tn || tmp[i2] == ',') {
                    int len = i2 - s;
                    if (len > CAOIN_CAPKW_LEN - 1)
                        len = CAOIN_CAPKW_LEN - 1;
                    if (len > 0) {
                        memcpy(capkw[capkw_n], tmp + s, (unsigned long)len);
                        capkw_len[capkw_n] = len;
                        capkw_n++;
                    }
                    s = i2 + 1;
                }
            }
        }
        else if (!strncmp(p, "arg", 3) && p[3] >= '0' && p[3] <= '9') {
            /* argN=，N 支持 1~2 位（arg0..arg30） */
            const char *q = p + 4;
            int ai = p[3] - '0';
            if (*q >= '0' && *q <= '9') {
                ai = ai * 10 + (*q - '0');
                q++;
            }
            if (*q == '=' && ai < CAOIN_MAX_ARGS) {
                g_args[ai] = parse_hex(q + 1);
                g_has_arg[ai] = 1;
            }
        }
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
    /* 先断流再恢复：vbar_on=0 之后新的 fault 不会再翻转 PTE；
     * 若先恢复后断流，并发 fault 可能把 PTE 又翻回 SHADOW，
     * zap 时就会看到 shadow 页（真机 Bad page state）。 */
    vbar_on = 0;
    __atomic_store_n(&g_fork_pause, 0, __ATOMIC_RELEASE);
    for (i = 0; i < hooks_n; i++) {
        /* 经 set_view 恢复：会把原页的 rmap/RSS 记账补回来 */
        caoin_set_view(i, VIEW_OFF);
        if (hooks[i].el0_pte_addr && hooks[i].el0_pte_addr != hooks[i].pte_addr)
            caoin_set_pte((u64 *)hooks[i].el0_pte_addr, hooks[i].orig_pte);
    }
    caoin_tlb_flush(0);
    CK_LOG("caoin-kpm: exit_mmap: %d hook PTEs restored for dying mm=%lx\n",
           hooks_n, (unsigned long)mm);

    /* 目标 mm 马上销毁。必须彻底断开：否则 mm 结构被释放后地址可能被
     * 新进程复用，caoin_is_target_proc() 会把新进程误判成目标，
     * 再经缓存的 pte_addr 写别的进程页表（实测 Bad page map）。 */
    vbar_on = 0;
    mm_run = 0;
    mm_run_pgd = 0;
}

/* ---- copy_process fork 防护（wxshadow 同款）----
 * fork 时 copy_process 快照父进程页表：受管页 PTE 若停在 SHADOW/STEP，
 * 子进程会继承 shadow 页 PFN，内核按 shadow 页记账子进程 RSS/rmap →
 * 后续 teardown 触发 "Bad rss-counter / Bad page map"。
 * 防护 = fork 前把受管页 PTE 恢复原值（pause），copy_process 返回后翻回
 * 原视图（resume）。只处理非 CLONE_VM（线程共享 mm，无页表快照）。
 * 状态经 args->local.data[0]（paused 标志）和 data[1..]（各 hook 视图）
 * 在 before/after 间传递（KP 保证同一次调用共享），并发 fork 不互相覆盖。
 * 与 caoin_fault_check 的并发：g_fork_pause > 0 期间 fault handler 不翻 PTE；
 * before 先置位并等 g_in_mh 归零，再恢复原 PTE。 */
static void before_copy_process(hook_fargs8_t *args, void *udata)
{
    unsigned long clone_flags = (unsigned long)args->arg0;
    int i, spin;

    (void)udata;
    args->local.data[0] = 0;
    if (!vbar_on)
        return;
    if (clone_flags & CLONE_VM)      /* 线程：共享 mm，无页表快照 */
        return;
    if (!caoin_is_target_proc())     /* 只处理目标进程的 fork */
        return;
    args->local.data[0] = 1;
    /* 先置 pause：新 fault 在 handler 里看到它就不再翻 PTE。 */
    __atomic_add_fetch(&g_fork_pause, 1, __ATOMIC_ACQ_REL);
    /* 等已经在 handler 里的线程退出（它们可能在 pause 之后把 PTE 翻回去）。
     * 有界自旋：handler 卡死时宁可保留小窗口，也不让 fork 挂住。 */
    for (spin = 0;
         spin < 100000 && __atomic_load_n(&g_in_mh, __ATOMIC_ACQUIRE) != 0;
         spin++)
        asm volatile("yield" ::: "memory");
    for (i = 0; i < hooks_n; i++) {
        /* 视图存 per-invocation（local.data[1..]），并发 fork 不互相覆盖 */
        args->local.data[1 + i] = hooks[i].cur_view;
        caoin_set_view_locked(i, VIEW_OFF);
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
        u64 view = args->local.data[1 + i];

        caoin_set_view_locked(i, view);
        if (!g_no_kpti || g_force_el0flip)
            caoin_flip_el0(i, view, 1);
    }
    caoin_tlb_flush(0);
    __atomic_sub_fetch(&g_fork_pause, 1, __ATOMIC_ACQ_REL);
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
    int i, alive = 0;
    if (!vbar_on && !g_hooks_installed)
        return 0;
    /* 先断流：vbar_on=0 后 hook 入口对一切 fault 纯放行，
     * 之后 unwrap/恢复动作不再有并发 hook 竞态 */
    vbar_on = 0;
    __atomic_store_n(&g_fork_pause, 0, __ATOMIC_RELEASE);
    /* 目标存活校验：目标已死则页表随 mm 释放，写悬挂 pte_addr = 随机
     * 内存写（页表页可能已复用）。死亡时 exit_mmap 钩子已恢复过 PTE，
     * 此处跳过即是正确语义。 */
    if (kfn_find_task_by_vpid) {
        void *task = kfn_find_task_by_vpid((int)cfg_pid);
        unsigned long cmm = 0;
        if (task && !kfn_probe_read(&cmm, (void *)(task + mm_off), 8)
            && cmm == mm_run) {
            int lk = caoin_mm_lock();

            alive = 1;
            for (i = 0; i < hooks_n; i++) {
                caoin_set_view(i, VIEW_OFF);
                if (hooks[i].el0_pte_addr && hooks[i].el0_pte_addr != hooks[i].pte_addr)
                    caoin_set_pte((u64 *)hooks[i].el0_pte_addr, hooks[i].orig_pte);
            }
            /* 恢复 status 页原 PTE（handler/trampoline 曾把它改成 RWX）。
             * 目标已死时页表已释放，不能碰。 */
            if (sva_pte_addr) {
                caoin_set_pte((u64 *)sva_pte_addr, sva_orig_pte);
                sva_pte_addr = 0;
            }
            if (lk)
                caoin_mm_unlock();
        } else {
            CK_LOG("caoin-kpm: target gone, PTE left to dying mm\n");
        }
    }
    caoin_tlb_flush(0);
    /* 内核钩子必须无条件摘除——即使 vbar_on 已被 exit_mmap 清零，
     * 否则 KP 链里残留指向本模块的项，下次加载 hook_wrap 会失败
     * （实测 err=-4094）。 */
    if (g_hooks_installed) {
        dpf = (void *)(unsigned long)kallsyms_lookup_name("do_page_fault");
        if (dpf)
            caoin_unhook(dpf, before_page_fault, NULL);
        em = (void *)(unsigned long)kallsyms_lookup_name("exit_mmap");
        if (em)
            caoin_unhook(em, exit_mmap_before, NULL);
        if (g_copy_process)
            caoin_unhook(g_copy_process, before_copy_process, after_copy_process);
        g_hooks_installed = 0;
    }
    if (alive)
        caoin_write_status(cfg_sva, 0xF);

    /* 内核分配的页只能在"确认没有目标 PTE 再指向它"之后释放。
     * 判据：所有 hook 的 cur_view 都回到 VIEW_OFF —— 要么本函数刚恢复过，
     * 要么 exit_mmap 钩子在目标死亡时恢复过，要么从未 arm。
     * 任何一条不满足（例如目标还活着但恢复被跳过）就宁可泄漏这两页，
     * 也不能把目标 PTE 指向的页还给分配器（UAF → 随机内核写）。 */
    {
        int safe = 1;
        for (i = 0; i < hooks_n; i++)
            if (hooks[i].cur_view != VIEW_OFF)
                safe = 0;
        if (!safe) {
            CK_ERR("caoin-kpm: PTE state not OFF -> kernel pages leaked (avoid UAF)\n");
        } else if (kfn_free_pages) {
            int nf = 0;
            for (i = 0; i < hooks_n; i++)
                if (hooks[i].kshadow) {
                    kfn_free_pages(hooks[i].kshadow, 0);
                    hooks[i].kshadow = 0;
                    nf++;
                }
            if (kstatus) {
                kfn_free_pages(kstatus, 0);
                kstatus = 0;
                nf++;
            }
            if (kcap) {
                kfn_free_pages(kcap, cap_order);
                kcap = 0;
                nf++;
            }
            /* 打出实际条数：旧路径（用户态 mmap）这里是 0，不是"释放了" */
            CK_ERR("caoin-kpm: kernel pages freed = %d\n", nf);
        }
    }
    /* 并发插桩收尾：卸载时无条件打一次（不依赖 ctl0）。
     * overlap > 0 且 desync_a/b == 0 → 并发进入确实发生过、且没脱同步。 */
    CK_ERR("caoin-kpm: conc entries=%llu overlap=%llu desync_a=%llu desync_b=%llu "
           "rearm_on=%llu rearm_cnt=%llu selfread_ok=%llu fb=%llu\n",
           (unsigned long long)g_entries, (unsigned long long)g_overlap,
           (unsigned long long)g_desync_a, (unsigned long long)g_desync_b,
           (unsigned long long)g_rearm_on, (unsigned long long)g_rearm_cnt,
           (unsigned long long)selfread_ok_cnt,
           (unsigned long long)selfread_fb_cnt);
    CK_LOG("caoin-kpm: off, restored (%d hooks)\n", hooks_n);
    return 0;
}

/* ---- 内核侧桩安装（按 hook）----
 * 在目标线程上下文（current 已验证）经页表 walk 取 tva/shva 物理帧 →
 * 内核线性地址直写桩（movz w0,#ret_val; ret）→ dc cvau/ic ivau
 * （线性地址；I-cache PIPT，同物理帧等效）。
 * 注意：绝不能对用户 VA 直接做 dc cvau/ic ivau——SW_TTBR0_PAN 机器上
 * EL1 的 TTBR0 为空表，这些指令直接 translation fault（真机实证）。 */
/* polymorph：status 页上的标记值也 XOR 一下，避免固定 magic 成为签名。 */
static u64 caoin_magic(u64 base)
{
    return g_polymorph ? (base ^ (g_stub_seed & 0xFFFFFFFFULL)) : base;
}

static void caoin_install_stub(int hi)
{
    struct caoin_hook *h = &hooks[hi];
    unsigned long kva;
    volatile u32 *stub;
    u32 enc;

    /* caoin_shadow_kva 同时覆盖"用户态 mmap 的影子页"和"内核分配的影子页" */
    kva = caoin_shadow_kva(h);
    if (kva) {
        kva += h->shva_off;
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
        status_mark(caoin_magic(0xCA0FCA03ULL));
        CK_ERR("caoin-kpm: hook%d stub installed %s=%lx off=%lx val=%d\n",
               hi, h->kshadow ? "kshadow" : "shva",
               h->kshadow ? h->kshadow : h->shva, h->shva_off,
               (int)(h->ret_val & 0xFFFF));
    } else {
        CK_ERR("caoin-kpm: hook%d shadow kva unresolvable\n", hi);
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
    u64 magic = caoin_magic(0xCA0FCA51ULL);

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
    unsigned long skva, okva, orig_pfn, off, page_va, n;
    unsigned long stkva = 0, hva_k, hva_u, trm_k, trm_u;
    u32 orig[4];
    int st[4], i;
    int sreg = g_polymorph ? (16 + (int)((g_stub_seed >> 8) & 1)) : 16;

    skva = caoin_shadow_kva(h);
    if (!skva) {
        CK_ERR("caoin-kpm: hook%d recstub: shadow kva unresolvable\n", hi);
        return;
    }
    orig_pfn = h->orig_pte & CAOIN_PFN_MASK;
    if (!orig_pfn) {
        CK_ERR("caoin-kpm: hook%d recstub: orig pfn unknown\n", hi);
        return;
    }
    okva = caoin_va(orig_pfn);
    off = h->shva_off;
    /* 影子页占的是**受管页的 VA**（PTE 只换 PFN）→ 所有 VA 编码量一律用受管页基准。
     * 这同时解决了内核分配影子页时"目标怎么读报告区"的问题：目标照常读
     * 受管页 VA + 0xF00 就行，不需要任何额外映射。
     * 注意 caoin 的命名：CAOIN_PAGE_MASK 就是 ~0xFFF（"保留页基址"），
     * 所以取基址是 & CAOIN_PAGE_MASK，取偏移才是 & ~CAOIN_PAGE_MASK。 */
    page_va = h->tva & CAOIN_PAGE_MASK;

    /* handler/trampoline 优先放 status 页：受管页可能被其他函数填满，
     * 固定 0x800/0xA00 会覆盖它们（Lua API 页实测登录即崩）。
     * status 页必须是用户 mmap 的（caoin_prep 提供 sva）。 */
    if (cfg_sva) {
        unsigned long spte_a = 0, spte_v = 0;
        int lk = caoin_mm_lock();

        if (caoin_walk_pgd_via_mm(cfg_sva, &spte_a)
            && !kfn_probe_read(&spte_v, (void *)spte_a, 8)
            && (spte_v & CAOIN_PFN_MASK)) {
            stkva = caoin_va(spte_v & CAOIN_PFN_MASK);
            sva_pte_addr = spte_a;
            sva_orig_pte = spte_v;
            /* EL0 RWX：AP=01 + UXN=0（status 写与取指都要允许） */
            caoin_set_pte((u64 *)spte_a,
                          (spte_v & ~(PTE_AP_MASK | PTE_UXN)) | 0x40UL);
            caoin_tlb_flush(cfg_sva);
        }
        if (lk)
            caoin_mm_unlock();
    }
    hva_k = stkva ? stkva + CAOIN_OFF_HANDLER : skva + CAOIN_OFF_HANDLER;
    hva_u = stkva ? cfg_sva + CAOIN_OFF_HANDLER : page_va + CAOIN_OFF_HANDLER;
    trm_k = stkva ? stkva + CAOIN_OFF_TRAMP : skva + CAOIN_OFF_TRAMP;
    trm_u = stkva ? cfg_sva + CAOIN_OFF_TRAMP : page_va + CAOIN_OFF_TRAMP;

    /* 读被覆盖的 4 条原指令：从原页线性地址读，绝不碰用户 VA */
    for (i = 0; i < 4; i++) {
        u32 w = 0;
        if (kfn_probe_read(&w, (void *)(okva + off + (unsigned long)i * 4), 4)) {
            CK_ERR("caoin-kpm: hook%d recstub: read prologue fail off=%lx\n",
                   hi, off + (unsigned long)i * 4);
            return;
        }
        orig[i] = w;
    }

    /* 1) 先重定位被覆盖的 4 条原指令。
     * 必须排在"写入口桩"之前：重定位失败时影子页还是原页的忠实副本，
     * 什么都没装 → 安全。反过来（先写桩再重定位）会在失败时留下半装的桩，
     * handler 里的 `b trampoline` 跳进没写过的区域 → 目标 SIGSEGV（实测）。 */
    g_rd_va_base = page_va;
    g_rd_kva_base = skva;
    n = caoin_reloc_block((u32 *)trm_k, trm_u, orig, h->tva, st);
    g_rd_va_base = 0;
    g_rd_kva_base = 0;
    if (!n) {
        CK_ERR("caoin-kpm: hook%d recstub: reloc fail st=%d,%d,%d,%d "
               "orig=%08x,%08x,%08x,%08x tva=%lx page=%lx tramp=%lx\n",
               hi, st[0], st[1], st[2], st[3],
               orig[0], orig[1], orig[2], orig[3],
               h->tva, page_va, page_va + CAOIN_OFF_TRAMP);
        return;
    }

    /* 2) 先把 handler 构建到局部缓冲（含空间守卫），**通过之后才写入口桩**。
     * 顺序很重要：入口桩先落盘而 handler 溢出的话，桩会跳进半写的 handler → 崩。 */
    {
        u32 hbuf[CAOIN_HANDLER_INSN_MAX];
        unsigned long tramp = trm_u;
        unsigned long hva   = hva_u;
        long d;
        int nh = 0, ai, nargs = 0, k;

        /* capture 模式：先按原寄存器触发哨兵 fault，让 KPM 在 EL1 拷数据，
         * 再执行 arg 覆盖和原逻辑。fault 处理会跳过本 ldr 继续往下走。 */
        if (stub_mode == 3 && cfg_capmax) {
            if (nh + 6 + 1 > CAOIN_HANDLER_INSN_MAX) {
                CK_ERR("caoin-kpm: hook%d capture: handler overflow\n", hi);
                return;
            }
            nh += caoin_emit_movx(&hbuf[nh], 9, cfg_sent);
            hbuf[nh++] = 0xF940013Fu;   /* ldr xzr, [x9] */
        }

        for (ai = 0; ai < CAOIN_MAX_ARGS; ai++)
            if (g_has_arg[ai]) {
                if (nh + 4 + 1 > CAOIN_HANDLER_INSN_MAX) {
                    CK_ERR("caoin-kpm: hook%d recstub: handler overflow "
                           "(args too many/large) -> abort, nothing installed\n",
                           hi);
                    return;     /* 什么都没写，影子页仍是原页忠实副本 ✓ */
                }
                nh += caoin_emit_movx(&hbuf[nh], ai, g_args[ai]);
                nargs++;
            }
        d = (long)((tramp - (hva + (unsigned long)nh * 4)) >> 2);
        hbuf[nh++] = 0x14000000u | ((u32)d & 0x03FFFFFFu);   /* b trampoline */

        /* 3) 入口桩（3 条，adrp+add+br，不读内存）+ handler 落盘 */
        if (stkva) {
            if (caoin_make_entry_stub_far((u32 *)(skva + off),
                                          page_va + off, hva_u, sreg)) {
                CK_ERR("caoin-kpm: hook%d recstub: entry stub out of range\n", hi);
                return;
            }
        } else {
            caoin_make_entry_stub((u32 *)(skva + off), CAOIN_OFF_HANDLER, sreg);
        }
        for (k = 0; k < nh; k++)
            *(volatile u32 *)(hva_k + (unsigned long)k * 4) = hbuf[k];
        g_nargs_installed = nargs;
    }

    /* 4) cache 维护（线性地址，I-cache PIPT 等效） */
    {
        unsigned long o2;
        if (stkva) {
            for (o2 = 0; o2 < 0x1000; o2 += 64) {
                asm volatile("dc cvau, %0" :: "r"(stkva + o2));
                asm volatile("ic ivau, %0" :: "r"(stkva + o2));
            }
        }
        for (o2 = 0; o2 < 0x1000; o2 += 64) {
            asm volatile("dc cvau, %0" :: "r"(skva + o2));
            asm volatile("ic ivau, %0" :: "r"(skva + o2));
        }
        asm volatile("dsb ish" ::: "memory");
        asm volatile("isb" ::: "memory");
    }
    status_mark(caoin_magic(0xCA0FCA03ULL));
    CK_ERR("caoin-kpm: hook%d recstub installed page=%lx off=%lx handler=%lx "
           "tramp=%lx(%lu insns) args=%d hnd=%s\n",
           hi, page_va, off, hva_u, trm_u, n, g_nargs_installed,
           stkva ? "status" : "shadow");
}

/* status 打标（经 status 页物理帧线性地址；帧 PFN=cfg_e2，init 自推导） */
static void status_mark(u64 v)
{
    u64 *statusp;
    u64 old;

    /* cfg_e2=0（status 页推导失败）或目标已 munmap status 页（PFN 被复用）
     * 时，直接写 + dc civac 是随机内核写/panic。先确认可读再写。 */
    if (!cfg_e2 || !kfn_probe_read)
        return;
    statusp = (u64 *)(caoin_va(cfg_e2 & CAOIN_PFN_MASK)
                      + ((unsigned long)cfg_sva & 0xFFUL));
    if (kfn_probe_read(&old, (void *)statusp, 8))
        return;
    if (kfn_probe_write) {
        if (kfn_probe_write(statusp, &v, 8) != 0)
            return;
    } else {
        statusp[0] = v;
    }
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
    CK_ERR("caoin-kpm: capkw_n=%d kw0_len=%d kw0=%02x%02x%02x%02x "
           "capmin=%llx captext=%d\n",
           capkw_n, capkw_n ? capkw_len[0] : 0,
           capkw[0][0], capkw[0][1], capkw[0][2], capkw[0][3],
           (unsigned long long)cfg_cap_min, cfg_cap_text);
    /* hook 数量统计（tva 非零即有效）。shva 可省 → 内核分配影子页；
     * sva 可省 → 内核分配 status 页。两者都省 = 目标 maps 零新增 VMA。 */
    hooks_n = 0;
    for (i = 0; i < CAOIN_MAX_HOOKS; i++)
        if (hooks[i].tva)
            hooks_n = i + 1;
    if (!cfg_pid || !hooks_n) {
        CK_ERR("caoin-kpm: missing args (need pid + tvaN; sva/shva optional)\n");
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
    kfn_get_free_pages = (void *)kallsyms_lookup_name("__get_free_pages");
    kfn_free_pages = (void *)kallsyms_lookup_name("free_pages");
    kfn_copy_to_user = (void *)kallsyms_lookup_name("__arch_copy_to_user");
    kfn_page_remove_rmap = (void *)kallsyms_lookup_name("page_remove_rmap");
    kfn_page_add_file_rmap = (void *)kallsyms_lookup_name("page_add_file_rmap");
    kfn___put_page = (void *)kallsyms_lookup_name("__put_page");
    kfn_down_read = (void *)kallsyms_lookup_name("down_read");
    kfn_up_read = (void *)kallsyms_lookup_name("up_read");
    if (!kvar_memstart_addr || !kfn_probe_read || !kfn_find_task_by_vpid) {
        CK_ERR("caoin-kpm: symbol resolve failed (memstart=%lx probe=%lx find=%lx)\n",
               (unsigned long)kvar_memstart_addr,
               (unsigned long)kfn_probe_read,
               (unsigned long)kfn_find_task_by_vpid);
        return -1;
    }
    if (!kfn_page_remove_rmap || !kfn_page_add_file_rmap || !kfn___put_page) {
        /* 没有 rmap 符号时记账无法做；关掉记账，只保留 PTE_SPECIAL。
         * PTE_SPECIAL 已能阻止 shadow 页被 zap 释放（主崩溃点）。 */
        g_acct_on = 0;
        CK_ERR("caoin-kpm: rmap symbols missing (remove=%lx add=%lx), acct off\n",
               (unsigned long)kfn_page_remove_rmap,
               (unsigned long)kfn_page_add_file_rmap);
    }
    CK_LOG("caoin-kpm: memstart=%llx hooks=%d args ok\n",
           (unsigned long long)(s64)*kvar_memstart_addr, hooks_n);

    /* capture 模式：内核分配 capture 页（无 VMA），前 8 字节存长度 */
    if (cfg_capmax) {
        u64 sz = 0x1000;
        if (cfg_cap_ptr < 0 || cfg_cap_ptr > 30
            || cfg_cap_len < 0 || cfg_cap_len > 30) {
            CK_ERR("caoin-kpm: capture: capptr/caplen invalid\n");
            return -1;
        }
        if (!cfg_sent) {
            CK_ERR("caoin-kpm: capture: sent= required\n");
            return -1;
        }
        if (!kfn_get_free_pages) {
            CK_ERR("caoin-kpm: capture: __get_free_pages unavailable\n");
            return -1;
        }
        cap_order = 0;
        while (sz < cfg_capmax + 8 && cap_order < 8) {
            sz <<= 1;
            cap_order++;
        }
        kcap = kfn_get_free_pages(CAOIN_GFP_KERNEL, cap_order);
        if (!kcap) {
            CK_ERR("caoin-kpm: capture: kcap alloc failed\n");
            return -1;
        }
        *(volatile u64 *)kcap = 0;
        CK_ERR("caoin-kpm: kcap=%lx size=%llu order=%d capptr=x%d caplen=x%d\n",
               (unsigned long)kcap, (unsigned long long)sz, cap_order,
               cfg_cap_ptr, cfg_cap_len);
    }

    /* status 页下沉：没有用户态 sva 就在内核分配。
     * 必须在第一次 caoin_write_status 之前把 cfg_e2 定好——否则 cfg_sva=0 时
     * caoin_write_status 会去 walk VA=0 的 PTE，那是完全错误的目标地址。 */
    if (!cfg_sva) {
        if (!kfn_get_free_pages) {
            CK_ERR("caoin-kpm: no sva provided and __get_free_pages unavailable\n");
            return -1;
        }
        kstatus = kfn_get_free_pages(CAOIN_GFP_KERNEL, 0);
        if (!kstatus) {
            CK_ERR("caoin-kpm: kstatus alloc failed\n");
            return -1;
        }
        cfg_e2 = caoin_pa(kstatus) & CAOIN_PFN_MASK;
        CK_ERR("caoin-kpm: kstatus=%lx pfn=%lx (kernel-allocated, no VMA)\n",
               (unsigned long)kstatus, (unsigned long)cfg_e2);
    }

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
    /* polymorph 种子：同一目标每次 load 稳定，不同目标/地址不同。 */
    g_stub_seed = hooks[0].tva ^ ((u64)cfg_pid << 32)
                ^ (u64)(unsigned long)task;
    if (!g_stub_seed)
        g_stub_seed = 0x9E3779B97F4A7C15ULL;
    caoin_write_status(cfg_sva, 0x5);
    CK_LOG("caoin-kpm: combo locked mm=%lx pgd=%lx pte=%lx\n",
           mm_off_out, pgd_off_out, pte_a);

    /* rss_stat 偏移自检：mm+0x2b0 是 __mmdrop 里 check_mm 反汇编得到的
     * MM_FILEPAGES 计数器。偏移错的话读出来是垃圾，直接关掉记账。 */
    if (g_acct_on) {
        long c0 = 0, c1 = 0, c2 = 0, c3 = 0;
        if (kfn_probe_read(&c0, (void *)(mmv + g_rss_off), 8)
            || kfn_probe_read(&c1, (void *)(mmv + g_rss_off + 8), 8)
            || kfn_probe_read(&c2, (void *)(mmv + g_rss_off + 16), 8)
            || kfn_probe_read(&c3, (void *)(mmv + g_rss_off + 24), 8)
            || c0 < 0 || c0 > (1L << 40) || c1 < 0 || c1 > (1L << 40)
            || c2 < 0 || c2 > (1L << 40) || c3 < 0 || c3 > (1L << 40)) {
            g_acct_on = 0;
            CK_ERR("caoin-kpm: rss_stat off=%lx sanity fail "
                   "(c=%ld,%ld,%ld,%ld), acct off\n",
                   g_rss_off, c0, c1, c2, c3);
        } else {
            CK_LOG("caoin-kpm: rss_stat off=%lx file=%ld anon=%ld "
                   "swap=%ld shmem=%ld\n", g_rss_off, c0, c1, c2, c3);
        }
    }

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

        /* 影子页 PFN：
         *  - 给了 shva：用户态 mmap 的影子页，walk 其 PTE 取 PFN（旧路径）
         *  - 没给 shva：内核分配一页 + 从原页拷 4K（新路径，maps 不留 VMA） */
        if (h->shva) {
            if (caoin_probe_walk(mmv, pgd_off_out, h->shva, 0, &spte)
                && !kfn_probe_read(&spv, (void *)spte, 8))
                h->shadow_pte_val = spv & CAOIN_PFN_MASK;   /* 暂存 PFN */
        } else if (caoin_alloc_shadow(h) == 0) {
            h->shadow_pte_val = caoin_pa(h->kshadow) & CAOIN_PFN_MASK;
        }
        if (!h->shadow_pte_val || !orig_v) {
            CK_ERR("caoin-kpm: hook%d derive fail\n", i);
            return -1;
        }
        /* shadow 视图：PFN→shadow，AP=10（EL0 数据 fault，取指走 X-only）。
         * PTE_SPECIAL(bit56)：让 __vm_normal_page 返回 NULL，zap/回收
         * 不会对内核 shadow 页做 rmap/put_page（否则 shadow 页被释放 → UAF）。 */
        h->shadow_pte_val = (orig_v & ~(CAOIN_PFN_MASK | PTE_AP_MASK | PTE_UXN))
                          | (h->shadow_pte_val & CAOIN_PFN_MASK) | 0x80UL
                          | CAOIN_PTE_SPECIAL;
        /* 原页 PFN（页号）：记账用 */
        h->orig_pfn = (orig_v & CAOIN_PFN_MASK) >> 12;
        /* original 视图：保留 VMA 的 AP（RO 页仍是 EL0 RO），只加 UXN=1。
         * dc civac 等 WnR=1 的 cache 维护指令由 fault handler 代做并跳过，
         * 不再靠把页改成 RW 来绕过。 */
        h->origview_pte_val = (orig_v & ~PTE_UXN) | PTE_UXN;
        if (g_polymorph)
            h->ret_val = 0x1000 + ((g_stub_seed >> (i * 8)) & 0x3FFF);
        else
            h->ret_val = 777 + i;   /* 测试桩：777/778…（区分 hook 点） */
        CK_LOG("caoin-kpm: hook%d tva=%lx shva=%lx kshadow=%lx pte=%lx ret=%d\n",
               i, h->tva, h->shva, h->kshadow, h->pte_addr,
               (int)(h->ret_val & 0xFFFF));
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
                                 | (hooks[0].shadow_pte_val & CAOIN_PFN_MASK) | 0x80UL
                                 | CAOIN_PTE_SPECIAL;
            hooks[0].origview2_val = (uppte & ~PTE_UXN) | PTE_UXN;
            /* 其余 hook：同一张副本表里走各自 tva */
            for (i = 1; i < hooks_n; i++) {
                unsigned long upte_a = 0, upte_v = 0;
                if (caoin_walk_pgd(caoin_va(upgd), hooks[i].tva, &upte_a)
                    && !kfn_probe_read(&upte_v, (void *)upte_a, 8)) {
                    hooks[i].pte_addr2 = upte_a;
                    hooks[i].orig_pte2 = upte_v;
                    hooks[i].shadow2_val = (upte_v & ~(CAOIN_PFN_MASK | PTE_AP_MASK | PTE_UXN))
                                         | (hooks[i].shadow_pte_val & CAOIN_PFN_MASK) | 0x80UL
                                         | CAOIN_PTE_SPECIAL;
                    hooks[i].origview2_val = (upte_v & ~PTE_UXN) | PTE_UXN;
                }
            }
            CK_LOG("caoin-kpm: user_pgd@%lx found (KPTI copy)\n", mmv + off);
            break;
        }
        if (!hooks[0].pte_addr2) {
            g_no_kpti = 1;
            CK_LOG("caoin-kpm: user_pgd NOT found (TTBR0==mm->pgd), "
                   "el0flip disabled (redundant + unsafe if page tables move)\n");
        }
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
    g_hooks_installed = 1;
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
        caoin_set_view_locked(i, VIEW_SHADOW);
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
        for (i = 0; i < hooks_n; i++) {
            /* 尊重 stub_mode：原来这里无条件装 777 桩，导致 stubmode=2（recstub）
             * 在 stub=1 路径下根本测不到。 */
            if (stub_mode == 0)
                caoin_install_stub(i);
            else if (stub_mode == 1)
                caoin_install_minstore(i);
            else
                caoin_install_recstub(i);
        }
        CK_LOG("caoin-kpm: stub=1 → %d stubs installed at load (mode=%d)\n",
               hooks_n, stub_mode);
    }
    /* engage 修复：桩装完后**再 flush 一次**。安装早期的 flush 之后、桩写入
     * 之前，目标仍在并发跑（多线程），本核/他核会重新走页表并把**旧**翻译填回
     * TLB —— 而旧翻译指向原页（可读可取指），永不 fault，于是陈旧项永不自愈、
     * seesaw 从不 engage（实测：mode=6 下 entries=0、hooked 仍是原值）。
     * 补这一次 flush 后 hook 立刻生效。同时重新 walk 一次读回内存里的 PTE，
     * 确认桩写入没把 PTE 碰掉。 */
    for (i = 0; i < hooks_n; i++) {
        unsigned long wa = 0, wv = 0;
        if (caoin_walk_pgd_via_mm(hooks[i].tva, &wa)
            && !kfn_probe_read(&wv, (void *)wa, 8))
            CK_ERR("caoin-kpm: engage hook%d tva=%lx pte=%lx view=%d\n",
                   i, hooks[i].tva, wv, (int)hooks[i].cur_view);
    }
    caoin_tlb_flush(0);

    CK_LOG("caoin-kpm: on (%d hooks, dpf hooked, seesaw armed)\n", hooks_n);
    return 0;
}

/* 运行时控制：args="restore" 手动恢复 */
static long caoin_ctl0(const char *args, char *__user out_msg, int outlen)
{
    int i;

    /* capture dump：dump <hex_off> <hex_len>，返回实际拷出的字节数 */
    if (args && !strncmp(args, "dump", 4)) {
        const char *p = args + 4;
        unsigned long off, len;
        u64 total;
        while (*p == ' ') p++;
        off = (unsigned long)parse_hex(p);
        while (*p && *p != ' ') p++;
        while (*p == ' ') p++;
        len = (unsigned long)parse_hex(p);
        if (!kcap)
            return -1;
        total = *(volatile u64 *)kcap;
        if (off >= total)
            return 0;
        if (!len || len > total - off)
            len = (unsigned long)(total - off);
        if (len > (unsigned long)outlen)
            len = (unsigned long)outlen;
        if (!kfn_copy_to_user)
            return -1;
        if (kfn_copy_to_user(out_msg, (void *)(kcap + 8 + off), len))
            return -1;
        return (long)len;
    }
    /* 通用目标内存读：read <hex_va> <hex_len>，走页表翻译（PAN 安全） */
    if (args && !strncmp(args, "read", 4)) {
        const char *p = args + 4;
        unsigned long va, len;
        static char rbuf[4096];
        while (*p == ' ') p++;
        va = (unsigned long)parse_hex(p);
        while (*p && *p != ' ') p++;
        while (*p == ' ') p++;
        len = (unsigned long)parse_hex(p);
        if (len > sizeof(rbuf))
            len = sizeof(rbuf);
        if (!len)
            return -1;
        if (!kfn_copy_to_user) {
            CK_ERR("caoin-kpm: read: copy_to_user unresolved\n");
            return -1;
        }
        if (caoin_read_user(rbuf, va, len)) {
            CK_ERR("caoin-kpm: read: user read fail va=%lx len=%lx\n",
                   (unsigned long)va, (unsigned long)len);
            return -1;
        }
        if (kfn_copy_to_user(out_msg, rbuf, len)) {
            CK_ERR("caoin-kpm: read: copy_to_user fail\n");
            return -1;
        }
        return (long)len;
    }
    if (args && !strncmp(args, "capinfo", 7)) {
        pr_info("caoin-kpm: capmax=%llu cap_len=%llu cap_cnt=%llu kcap=%lx\n",
                (unsigned long long)cfg_capmax,
                (unsigned long long)cap_len,
                (unsigned long long)cap_cnt, (unsigned long)kcap);
        return 0;
    }
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
    pr_info("caoin-kpm: sent=%llu el0tab=%lx selfread_ok=%llu selfread_fb=%llu\n",
            (unsigned long long)sent_cnt, el0_table_base,
            (unsigned long long)selfread_ok_cnt,
            (unsigned long long)selfread_fb_cnt);
    return 0;
}

static long caoin_exit(void *__user reserved)
{
    (void)reserved;
    return caoin_restore();
}

KPM_NAME("caoin-shadow");
KPM_VERSION("0.6.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("caoin");
KPM_DESCRIPTION("caoin traceless hook - multi-hook dpf shadow seesaw (muted logs)");

KPM_INIT(caoin_init);
KPM_CTL0(caoin_ctl0);
KPM_EXIT(caoin_exit);
