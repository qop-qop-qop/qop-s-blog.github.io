/*
 * bionic 动态测试目标（无 NDK）：周期调用 caoin_target 并打印。
 * 注入 caoin_agent 后输出应从 base 变为 base+100（行为级证据）。
 * shadow 模式（argv[1]=="shadow"）：准备 shadow 页（快照+桩）并打印
 * caoin 内核模块所需的全部 cfg 值，之后进入 status 轮询 + 周期输出。
 */
extern long write(int, const void *, unsigned long);
extern void *mmap(void *, unsigned long, int, int, int, long);
extern long lseek(int, long, int);
extern int mprotect(void *, unsigned long, int);
extern long open(const char *, int, ...);
extern long read(int, void *, unsigned long);
extern long close(int);

struct ts { long sec, nsec; };

/* caoin_target 独占 4K 页：主循环代码绝不能与它同页——
 * CRC 读指令若在 code 页内，SHADOW 可执行/STEP 可读互斥会导致死锁 */
__attribute__((noinline, visibility("default"), section(".target.text"), aligned(4096)))
int caoin_target(int x)
{
    volatile int r = x;
    r = r * 3;
    r = r ^ 0x2A;
    r = r + 7;
    r = r * 2;
    return r;
}

/* 第二 hook 目标：独立 4K 页（P3-v3 多 hook 验证） */
__attribute__((noinline, visibility("default"), section(".target2.text"), aligned(4096)))
int caoin_target2(int x)
{
    volatile int r = x;
    r = r + 1;
    r = r * 5;
    return r;
}

/* 占满目标页剩余空间，防止链接器把其它代码排进同一页 */
asm(".pushsection .target.text, \"ax\"\n.fill 4096, 1, 0\n.popsection");
asm(".pushsection .target2.text, \"ax\"\n.fill 4096, 1, 0\n.popsection");

static int (*volatile fp)(int) = caoin_target;     /* 防 LTO/去优化，调用必经入口桩 */
static int (*volatile fp2)(int) = caoin_target2;

volatile unsigned long g_shadow_status;
volatile unsigned long g_pagemap_diag;
volatile unsigned long g_code_va;
volatile unsigned long g_sent_va;   /* 哨兵页 VA（KPM 靠它识别 EL0 表） */

/* 独立于 stdout 的文件日志（防 adb 假死丢输出误判）：
 * [F]/[G]/每轮 t5、crc 落盘 /data/local/tmp/tdyn4.log，失败不影响主流程 */
static long g_logfd = -1;

static void out_log(const char *tag, long v)
{
    char b[64];
    long n = 0;
    while (tag[n] && n < 40) { b[n] = tag[n]; n++; }
    if (v >= 0) {
        char t[24]; int d = 0;
        do { t[d++] = (char)('0' + v % 10); v /= 10; } while (v);
        while (d) b[n++] = t[--d];
    }
    b[n++] = '\n';
    if (g_logfd >= 0)
        write((int)g_logfd, b, (unsigned long)n);
}

static void out_str(const char *s);
static void out_int(long v);

static unsigned long page_pa(unsigned long va)
{
    long fd = open("/proc/self/pagemap", 0 /*O_RDONLY*/);
    if (fd < 0) return 0;
    unsigned long entry = 0;
    /* procfs 文件 mmap 得到零页，必须 lseek+read */
    lseek((int)fd, (long)((va >> 12) * 8), 0 /*SEEK_SET*/);
    long r = read((int)fd, &entry, 8);
    close((int)fd);
    if (r != 8) return 0;
    g_pagemap_diag = entry;   /* 原始 entry 诊断 */
    if (!(entry >> 63 & 1)) return 0;   /* not present */
    return (entry & 0x7FFFFFFFFFFFFFULL) << 12;
}

/* shadow 页写桩后的 cache 维护：脏 D-cache 行清到 PoU + I-cache 全失效。
   没有这一步，换视图后取指拿到的是 RAM 陈旧内容（脏行未写回）。 */
static void shadow_cache_maint(unsigned long va, unsigned long len)
{
    unsigned long off;
    for (off = 0; off < len; off += 64) {
        asm volatile("dc cvau, %0" :: "r"(va + off));
        asm volatile("ic ivau, %0" :: "r"(va + off));
    }
    asm volatile("dsb ish" ::: "memory");
    asm volatile("isb" ::: "memory");
}

static void out_hex(unsigned long v)
{
    char b[24];
    int n = 0;
    char t[16]; int d = 0;
    do { t[d++] = (char)('0' + v % 16); v /= 16; } while (v);
    b[n++] = '0'; b[n++] = 'x';
    while (d) {
        char c = t[--d];
        if (c > '9') c += 39;
        b[n++] = c;
    }
    write(1, b, (unsigned long)n);
}

/* 哨兵页：KPM 在其 fault 现场记录本进程 EL0 页表（TTBR0）。
 * 触发方式 = vfork 子进程读哨兵（共享 mm，子进程死于 SIGSEGV 无碍，
 * 零 signal/handler 依赖——bionic signal() 会卡死在 sigsuspend）。 */
extern int vfork(void);
extern void _exit(int) __attribute__((noreturn));

/* aarch64 raw syscall（nostdlib）：wait4=260——收尸哨兵子进程不留 zombie */
static long sys_wait4(int pid, void *status, int options)
{
    register long x0 __asm__("x0") = pid;
    register long x1 __asm__("x1") = (long)status;
    register long x2 __asm__("x2") = options;
    register long x8 __asm__("x8") = 260;
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x8) : "memory");
    return x0;
}

/* aarch64 clone=220；fork 语义 = clone(SIGCHLD, 0, 0, 0, 0)（非 CLONE_VM，
 * 会复制页表 → 触发 caoin-shadow 的 copy_process pause/resume 防护） */
static long sys_clone(unsigned long flags)
{
    register long x0 __asm__("x0") = (long)flags;
    register long x1 __asm__("x1") = 0;
    register long x2 __asm__("x2") = 0;
    register long x3 __asm__("x3") = 0;
    register long x4 __asm__("x4") = 0;
    register long x8 __asm__("x8") = 220;
    __asm__ volatile("svc #0" : "+r"(x0)
                     : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x8) : "memory");
    return x0;
}

static void sentinel_fire(void)
{
    int c = vfork();
    if (c == 0) {
        volatile unsigned long t = *(unsigned long *)g_sent_va;
        (void)t;
        _exit(0);
    }
    if (c > 0)
        sys_wait4(c, 0, 0);   /* vfork 语义下子 _exit 后此处解除阻塞 */
}

static void shadow_mode(void)
{
    unsigned long code = (unsigned long)(void *)caoin_target & ~0xFFFUL;
    unsigned long code2 = (unsigned long)(void *)caoin_target2 & ~0xFFFUL;
    unsigned long shadow = (unsigned long)mmap(0, 4096, 3 /*RW*/, 0x22, -1, 0);
    unsigned long shadow2 = (unsigned long)mmap(0, 4096, 3 /*RW*/, 0x22, -1, 0);
    g_code_va = code;
    g_logfd = open("/data/local/tmp/tdyn4.log", 0x441 /*O_WRONLY|O_APPEND|O_CREAT*/, 0666);
    if (shadow == (unsigned long)-1 || shadow2 == (unsigned long)-1) { out_str("mmap-fail\n"); return; }

    g_sent_va = (unsigned long)mmap(0, 4096, 0 /*PROT_NONE*/, 0x22, -1, 0);

    /* 代码页原样快照（CRC 自检基准） */
    /* 独占 4K 页：g_shadow_status 的页与此页隔离后，status 页 +0x100 的
     * CFG 块（注入 payload 读取）才不会踩进 snap（真机实证：同页时 CFG 写
     * 覆盖 snap[26..29] → CRC 假阳性） */
    static unsigned long snap[512] __attribute__((aligned(4096)));
    for (int i = 0; i < 512; i++)
        snap[i] = ((unsigned long *)code)[i];
    static unsigned long snap2[512] __attribute__((aligned(4096)));
    for (int i = 0; i < 512; i++)
        snap2[i] = ((unsigned long *)code2)[i];

    /* v2e 桩：直返基线值——2 态跷跷板下执行流到达 shadow 页时直接返回
       替换值；读流 fault 切 orig 拿干净快照。
       注：KPM 注入请求命中后会用 777/778 桩覆写（hook0/hook1 各自），
       若注入成功 fp(5) 应 515→777、fp2(5) 应 55→778。 */
    for (int i = 0; i < 512; i++)
        ((unsigned long *)shadow)[i] = snap[i];
    unsigned long off_in_page = (unsigned long)(void *)caoin_target & 0xFFFUL;
    unsigned int *stub = (unsigned int *)(shadow + off_in_page);
    stub[0] = 0x52804060u;                  /* movz w0, #515 */
    stub[1] = 0xD65F03C0u;                  /* ret */
    shadow_cache_maint(shadow, 4096);

    /* hook1 的 shadow 页：快照 + 55 基线桩 */
    for (int i = 0; i < 512; i++)
        ((unsigned long *)shadow2)[i] = snap2[i];
    unsigned long off2 = (unsigned long)(void *)caoin_target2 & 0xFFFUL;
    unsigned int *stub2 = (unsigned int *)(shadow2 + off2);
    stub2[0] = 0x528006E0u;                 /* movz w0, #55 (基线：5+1)*5 */
    stub2[1] = 0xD65F03C0u;                 /* ret */
    shadow_cache_maint(shadow2, 4096);

    /* tva/shva 经 KPM 寄存器传给注入的 payload（x4/x5）——内存约定已废弃：
     * status 页 .bss 散布其它全局，内存块写会被 page_pa() 等覆写 */

    out_str("CFG");
    unsigned long pid = 0;
    {
        long fd = open("/proc/self/stat", 0);
        char b[64];
        long r = read((int)fd, b, sizeof(b) - 1);
        close((int)fd);
        b[r > 0 ? r : 0] = 0;
        char *p = b;   /* stat 首字段即 pid */
        while (*p >= '0' && *p <= '9') pid = pid * 10 + (*p++ - '0');
    }
    out_str(" pid=");
    out_hex(pid);
    out_str(" target_page=");
    out_hex(code);
    out_str(" shadow_page=");
    out_hex(shadow);
    out_str(" target2_page=");
    out_hex(code2);
    out_str(" shadow2_page=");
    out_hex(shadow2);
    out_str(" code_phys=");
    out_hex(page_pa(code));
    out_str(" diag=");
    out_hex(g_pagemap_diag);
    out_str(" shadow_phys=");
    out_hex(page_pa(shadow));
    out_str(" status_va=");
    out_hex((unsigned long)&g_shadow_status);
    out_str(" status_phys=");
    out_hex(page_pa((unsigned long)&g_shadow_status & ~0xFFFUL));
    out_str(" sent=");
    out_hex(g_sent_va);
    out_str("\n");

    /* 哨兵触发 v2：主进程自己读哨兵页。KPM 的 dpf hook 在该 fault 现场记录
     * TTBR0（= 本进程 EL0 页表）、翻 SHADOW、并修改 PC 跳过本条读指令后
     * 放行（skip_origin）——进程不死，跷跷板立即接管。 */
    /* 忙等 KPM arm 完成（status>=6 = dpf hook 已挂、视图已翻转）。
     * 等满握手再动，避免哨兵 fault 抢在 vbar_on 窗口之前；
     * KPM 侧哨兵分支即使抢跑也会跳过读（双保险）。 */
    while (g_shadow_status < 6) { volatile int d; for (d = 0; d < 1000000; d++) ; }
    out_str("[F]");
    out_log("F", 0);
    sentinel_fire();
    out_str("[G]");
    out_log("G", 0);

    /* v2 主循环：三态输出——status / 调用结果（执行视图）/ CRC 自检（读取视图）
     * 忙转代替 sleep：核保持非 idle，VBAR（v2e）不被 cpuidle 恢复路径重置 */
    {
        long round = 0;
        for (;;) {
            unsigned long crc_ok = 1;
            out_str("[A]");
            /* 关键：VIPT D-cache 命中的读不查 TLB，PTE 翻转不可见。
             * DC CIVAC 目标页强制下次读走 cache miss → TLB → SHADOW PTE → fault */
            for (int l = 0; l < 512; l += 8)
                asm volatile("dc civac, %0" :: "r"(code + (unsigned long)l * 8));
            asm volatile("dsb ish" ::: "memory");
            out_str("[B]");
            for (int i = 0; i < 512; i++)
                if (((unsigned long *)code)[i] != snap[i]) {
                    out_str(" MM@");
                    out_hex((unsigned long)(i * 8));

                    crc_ok = 0;
                    break;
                }
            out_str("[C]");
            out_str("status=");
            out_hex(g_shadow_status);
            out_str(" t(5)=");
            {
                int t5 = fp(5);
                out_int(t5);
                out_log("t5", t5);
            }
            out_str(" t2(5)=");
            {
                int t2 = fp2(5);
                out_int(t2);
                out_log("t2", t2);
            }
            out_str(" cap=");
            out_hex(*(volatile unsigned long *)(shadow + 0xF00));
            out_hex(*(volatile unsigned long *)(shadow + 0xF40));
            out_hex(*(volatile unsigned long *)(shadow2 + 0xF00));
            out_str(" crc_ok=");
            out_int((long)crc_ok);
            out_str("\n");
            out_log("crc", (long)crc_ok);
            out_str("[D]");
            /* 第 3 轮自动发注入请求：写 status = INJ_REQ（0xCA0F0002），KPM 在
             * 下一次 fault 经线性映射探测命中 → 内核态注入（payload 写 magic
             * 回 status → 后续轮 status=0xca0fca0f 可见）。外部亦可用 poke64
             * 手动触发同一通道。 */
            ++round;
            if (round == 3) {
                g_shadow_status = 0xCA0F0002UL;
                out_str(" [R3-REQ]");
            }
            if (round == 3 + 8)
                g_shadow_status = 0xCA0F0002UL;   /* 8 轮后重发一次(防丢) */
            /* fork 防护测试：每 8 轮 fork 一个子进程（非 CLONE_VM → copy_process
             * 复制页表 → 触发 pause/resume），子进程立即退出、父进程收尸。
             * 验证点：fork 时受管页 PTE 被 pause（无 Bad rss-counter/Bad page），
             * 父进程继续正常（t(5)/crc_ok 不变）。 */
            if (round % 8 == 0) {
                long c = sys_clone(17 /*SIGCHLD*/);
                if (c == 0)
                    _exit(0);
                if (c > 0)
                    sys_wait4((int)c, 0, 0);
                out_str(" fork=");
                out_int(c);
            }
            for (volatile long k = 0; k < 20000000; k++)
                ;
        }
    }
}

static void out_str(const char *s)
{
    long n = 0;
    while (s[n]) n++;
    write(1, s, (unsigned long)n);
}

static void out_int(long v)
{
    char b[24];
    int n = 0;
    if (v < 0) { out_str("-"); v = -v; }
    do { b[n++] = (char)('0' + v % 10); v /= 10; } while (v);
    char o[24];
    for (int i = 0; i < n; i++) o[i] = b[n - 1 - i];
    write(1, o, (unsigned long)n);
}

void _start(void)
{
    /* tdyn4 专用：无条件 shadow 模式（argv 经 linker 启动栈不可靠） */
    shadow_mode();
    for (;;) {
        out_str("caoin_target(5)=");
        /* 强制取指重新翻译：ic ivau 目标页（EL0 合法）——翻转只在新翻译时显形 */
        for (int l = 0; l < 512; l += 8)
            asm volatile("ic ivau, %0" :: "r"(g_code_va + (unsigned long)l * 8));
        asm volatile("dsb ish" ::: "memory");
        asm volatile("isb" ::: "memory");
        out_int(fp(5));
        out_str("\n");
        for (volatile long k = 0; k < 20000000; k++)
            ;
    }
}
