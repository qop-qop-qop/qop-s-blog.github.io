/*
 * selfread — 实验 A：验证 caoin-shadow 的"独占页"约束是否来自【自指数据读】
 *
 * 假设（待验证）
 * -------------
 * SHADOW 视图是 execute-only（EL0 无数据访问），STEP 视图是原页但 UXN=1（不可执行）。
 * 若**取指与数据读落在同一个受管页**，两态会互相踢：
 *     取指(成功) → 读 fault → 切 STEP → eret 重取指(STEP 不可执行) → fault
 *       → 切 SHADOW → 取指成功 → 读又 fault → ...
 * 即无限振荡（活锁）。若成立，则独占页的真正边界不是"页内有别的代码"，而是
 * "受管页里存在自指数据访问"——后者在真实代码里几乎必然出现（字面量池/跳转表）。
 *
 * 三个格子（同一进程内循环，便于任意时刻挂 hook 观察）
 * ---------------------------------------------------
 *   C1  读指令在页外，读受管页     对照，已知可用（等价 shellwatch 的 sw_crc）
 *   C2  读指令在受管页内，读别的页  对照，隔离"页内有可执行代码"这个变量
 *   C3  读指令在受管页内，读受管页  处理组，预测活锁
 *
 * 判据（详见下方"判据"一节）
 * -------------------------
 *   挂 hook 后 C1/C2 正常、C3 卡在 start 且进程 ~100% utime、无 SIGSEGV
 *       → 假设成立，变量精确是"读指令住在受管页里"
 *   挂 hook 后 C3 继续 done
 *       → 假设被证伪，独占页约束另有成因（退回到"页内有别的可执行代码"那条）
 *   C3 继续 done 但 hooked 不再是 777（或 match 翻 0）
 *       → 桩失效/读隐藏失效，但不是活锁（对应 README"桩不生效"那条）
 *   same_page=0 / readers_differ=0
 *       → 布局没做对，本轮无效
 *   dmesg 里出现 caoin-kpm: DUMP ... esr=... （或 flt 行 ec=25）
 *       → EL1 那条线。注意它与活锁是【两条不同的线】：
 *         DUMP 只在"状态机未接管"的 fault 上打印（caoin_kpm.c:332-347），
 *         而活锁的每次 fault 都被接管、永远走不到 DUMP。EC=0x25 说明是 EL1
 *         侧访问，caoin 自己的 KPM 全程只用内核线性地址（13 处 caoin_va()），
 *         所以那个 EL1 访问者不是 caoin 的代码。用 mode 文件把这条线单独隔离。
 *
 * 运行模式（可选，随时可切，每轮重读）
 * ----------------------------------
 *   echo 1 > /data/local/tmp/selfread.mode   # 只跑 C1（页外读受管页）
 *   echo 2 > /data/local/tmp/selfread.mode   # 只跑 C2（页内读别页）
 *   echo 3 > /data/local/tmp/selfread.mode   # 只跑 C3（页内读受管页）
 *   echo 4 > /data/local/tmp/selfread.mode   # 只跑 fork 压力（每轮 fork 一次）
 *   echo a > /data/local/tmp/selfread.mode   # 只跑 C10（只读页写 → 期望 SIGSEGV）
 *   echo b > /data/local/tmp/selfread.mode   # 只跑 C11（PROT_NONE 不绕过不活锁）
 *   echo c > /data/local/tmp/selfread.mode   # 只跑 C12（只读页 DC/IC 代做跳过）
 *   echo d > /data/local/tmp/selfread.mode   # 只跑 C13（/proc/self/mem GUP 读）
 *   echo e > /data/local/tmp/selfread.mode   # 只跑 C14（munmap+mmap FIXED 感知，不碰页内容）
 *   rm /data/local/tmp/selfread.mode         # 三个都跑
 *   用途：C3 活锁会以极高频率刷 fault 日志，把 caoin 的 flt 日志上限（100 条）
 *   瞬间吃光，EL1 那条线就看不到窗口了。用 mode=2 可以拿到不含活锁的干净窗口。
 *
 * mode=4（fork 压力）测什么
 * ------------------------
 * 影子页改由内核分配后，fork 会让子进程的页表快照继承一个**指向内核页**的 PTE。
 * caoin 的 copy_process 伴侣钩子应在 fork 前 pause（受管页 PTE 恢复原值）、
 * fork 后 resume。若该保护失效，子进程退出时 exit_mmap 会按内核页的物理页
 * 释放 + rss 记账 → dmesg 出现 `Bad page` / `Bad rss-counter`。
 * 子进程立刻 _exit(0)，专门去踩这条路径。
 *
 * 受管页布局（.st.text，页对齐，独占页）
 * ------------------------------------
 *   +0x00  64B 填充（不执行）
 *   +0x40  st_hooked          ← 被 hook 的函数；桩写在 tva & 0xFFF = 0x40
 *   +0x70  st_reader_inpage   ← 读指令所在函数，必须与 st_hooked 同页
 *   其余   填充（不执行）
 *
 * noinline 是硬要求：一旦 st_reader_inpage 被内联进 _start，读指令就跑到别的页，
 * C3 会静默退化成 C1，整轮实验失去意义。运行时会打印 same_page= 与两个 off= 自检。
 *
 * 编译（同 shtarget：动态链接 bionic，符号进 .dynsym 供 caoin_prep 远程解析）
 * ---------------------------------------------------------------------
 *   aarch64-linux-gnu-gcc -Wall -O2 -nostdlib -pie tests/selfread.c -o build/selfread \
 *     -Wl,--dynamic-linker=/system/bin/linker64 \
 *     -Wl,--allow-shlib-undefined -Wl,--export-dynamic \
 *     -Lbuild -l:libc_bionic.so
 *
 * 跑法
 * ----
 *   # 设备上（先清 dmesg，观察窗口干净）
 *   dmesg -c > /dev/null
 *   ./build/selfread &                          # 记下 pid，先看几轮基线
 *   caoin_prep <pid> @ st_hooked                # → pid=0x.. tva=0x.. shva=0x.. sva=0x..
 *   dmesg -c > /dev/null                        # 再清一次，只留挂 hook 之后
 *   kpatch su kpm load caoin-shadow.kpm \
 *     "pid=0x.. tva=0x.. shva=0x.. sva=0x.. stub=1 verbose=1"
 *
 *   # 判定活锁：dmesg 里 pc 与 far 都落在受管页内的 flt# 行（verbose=1 才打）
 *   dmesg | grep caoin-kpm | grep flt
 *   # 对照：C1 的 fault 是 pc 在页外、far 在页内
 *   # 处理组：C3 的 fault 是 pc 与 far 都在页内，且 ec=20 与 ec=24 交替
 */
extern long write(int, const void *, unsigned long);
extern int getpid(void);
extern unsigned int usleep(unsigned int);
extern int open(const char *, int, ...);
extern long read(int, void *, unsigned long);
extern int close(int);
extern int fork(void);
extern void _exit(int);
extern int waitpid(int, int *, int);
extern int pthread_create(unsigned long *th, const void *attr,
                          void *(*fn)(void *), void *arg);
extern int mprotect(void *addr, unsigned long len, int prot);
extern int madvise(void *addr, unsigned long len, int advice);
extern int munmap(void *addr, unsigned long len);
extern long mmap(void *addr, unsigned long len, int prot, int flags,
                 int fd, long off);
extern long lseek(int, long, int);
extern void (*signal(int, void (*)(int)))(int);
extern long pread(int fd, void *buf, unsigned long n, long off);

#define SR_PROT_NONE    0
#define SR_PROT_RX      5   /* PROT_READ | PROT_EXEC */
#define SR_PROT_RWX     7   /* PROT_READ | PROT_WRITE | PROT_EXEC */
#define SR_MADV_DONTNEED 4
#define SR_SIGSEGV      11

/* ---- 受管页布局 ---- */
asm(".pushsection .st.text, \"ax\"\n.balign 4096\n.fill 64, 1, 0\n.popsection");

/* 跨页被调用者：在默认 .text（与受管页不同页）。st_hooked 的体会调它，
 * 编译成一条**跨页**的 b/bl —— 这正是"影子页方案"会算错目标的那类指令
 * （约束②：执行从影子页跑，PC 相对偏移算出来的是影子页基准的地址）。
 * 方案 A（硬件断点 + pc 重定向）下函数体在原页执行，所以它必须正常。 */
__attribute__((noinline, used, visibility("default")))
long st_helper(long x)
{
    return x * 3 + 7;
}

/* C12：从页外对受管页做 cache 维护。只读页上 DC/IC 是 WnR=1 permission
 * fault —— 新 handler 代做并跳过（不翻 STEP、不 SIGSEGV）。 */
__attribute__((noinline, used, visibility("default")))
long st_cacheop(volatile void *p)
{
    __asm__ volatile("dc cvac, %0" :: "r"(p) : "memory");
    __asm__ volatile("ic ivau, %0" :: "r"(p) : "memory");
    return 4321;
}

/* pc 重定向的目标（方案 A 的 trampoline）：返回一个一眼可辨的标记值 */
__attribute__((noinline, used, visibility("default")))
long st_tramp(long x)
{
    (void)x;
    return 4242;
}

/* 被 hook 的函数：页内偏移 0x40。777 替换桩会覆盖它的序言。 */
__attribute__((noinline, used, visibility("default"), section(".st.text")))
long st_hooked(long x)
{
    return st_helper(x);   /* 跨页调用：影子页方案会算错，方案 A 不会 */
}

asm(".pushsection .st.text, \"ax\"\n.fill 32, 1, 0\n.popsection");

/* 读指令所在函数 —— C3 的自变量。乘数故意与页外版本不同：
 * 避免链接期 ICF（-fipa-icf 在 -O2 下默认开）把两个函数合并，否则
 * st_reader_outpage 可能被并到页内，C1 静默变成 C3。 */
__attribute__((noinline, used, visibility("default"), section(".st.text")))
unsigned long st_reader_inpage(volatile unsigned long *p, long n)
{
    unsigned long s = 0;
    long i;
    for (i = 0; i < n; i++)
        s = s * 31 + p[i];
    return s;
}

asm(".pushsection .st.text, \"ax\"\n.fill 16, 1, 0\n.popsection");

/* 约束② 探针：位于受管页内，体内做一次**跨页调用**（bl st_helper）。
 * 影子页路线下页内代码从影子页执行 → 这条 PC 相对分支算出的是"影子页基准"
 * 的地址 → 目标错误（可能崩，也可能静默跳进别的已映射区域 —— 这正是②的
 * "哑失败"特征，没法在 fault 里救）。
 * 方案 A（硬件断点）下函数体在原页执行，所以它必须正常。
 * 故意用 +1 挡住尾调用，保证编译成 bl + ret 而不是单条 b。 */
__attribute__((noinline, used, visibility("default"), section(".st.text")))
long st_xpage(long x)
{
    return st_helper(x) + 1;
}

/* 页内其余填充：把 .st.text 撑满，保证紧随其后的段从新页开始
 * （否则 .text 可能与本页共享一页，独占性被破坏）。不执行。 */
asm(".pushsection .st.text, \"ax\"\n.fill 4000, 1, 0\n.popsection");

/* 第二个独占页：多 hook 测试用。caoin 的 fault 按页帧分发，同页挂不了两个 hook，
 * 所以第二个 hook 点必须落在另一个页上。返回值与 st_hooked 区分（3x+307 vs 3x+7），
 * 便于分辨哪个桩生效。 */
asm(".pushsection .st2.text, \"ax\"\n.balign 4096\n.fill 64, 1, 0\n.popsection");

__attribute__((noinline, used, visibility("default"), section(".st2.text")))
long st_hooked2(long x)
{
    return st_helper(x + 100);
}

asm(".pushsection .st2.text, \"ax\"\n.fill 16, 1, 0\n.popsection");

/* 双参数函数：验证 argN= 真的改到了 x1（而不是只改 x0）。
 * st_hooked3(n, 1000) 未 hook 时 = 3*(n+1000)+7 = 3n+3007；
 * 用 arg1=0x0 把 x1 压成 0 → 应变成 3n+7。 */
__attribute__((noinline, used, visibility("default"), section(".st2.text")))
long st_hooked3(long a, long b)
{
    return st_helper(a + b);
}

/* 尾部填充必须让本段总长 >= 4096，否则紧随其后的 .rodata 会挤进同一页
 * （实测 fill 4000 时总长 4072，.rodata 落到 0x4ff0 = st_hooked2 所在页）。 */
asm(".pushsection .st2.text, \"ax\"\n.fill 4100, 1, 0\n.popsection");

/* 读指令在页外的对照函数（默认 .text）。乘数 131 ≠ 31（见上）。 */
__attribute__((noinline, used, visibility("default")))
unsigned long st_reader_outpage(volatile unsigned long *p, long n)
{
    unsigned long s = 0;
    long i;
    for (i = 0; i < n; i++)
        s = s * 131 + p[i];
    return s;
}

/* ---- 输出工具（零依赖，同 shtarget/shellwatch） ---- */
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
    {
        char o[24];
        int i;
        for (i = 0; i < n; i++) o[i] = b[n - 1 - i];
        write(1, o, (unsigned long)n);
    }
}

static void out_hex(unsigned long v)
{
    char b[18];
    int i;
    b[0] = '0'; b[1] = 'x';
    for (i = 0; i < 16; i++) {
        int d = (int)((v >> (60 - i * 4)) & 0xf);
        b[2 + i] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
    }
    write(1, b, 18);
}

/* 读受管页 16 个字（0x00..0x7F，含 0x40 的桩位）。
 * 之所以要含 0x40：桩只改影子页，读原页与读影子页的校验和因此不同，
 * match= 才有判别力（若只读前面的填充零区，两边一样，等于没测）。 */
#define RD_N 16

static unsigned long page_of(unsigned long a)
{
    return a & ~0xFFFUL;
}

/* 直接读 /proc/self/pagemap 拿当前 PTE 的物理页号。
 * 目的：mprotect 到底"改了什么"——是换了 PFN（回到原页），还是只重写了权限位。
 * 目标以 root 跑，pagemap 的 PFN 字段对 CAP_SYS_ADMIN 可见。 */
static unsigned long pgmap_pfn(unsigned long va)
{
    int fd = open("/proc/self/pagemap", 0);
    unsigned long e = 0;
    if (fd < 0)
        return 0;
    if (lseek(fd, (long)((va >> 12) * 8), 0) < 0) {
        close(fd);
        return 0;
    }
    if (read(fd, &e, 8) != 8) {
        close(fd);
        return 0;
    }
    close(fd);
    return e & ((1UL << 55) - 1);
}

/* 运行模式：每轮重读，可随时切换（'1'/'2'/'3' 单选某格，其它 = 全跑）。
 * 存在的意义：C3 活锁会瞬间吃光 caoin 的 flt 日志上限（100 条），
 * 用 mode=2 才能拿到不含活锁的干净 dmesg 窗口去抓 EL1 那条线。 */
static int read_mode(void)
{
    char b = 0;
    int fd = open("/data/local/tmp/selfread.mode", 0);
    if (fd < 0)
        return 0;
    if (read(fd, &b, 1) != 1)
        b = 0;
    close(fd);
    if (b >= '1' && b <= '9')
        return (int)(b - '0');
    if (b >= 'a' && b <= 'e')
        return 10 + (b - 'a');   /* 'a'..'e' = C10..C14 */
    return 0;
}

static unsigned long other_page[RD_N];   /* 另一页，C2 读它 */

/* ---- mode=6：多线程竞态压力 ----
 * caoin 的 PTE 翻转没有任何锁（caoin_kpm.c 里 spin_lock / mutex / atomic_* 一个都没有），
 * 靠的是 fault 路径持有的 mmap_sem —— 而 4.9 arm64 的 do_page_fault 用的是【读锁】
 * （down_read），两个 CPU 可以同时进 handler。所以"fault vs fault"是不互斥的。
 *
 * 这个格子让多个线程同时踩受管页，每轮交替做两件事：
 *   (a) 页外读受管页（st_reader_outpage 在 .text）→ 触发 SHADOW→STEP 翻转
 *   (b) 取指受管页（st_hooked）                → 触发 STEP→SHADOW 翻回
 * 单线程时这是正常的跷跷板；多线程并发时 cur_view 与 PTE 可能脱同步。
 * 观察指标：主线程的 hooked 是否还能稳定拿到 777、进程是否卡死/崩溃。 */
static volatile unsigned long g_race_iters;
static volatile int g_race_stop;

/* 通过 volatile 函数指针调用：GCC 会把"纯函数 + 返回值未使用"的调用当死代码删掉。
 * 第一次实测就是这样 —— thr_race 里的 st_hooked(0) 被整个删了，线程只读不取指，
 * 跷跷板翻一次就静止（零 fault、低 stime），整轮测试静默失效。 */
static long (*volatile g_fp_hooked)(long) = st_hooked;
static unsigned long (*volatile g_fp_outpage)(volatile unsigned long *, long) =
    st_reader_outpage;

/* 并发下"读隐藏"是否还成立：把每次读的校验和与挂 hook 前的基线比。
 *   ok  = 读到原页字节（读隐藏成立）
 *   bad = 读到别的（读到影子页/桩字节 → 读隐藏被破坏） */
static unsigned long g_base_out;
static volatile unsigned long g_race_ok, g_race_bad;

static void *thr_race(void *arg)
{
    volatile unsigned long *mp = (volatile unsigned long *)arg;
    while (!g_race_stop) {
        unsigned long r = g_fp_outpage(mp, RD_N);
        if (r == g_base_out)
            g_race_ok++;
        else
            g_race_bad++;
        g_fp_hooked(0);           /* 取指受管页 → 翻回 SHADOW */
        g_race_iters++;
    }
    return (void *)0;
}

/* ---- C10/C11：fork 子进程探针 ----
 * 只读页写 / PROT_NONE 访问的新 handler 语义是交还原生 → 子进程收 SIGSEGV。
 * 用 fork 子进程做坏访问、父进程 waitpid 看死法：确定性，无信号处理陷阱
 * （首版用 sigsetjmp(0)+handler 内 siglongjmp，第二次 SIGSEGV 没接住，
 *  进程直接死——signal 掩码/内核信号状态不一致，弃用）。
 * 顺带每格都过一遍 copy_process pause/resume 路径。 */
static int probe_segv(long (*volatile fn)(long))
{
    int st = 0;
    long cpid = fork();

    if (cpid == 0)
        _exit((int)fn(0));   /* 没崩 = 写/访问成功，退出码是返回值 */
    if (cpid < 0)
        return -1;
    waitpid((int)cpid, &st, 0);
    /* 被 SIGSEGV 杀死 = 1（期望）；正常退出 = 0（权限被绕过，BAD） */
    return ((st & 0x7f) == SR_SIGSEGV) ? 1 : 0;
}

static volatile unsigned long g_mp;   /* 受管页地址（探针子进程用） */

/* 探针包装（.text 页外）：坏写 / 坏读 */
__attribute__((noinline, used, visibility("default")))
long st_badwrite(long x)
{
    (void)x;
    *(volatile unsigned long *)g_mp = 0x1234;
    return 7777;
}

__attribute__((noinline, used, visibility("default")))
long st_badread(long x)
{
    (void)x;
    return (long)st_reader_outpage((volatile unsigned long *)g_mp, RD_N);
}

void _start(void)
{
    volatile unsigned long *mp =
        (volatile unsigned long *)page_of((unsigned long)(void *)st_hooked);
    volatile unsigned long *other = (volatile unsigned long *)other_page;
    unsigned long hp = (unsigned long)(void *)st_hooked;
    unsigned long rp = (unsigned long)(void *)st_reader_inpage;
    unsigned long base_out, base_in;
    long i, round;

    /* 布局自检：same_page 必须为 1，否则本轮实验无效 */
    out_str("SR pid="); out_int((long)getpid());
    out_str(" hooked="); out_hex(hp);
    out_str(" hooked_off="); out_hex(hp & 0xFFFUL);
    out_str(" hooked2="); out_hex((unsigned long)(void *)st_hooked2);
    out_str(" hooked2_off="); out_hex((unsigned long)(void *)st_hooked2 & 0xFFFUL);
    out_str(" xpage="); out_hex((unsigned long)(void *)st_xpage);
    out_str(" xpage_off="); out_hex((unsigned long)(void *)st_xpage & 0xFFFUL);
    out_str(" hooked3="); out_hex((unsigned long)(void *)st_hooked3);
    out_str(" hooked3_off="); out_hex((unsigned long)(void *)st_hooked3 & 0xFFFUL);
    out_str(" reader="); out_hex(rp);
    out_str(" reader_off="); out_hex(rp & 0xFFFUL);
    out_str(" outpage_reader="); out_hex((unsigned long)(void *)st_reader_outpage);
    out_str(" same_page="); out_int(page_of(hp) == page_of(rp) ? 1 : 0);
    /* ICF 自检：两个 reader 地址必须不同。若相同说明被链接期合并，
     * C1 会静默变成 C3，本轮实验无效。 */
    out_str(" readers_differ=");
    out_int((void *)st_reader_inpage != (void *)st_reader_outpage ? 1 : 0);
    out_str("\n");

    for (i = 0; i < RD_N; i++)
        other_page[i] = (unsigned long)(0x1000 + i);

    /* 基线校验和：挂 hook 之前取，此时读到的一定是原页。
     * 顺带证明 st_reader_inpage 在无 seesaw 时是能跑的（否则布局有问题）。 */
    base_out = st_reader_outpage(mp, RD_N);
    base_in  = st_reader_inpage(mp, RD_N);
    g_base_out = base_out;
    g_mp = (unsigned long)mp;
    out_str("base_out="); out_hex(base_out);
    out_str(" base_in="); out_hex(base_in);
    out_str("\n");

    for (round = 0; ; round++) {
        int mode = read_mode();
        unsigned long r1, r2, r3;

        /* 每轮都调一次 st_hooked：hooked=777 表示桩生效，3n+7 表示未 hook。
         * 放在行首，保证任何 mode 下都能看到桩的状态。 */
        out_str("R r="); out_int(round);
        out_str(" mode="); out_int(mode);
        if (mode != 14) {
            /* C14 例外：mmap FIXED 后受管页是 RW 匿名页，st_hooked 取指
             * 必 SIGSEGV（首版实测进程 <1s 即死，prep 都来不及） */
            out_str(" hooked="); out_int(st_hooked(round));
            out_str(" hooked2="); out_int(st_hooked2(round));
            out_str(" hooked3="); out_int(st_hooked3(round, 1000));
        }
        out_str("\n");

        /* C1：读指令在页外，读受管页（对照，等价 shellwatch 的 sw_crc） */
        if (mode == 0 || mode == 1) {
            r1 = st_reader_outpage(mp, RD_N);
            out_str("C1 r="); out_int(round);
            out_str(" rd="); out_hex(r1);
            out_str(" match="); out_int(r1 == base_out);
            out_str("\n");
        }

        /* C2：读指令在受管页内，读别的页（对照，隔离"页内有可执行代码"） */
        if (mode == 0 || mode == 2) {
            r2 = st_reader_inpage(other, RD_N);
            out_str("C2 r="); out_int(round);
            out_str(" rd="); out_hex(r2);
            out_str("\n");
        }

        /* C3：读指令在受管页内，读受管页（处理组，预测在此活锁） */
        if (mode == 0 || mode == 3) {
            out_str("C3 r="); out_int(round); out_str(" start\n");
            r3 = st_reader_inpage(mp, RD_N);
            out_str("C3 r="); out_int(round);
            out_str(" done rd="); out_hex(r3);
            out_str(" match="); out_int(r3 == base_in);
            out_str("\n");
        }

        /* C4（mode=4）：fork 压力。子进程立刻 _exit(0)，专门去踩它的 exit_mmap——
         * 如果 copy_process 伴侣钩子没把受管页 PTE 恢复原值，子进程页表快照里
         * 就是一个指向内核页的 PTE，退出时按内核页释放 + rss 记账 → Bad page。 */
        if (mode == 4) {
            int cpid = fork();
            if (cpid == 0) {
                _exit(0);
            } else if (cpid > 0) {
                int st = 0;
                waitpid(cpid, &st, 0);
                out_str("F4 r="); out_int(round);
                out_str(" child="); out_int(cpid);
                out_str(" status="); out_int(st);
                out_str("\n");
            } else {
                out_str("F4 r="); out_int(round); out_str(" fork_failed\n");
            }
        }

        /* C5（mode=5）：约束② 探针 —— 受管页内的跨页调用。
         * pre 与 post 分开打：崩在调用里就会只看到 pre。 */
        if (mode == 5) {
            out_str("C5 r="); out_int(round); out_str(" pre\n");
            out_str("C5 r="); out_int(round);
            out_str(" post="); out_int(st_xpage(round));
            out_str("\n");
        }

        /* C6（mode=6）：多线程竞态压力 */
        if (mode == 6) {
            static int race_started;
            if (!race_started) {
                unsigned long th;
                int k;
                race_started = 1;
                for (k = 0; k < 4; k++)
                    pthread_create(&th, (const void *)0, thr_race, (void *)mp);
                out_str("C6 spawned 4 threads\n");
            }
            out_str("C6 r="); out_int(round);
            out_str(" iters="); out_int((long)g_race_iters);
            out_str(" ok="); out_int((long)g_race_ok);
            out_str(" bad="); out_int((long)g_race_bad);
            out_str(" hooked="); out_int(st_hooked(round));
            out_str("\n");
        }

        /* C7（mode=7）：只做 mprotect，每轮都做，用来拿"桩还活着"时的样本。
         *
         * 关键机制：mprotect 走 change_protection 时只重写 PTE 的**属性位**
         * （pte_modify 的掩码里不含 PFN 位），PFN 原样保留。所以它既不"回到
         * 原页"，也不认 caoin 的 cur_view —— 它只是把**当前那个 PFN** 按 VMA
         * 新权限重新描述一遍。后果取决于跷跷板当时停在哪一态：
         *   SHADOW（PFN=影子页, execute-only）→ 变成 EL0 可读 → 读隐藏破
         *                                      （CRC 能读到桩字节）
         *   STEP  （PFN=原页,    UXN=1）      → 变成可执行 → 从此不再 fault
         *                                      → 桩彻底失效且无从察觉
         * 同权限 mprotect（VMA 已是 r-x 再要 r-x）会被 mprotect_fixup 早退，
         * 连 change_protection 都进不去 → PTE 一个 bit 都不动。 */
        if (mode == 7) {
            int rc;
            out_str("C7 r="); out_int(round);
            /* 先读一次受管页：页外读触发 SHADOW→STEP，让后面的 mprotect
             * 落在 **STEP 态**（PFN=原页、UXN=1）上 —— 这才是最危险的那种。 */
            out_str(" rd0="); out_int(st_reader_outpage(mp, RD_N) == base_out);
            out_str(" pfnA="); out_hex(pgmap_pfn((unsigned long)mp));

            rc = mprotect((void *)mp, 4096, SR_PROT_RWX);      /* 改权限 */
            out_str(" | rwx rc="); out_int(rc);
            out_str(" pfn="); out_hex(pgmap_pfn((unsigned long)mp));
            out_str(" hooked="); out_int(st_hooked(round));

            rc = mprotect((void *)mp, 4096, SR_PROT_RX);       /* 还原 */
            out_str(" | rx rc="); out_int(rc);
            out_str(" pfn="); out_hex(pgmap_pfn((unsigned long)mp));
            out_str(" hooked="); out_int(st_hooked(round));
            /* 直判：mprotect 之后从页外**读**受管页，校验和是否仍等于原页。
             * =1 → PTE 仍拒绝 EL0 数据访问（读被 caoin 翻 STEP 后拿原页）
             * =0 → PTE 已变可读，读到的是影子页（含桩）→ 读隐藏已破 */
            out_str(" rd_eq_base=");
            out_int(st_reader_outpage(mp, RD_N) == base_out);
            out_str("\n");
        }

        /* C8（mode=8）：madvise(DONTNEED) —— 真正 zap PTE，下次访问由原生缺页
         * 路径按 VMA 重建 → 这才是"回到原页"，桩必然失效。 */
        if (mode == 8) {
            int rc;
            out_str("C8 r="); out_int(round);
            out_str(" pre="); out_int(st_hooked(round));
            out_str(" pfn0="); out_hex(pgmap_pfn((unsigned long)mp));

            rc = madvise((void *)mp, 4096, SR_MADV_DONTNEED);
            out_str(" | madv rc="); out_int(rc);
            out_str(" hooked="); out_int(st_hooked(round));
            out_str(" pfn="); out_hex(pgmap_pfn((unsigned long)mp));
            out_str("\n");
        }

        /* C9（mode=9）：**同权限** mprotect 到底碰不碰 PTE —— 用来确认"判断发生在
         * VMA 层、不在 PTE 层"。
         *
         * 内核 mprotect_fixup 只有一条早退：`newflags == vma->vm_flags` 就直接返回，
         * 连 change_protection 都进不去。而 change_protection 才是唯一重写 PTE 的
         * 地方。所以同权限 mprotect 应当**一个 bit 都不动**。
         *
         * 判据用读隐藏：先执行一次让页停在 SHADOW（execute-only），再 mprotect(r-x)
         * （VMA 本来就是 r-x），然后从页外读受管页：
         *   rd_eq_base=1 → PTE 仍是 execute-only（读被 caoin 翻 STEP 后拿到原页）
         *                  ⇒ 同权限 mprotect 确实没碰 PTE（早退成立）
         *   rd_eq_base=0 → PTE 已变可读（读到影子页内容）
         *                  ⇒ change_protection 真跑了，早退不存在 */
        if (mode == 9) {
            int rc;
            out_str("C9 r="); out_int(round);
            out_str(" hooked0="); out_int(st_hooked(round));   /* 执行 → 页停 SHADOW */
            out_str(" pfn0="); out_hex(pgmap_pfn((unsigned long)mp));

            rc = mprotect((void *)mp, 4096, SR_PROT_RX);       /* 同权限 */
            out_str(" | rx rc="); out_int(rc);
            out_str(" pfn1="); out_hex(pgmap_pfn((unsigned long)mp));
            out_str(" rd_eq_base=");
            out_int(st_reader_outpage(mp, RD_N) == base_out);
            out_str("\n");
        }

        /* C10（mode=10 / 'a'）：只读页上的普通写必须 SIGSEGV（fork 子进程探针）。
         * 旧 handler 会把受管页翻成 STEP RW 让写成功 —— 目标对自己的 r-x 代码页
         * 写一个字节不崩，本身就是强检测向量，还会改坏原页。
         * 新语义：SHADOW 下 WnR=1 非 cache op → 交原生；STEP 只读页写 → 交原生。
         * 判据：wr_segv=1 且 crc_ok=1（写没落盘）且 hooked=777（桩还活着）。 */
        if (mode == 10) {
            out_str("C10 r="); out_int(round);
            out_str(" hooked0="); out_int(st_hooked(round));
            out_str(" rd="); out_int(st_reader_outpage(mp, RD_N) == base_out);
            out_str(" wr_segv="); out_int(probe_segv(st_badwrite));
            out_str(" crc_ok=");
            out_int(st_reader_outpage(mp, RD_N) == base_out);
            out_str(" hooked="); out_int(st_hooked(round));
            out_str("\n");
        }

        /* C11（mode=11 / 'b'）：PROT_NONE 不被绕过、不活锁（fork 探针）。
         * 旧 handler 会把 PROT_NONE 的数据 fault 翻 STEP（绕过），或把 STEP 下
         * 的 fault 当 TLB 陈旧 flush+retry（PTE 仍是 PROT_NONE → 活锁）。
         * 新语义：AP=0 的数据/取指 fault 一律交原生 SIGSEGV。
         * 还原 RX 后 hooked 应当仍活；rd_eq_base 只记录 —— shadow PTE 被
         * change_protection 重写过，读隐藏可能已破（mprotect 边界，非本格目标）。 */
        if (mode == 11) {
            int rc;
            out_str("C11 r="); out_int(round);
            rc = mprotect((void *)mp, 4096, SR_PROT_NONE);
            out_str(" none_rc="); out_int(rc);
            out_str(" rd_segv="); out_int(probe_segv(st_badread));
            out_str(" ex_segv="); out_int(probe_segv(st_hooked));
            rc = mprotect((void *)mp, 4096, SR_PROT_RX);
            out_str(" rx_rc="); out_int(rc);
            out_str(" hooked="); out_int(st_hooked(round));
            out_str(" rd_eq_base=");
            out_int(st_reader_outpage(mp, RD_N) == base_out);
            out_str("\n");
        }

        /* C12（mode=12 / 'c'）：只读页上的 DC/IC 维护指令。
         * handler 在 EL1 代做并 pc+=4 跳过：不翻 STEP、不 SIGSEGV、不活锁。
         * 判据：cache_rc=4321（两条都走完）且 hooked=777 且 crc_ok=1。 */
        if (mode == 12) {
            long crc;
            out_str("C12 r="); out_int(round);
            out_str(" hooked0="); out_int(st_hooked(round));
            out_str(" rd="); out_int(st_reader_outpage(mp, RD_N) == base_out);
            crc = st_cacheop((void *)mp);
            out_str(" cache_rc="); out_int(crc);
            out_str(" hooked="); out_int(st_hooked(round));
            out_str(" crc_ok=");
            out_int(st_reader_outpage(mp, RD_N) == base_out);
            out_str("\n");
        }

        /* C13（mode=13 / 'd'）：读类 GUP（/proc/self/mem pread）打受管页。
         * 无 GUP 伴侣钩子时：SHADOW 的 PTE_SPECIAL 让 follow_page_pte 拿不到
         * page → faultin_page 按 VMA 权限（r-x, UXN=0）重写 PTE → 桩静默死。
         * 观测：pfn0/pfn1（pread 前后 PTE 指向：影子 PFN ≠ 原 PFN）、got（pread
         * 返回字节数）、s/base（读到内容的校验和 vs 原页基线）、hooked。
         * 判据（钩子工作时）：pfn0=影子 pfn1=影子、got=4096、s=base、hooked=777。 */
        if (mode == 13) {
            unsigned long buf[RD_N];
            unsigned long s = 0;
            long got;
            int i, fd = open("/proc/self/mem", 0);

            out_str("C13 r="); out_int(round);
            out_str(" hooked0="); out_int(st_hooked(round));
            out_str(" pfn0="); out_hex(pgmap_pfn((unsigned long)mp));
            got = -1;
            if (fd >= 0) {
                got = pread(fd, buf, sizeof(buf), (long)(unsigned long)mp);
                close(fd);
            }
            if (got == (long)sizeof(buf))
                for (i = 0; i < RD_N; i++)
                    s = s * 131 + buf[i];   /* 与 st_reader_outpage 同乘数 */
            out_str(" got="); out_int(got);
            out_str(" w10="); out_hex(buf[10]);   /* 0x50: 原页=b 桩=movz777 */
            out_str(" s="); out_hex(s);
            out_str(" base="); out_hex(base_out);
            out_str(" pfn1="); out_hex(pgmap_pfn((unsigned long)mp));
            out_str(" gup_ok=");
            out_int(got == (long)sizeof(buf) && s == base_out);
            out_str(" hooked="); out_int(st_hooked(round));
            out_str("\n");
        }

        /* C14（mode=14 / 'e'）：munmap + mmap(MAP_FIXED) 感知正路径（0.6.3）。
         * 安全约束（与 C7/C8 的关键差异）：mmap FIXED 会把受管页 PTE 换成
         * 新匿名页，之后该地址的**任何**访问（连调 st_hooked 观测也不行）
         * 都会把 KPM 的 fault 路径带进未知分支——所以本格全程不碰 mp
         * 内容，只做两个 syscall + 打印返回值。
         * 页表安全性：munmap 一页只清 PTE 不拆 PT（.text VMA 多页还在）→
         * KPM 缓存的 pte_addr 槽位仍有效。
         * 收尾流程固定：kill 目标 → unload（目标已死，restore 走
         * target-gone 分支不碰页表）。
         * 判据（mstat）：munmap_hits/mmap_hits 每轮各 +1，which=4/3，ret=0。 */
        if (mode == 14) {
            long rc;
            long p;

            out_str("C14 r="); out_int(round);
            rc = munmap((void *)mp, 4096);
            out_str(" | munmap rc="); out_int(rc);
            p = mmap((void *)mp, 4096, 3 /* PROT_RW */,
                     0x32 /* FIXED|PRIVATE|ANON */, -1, 0);
            out_str(" mmap=");
            out_hex((unsigned long)p);
            out_str("\n");
        }

        /* mode=4/6 跑密一点 */
        usleep((mode == 4 || mode == 6) ? 20000 : 300000);
    }
}
