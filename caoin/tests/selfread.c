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
    if (b >= '1' && b <= '6')
        return (int)(b - '0');
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
        out_str(" hooked="); out_int(st_hooked(round));
        out_str(" hooked2="); out_int(st_hooked2(round));
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

        /* mode=4/6 跑密一点 */
        usleep((mode == 4 || mode == 6) ? 20000 : 300000);
    }
}
