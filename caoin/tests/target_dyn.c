/*
 * bionic 动态测试目标（无 NDK）：周期调用 caoin_target 并打印。
 * 注入 caoin_agent 后输出应从 base 变为 base+100（行为级证据）。
 * shadow 模式（argv[1]=="shadow"）：准备 shadow 页（快照+桩）并打印
 * caoin 内核模块所需的全部 cfg 值，之后进入 status 轮询 + 周期输出。
 */
extern long write(int, const void *, unsigned long);
extern int nanosleep(const void *req, void *rem);
extern void *mmap(void *, unsigned long, int, int, int, long);
extern long lseek(int, long, int);
extern int mprotect(void *, unsigned long, int);
extern long open(const char *, int, ...);
extern long read(int, void *, unsigned long);
extern long close(int);

struct ts { long sec, nsec; };

__attribute__((noinline, visibility("default")))
int caoin_target(int x)
{
    volatile int r = x;
    r = r * 3;
    r = r ^ 0x2A;
    r = r + 7;
    r = r * 2;
    return r;
}

static int (*volatile fp)(int) = caoin_target;   /* 防 LTO/去优化，调用必经入口桩 */

volatile unsigned long g_shadow_status;
volatile unsigned long g_pagemap_diag;
long g_shadow_ret_off = 500;

static void out_str(const char *s);
static void out_int(long v);

/* shadow 模式的桩目标：返回原值+500 */
__attribute__((noinline))
static int shadow_handler(int x) { return x * 3 + 500; }

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

static void shadow_mode(void)
{
    unsigned long code = (unsigned long)(void *)caoin_target & ~0xFFFUL;
    unsigned long shadow = (unsigned long)mmap(0, 4096, 3 /*RW*/, 0x22, -1, 0);
    if (shadow == (unsigned long)-1) { out_str("mmap-fail\n"); return; }

    /* 代码页原样快照（CRC 自检基准） */
    static unsigned long snap[512];
    for (int i = 0; i < 512; i++)
        snap[i] = ((unsigned long *)code)[i];

    /* v2c 桩：BRK #0xCA0（跷跷板 BRK+单步模型）。
       BRK 在 X-only 页正常执行（指令非数据访问）；
       模块 BRK handler 切 STEPPING 视图（original 可执行 RO）+ 开硬件单步；
       单步异常后切回 SHADOW_X。handler 逻辑全在内核侧。 */
    for (int i = 0; i < 512; i++)
        ((unsigned long *)shadow)[i] = snap[i];
    unsigned long off_in_page = (unsigned long)(void *)caoin_target & 0xFFFUL;
    unsigned int *stub = (unsigned int *)(shadow + off_in_page);
    stub[0] = 0xD4200000u | (0xCA0 << 5);   /* BRK #0xCA0 */
    stub[1] = 0xD503201Fu;                  /* NOP（单步落点） */
    shadow_cache_maint(shadow, 4096);

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
    out_str(" code_phys=");
    out_hex(page_pa(code));
    out_str(" shadow_phys=");
    out_hex(page_pa(shadow));
    out_str(" status_va=");
    out_hex((unsigned long)&g_shadow_status);
    out_str(" status_phys=");
    out_hex(page_pa((unsigned long)&g_shadow_status & ~0xFFFUL));
    out_str("\n");

    /* v2 主循环：三态输出——status / 调用结果（执行视图）/ CRC 自检（读取视图） */
    struct ts t = { 1, 0 };
    for (;;) {
        unsigned long crc_ok = 1;
        for (int i = 0; i < 512; i++)
            if (((unsigned long *)code)[i] != snap[i]) { crc_ok = 0; break; }
        out_str("status=");
        out_hex(g_shadow_status);
        out_str(" caoin_target(5)=");
        out_int(fp(5));
        out_str(" crc_ok=");
        out_int((long)crc_ok);
        out_str("\n");
        nanosleep(&t, 0);
    }
}

static void out_str(const char *s)
{
    long n = 0;
    while (s[n]) n++;
    write(1, s, (unsigned long)n);
}

static void out2_str(const char *s)   /* stderr 路，if0 过滤验证的负样本 */
{
    long n = 0;
    while (s[n]) n++;
    write(2, s, (unsigned long)n);
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
    struct ts t = { 1, 0 };
    /* tdyn4 专用：无条件 shadow 模式（argv 经 linker 启动栈不可靠） */
    shadow_mode();
    for (;;) {
        out_str("caoin_target(5)=");
        out_int(fp(5));
        out_str("\n");
        nanosleep(&t, 0);
    }
}
