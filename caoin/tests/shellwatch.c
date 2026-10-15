/*
 * shellwatch — "ll 壳"双层检测模拟目标（验证 caoin 对抗能力）
 *
 * 模拟真实加固壳的两类检测：
 *   ① 代码段 CRC 自检：定期算受管函数所在页的校验和（防 inline hook 改字节）
 *   ② maps 扫描：统计可执行映射数 + 找可疑项（/data/ 路径、/memfd: 映射）
 *   ③ TracerPid：读 /proc/self/status（防 ptrace 附加）
 * 循环调用受管函数并输出检测结果，供 caoin 各路线（shadow / agent）对照。
 *
 * 受管函数独占页（页内偏移 64）——满足 caoin-shadow 的页级独占约束。
 *
 * 编译（同 shtarget：动态链接 bionic，符号进 .dynsym）：
 *   aarch64-linux-gnu-gcc -Wall -O2 -nostdlib -pie tests/shellwatch.c -o build/shellwatch \
 *     -Wl,--dynamic-linker=/system/bin/linker64 \
 *     -Wl,--allow-shlib-undefined -Wl,--export-dynamic \
 *     -Lbuild -l:libc_bionic.so
 */
extern long write(int, const void *, unsigned long);
extern int getpid(void);
extern unsigned int usleep(unsigned int);
extern int open(const char *, int, ...);
extern long read(int, void *, unsigned long);
extern int close(int);

asm(".pushsection .sw.text, \"ax\"\n.balign 4096\n.fill 64, 1, 0\n.popsection");

/* 受管函数：页内偏移 64，独占页（页内其余为不执行的填充） */
__attribute__((noinline, visibility("default"), section(".sw.text")))
long sw_target(long x)
{
    return x * 5 + 11;
}

asm(".pushsection .sw.text, \"ax\"\n.fill 4000, 1, 0\n.popsection");

static unsigned long sw_page(void)
{
    return (unsigned long)(void *)sw_target & ~0xFFFUL;
}

/* ① 代码段 CRC：对受管页做滚动校验和（壳的完整性自检） */
static unsigned long sw_crc(void)
{
    volatile unsigned long *p = (volatile unsigned long *)sw_page();
    unsigned long s = 0;
    int i;
    for (i = 0; i < 512; i++)
        s = s * 31 + p[i];
    return s;
}

static char g_maps[256 * 1024];

/* ② maps 扫描：可执行映射数 / 可疑路径数（/data/ 或 /memfd:） */
static void sw_scan(long *nexec, long *nsusp, long *nmemfd)
{
    long fd = open("/proc/self/maps", 0), total = 0, n;
    char *p, *nl;

    *nexec = *nsusp = *nmemfd = 0;
    if (fd < 0)
        return;
    while (total < (long)sizeof(g_maps) - 1) {
        n = read((int)fd, g_maps + total, (unsigned long)(sizeof(g_maps) - 1 - total));
        if (n <= 0) break;
        total += n;
    }
    close((int)fd);
    g_maps[total] = 0;

    for (p = g_maps; *p; p = (*nl) ? nl + 1 : nl) {
        int exec = 0, susp = 0, memfd = 0;
        char *q;
        for (nl = p; *nl && *nl != '\n'; nl++) ;
        for (q = p; q < nl; q++) {
            if (q + 3 <= nl && q[0] == 'r' && q[1] == '-' && q[2] == 'x')
                exec = 1;
            if (q + 6 <= nl && q[0] == '/' && q[1] == 'd' && q[2] == 'a' &&
                q[3] == 't' && q[4] == 'a' && q[5] == '/')
                susp = 1;
            if (q + 6 <= nl && q[0] == '/' && q[1] == 'm' && q[2] == 'e' &&
                q[3] == 'm' && q[4] == 'f' && q[5] == 'd')
                memfd = 1;
        }
        if (exec) (*nexec)++;
        if (susp) (*nsusp)++;
        if (memfd) (*nmemfd)++;
    }
}

/* ③ TracerPid：读 /proc/self/status */
static long sw_tracer(void)
{
    long fd = open("/proc/self/status", 0);
    char b[1024];
    long n, i, v = 0;
    if (fd < 0) return -1;
    n = read((int)fd, b, sizeof(b) - 1);
    close((int)fd);
    if (n <= 0) return -1;
    b[n] = 0;
    for (i = 0; i + 10 < n; i++) {
        if (b[i] == 'T' && b[i + 1] == 'r' && b[i + 2] == 'a' && b[i + 3] == 'c' &&
            b[i + 4] == 'e' && b[i + 5] == 'r' && b[i + 6] == 'P' && b[i + 7] == 'i' &&
            b[i + 8] == 'd') {
            long j = i + 10;
            while (j < n && (b[j] < '0' || b[j] > '9')) j++;
            while (j < n && b[j] >= '0' && b[j] <= '9') v = v * 10 + (b[j++] - '0');
            break;
        }
    }
    return v;
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

void _start(void)
{
    long i;
    unsigned long base_crc;

    out_str("SW pid=");
    out_int((long)getpid());
    out_str(" target=");
    out_hex((unsigned long)(void *)sw_target);
    out_str(" off=");
    out_hex((unsigned long)(void *)sw_target & 0xFFFUL);
    out_str("\n");

    base_crc = sw_crc();   /* 基线 CRC（注入前的代码页校验和） */

    for (i = 0; ; i++) {
        long nexec, nsusp, nmemfd;
        unsigned long crc = sw_crc();
        sw_scan(&nexec, &nsusp, &nmemfd);
        out_str("call#");
        out_int(i);
        out_str(" sw_target(");
        out_int(i);
        out_str(")=");
        out_int(sw_target(i));
        out_str(" crc=");
        out_str(crc == base_crc ? "ok" : "CHANGED");
        out_str(" exec=");
        out_int(nexec);
        out_str(" susp=");
        out_int(nsusp);
        out_str(" memfd=");
        out_int(nmemfd);
        out_str(" tracer=");
        out_int(sw_tracer());
        out_str("\n");
        usleep(300000);
    }
}
