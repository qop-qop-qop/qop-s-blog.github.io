/*
 * poke64 <pid> <hex-va> <hex-val> —— 向目标进程 8 字节写（root）。
 * status 页远控通道写入端。纯 syscall 静态二进制（零 libc 符号——
 * nostdlib 下任何 bionic 调用都会因 TLS 未初始化而崩，真机实证）。
 * 编译：-nostdlib -static -fno-pic（入口 _start，argv 由启动栈 ABI 传递）。
 */
extern int cmain(int argc, char **argv);

__asm__(
".globl _start\n"
"_start:\n"
"    ldr x0, [sp]\n"          /* argc */
"    add x1, sp, #8\n"        /* argv */
"    bl cmain\n"
"    mov x8, #93\n"           /* __NR_exit */
"    svc #0\n"
);

static long sys_openat(const char *path, int flags)
{
    register long x0 __asm__("x0") = -100;   /* AT_FDCWD */
    register long x1 __asm__("x1") = (long)path;
    register long x2 __asm__("x2") = flags;
    register long x3 __asm__("x3") = 0;
    register long x8 __asm__("x8") = 56;     /* __NR_openat */
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3) : "memory", "cc");
    return x0;
}

static long sys_write(int fd, const void *buf, unsigned long len)
{
    register long x0 __asm__("x0") = fd;
    register long x1 __asm__("x1") = (long)buf;
    register long x2 __asm__("x2") = len;
    register long x8 __asm__("x8") = 64;     /* __NR_write */
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2) : "memory", "cc");
    return x0;
}

static long sys_pwrite64(int fd, const void *buf, unsigned long len, long long off)
{
    register long x0 __asm__("x0") = fd;
    register long x1 __asm__("x1") = (long)buf;
    register long x2 __asm__("x2") = len;
    register long x3 __asm__("x3") = off;
    register long x8 __asm__("x8") = 181;    /* __NR_pwrite64 */
    __asm__ volatile("svc #0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3) : "memory", "cc");
    return x0;
}

static void out_str(const char *s)
{
    long n = 0;
    while (s[n]) n++;
    sys_write(2, s, (unsigned long)n);
}

static void out_str_hex(unsigned long v)
{
    char b[19];
    int n = 0, d = 0;
    char t[16];
    do { t[d++] = (char)('0' + v % 16); v /= 16; } while (v);
    b[n++] = '0';
    b[n++] = 'x';
    while (d) b[n++] = t[--d];
    sys_write(2, b, (unsigned long)n);
}

static unsigned long long hexs(const char *s)
{
    unsigned long long v = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;
    for (;; s++) {
        char c = *s;
        if (c >= '0' && c <= '9') v = v * 16 + (unsigned long long)(c - '0');
        else if (c >= 'a' && c <= 'f') v = v * 16 + (unsigned long long)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v = v * 16 + (unsigned long long)(c - 'A' + 10);
        else break;
    }
    return v;
}

int cmain(int argc, char **argv)
{
    char path[64];
    char *p, *q;
    unsigned long long va, val;
    long fd, r;

    if (argc < 4) {
        out_str("usage: poke64 <pid> <hex-va> <hex-val>\n");
        return 1;
    }
    p = path;
    q = "/proc/";
    while (*q) *p++ = *q++;
    q = argv[1];
    while (*q) *p++ = *q++;
    q = "/mem";
    while (*q) *p++ = *q++;
    *p = 0;

    va = hexs(argv[2]);
    val = hexs(argv[3]);

    fd = sys_openat(path, 2 /*O_RDWR*/);
    if (fd < 0) {
        out_str("open fail r=");
        out_str_hex((unsigned long)-fd);
        out_str("\n");
        return 2;
    }
    r = sys_pwrite64((int)fd, &val, 8, (long long)va);
    if (r != 8) {
        out_str("pwrite fail\n");
        return 3;
    }
    return 0;
}
