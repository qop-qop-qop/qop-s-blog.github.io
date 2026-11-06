/* kpmctl — KPM ctl0 supercall 客户端（nostdlib 纯 svc，静态 aarch64）
 *
 * 本机 kpatch 精简版没有 kpm ctl0 子命令，capture dump 走这里。
 *
 * 用法: kpmctl <superkey> <module> "<ctl_args>" [outlen]
 *   stdout 输出 out_msg 内容，exit 码 = supercall 返回值。
 * 例: kpmctl su caoin-shadow "dump 0 10000" 65536 > cap.bin
 *     kpmctl su caoin-shadow "capinfo"            # 统计走 dmesg
 *
 * 真机坑：本机 4.9 内核拒绝/错映射 filesz=0 的 .bss PT_LOAD（进程入口即
 * segfault，实测）。所以这里零未初始化静态存储——dump 缓冲运行时 mmap，
 * 小缓冲放栈上（显式初始化）。
 */
#define __NR_supercall 45

#define SUPERCALL_KPM_CONTROL 0x1022

/* 与 tools/kpatch/kpatch.c 完全一致的编码（真机 hello 已验证可用） */
#define KP_MAJOR 0
#define KP_MINOR 12
#define KP_PATCH 3

/* aarch64 Linux 进程入口：sp[0]=argc, sp[8..]=argv[]；转发给 C main */
__asm__(".global _start\n"
        "_start:\n"
        "   ldr x0, [sp]\n"
        "   add x1, sp, #8\n"
        "   b kpm_main\n");

static long ver_and_cmd(long cmd)
{
    unsigned int ver = (KP_MAJOR << 16) | (KP_MINOR << 8) | KP_PATCH;
    return ((long)ver << 32) | (0x1158L << 16) | (cmd & 0xFFFF);
}

static long sys_call6(long n, long a, long b, long c, long d, long e, long f)
{
    register long x8 __asm__("x8") = n;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
}

static void sys_exit(long code)
{
    sys_call6(93, code, 0, 0, 0, 0, 0);
    for (;;)
        ;
}

static long sys_write(int fd, const void *buf, unsigned long n)
{
    return sys_call6(64, fd, (long)buf, n, 0, 0, 0);
}

static void *sys_mmap_anon(unsigned long len)
{
    long r = sys_call6(222, 0, (long)len, 3L /* PROT_RW */,
                       0x22L /* MAP_PRIVATE|MAP_ANONYMOUS */, -1L, 0);
    if (r < 0)
        return 0;
    return (void *)r;
}

/* poke <pid> <hex-va> <hex-val>：向 /proc/pid/mem 偏移 va 写 8 字节。
 * 用于 status 页远控写（INJ_REQ 等）。走 GUP，会触发内核原生 fault 路径。 */
static unsigned long parse_hex(const char *p);

static int do_poke(const char *pid, const char *va_s, const char *val_s)
{
    char path[48];
    unsigned long va = parse_hex(va_s);
    unsigned long val = parse_hex(val_s);
    long fd, r;
    unsigned long i;

    /* /proc/<pid>/mem 拼接 */
    {
        static const char p1[] = "/proc/";
        static const char p2[] = "/mem";
        unsigned long n = 0, m;
        for (i = 0; i < sizeof(p1) - 1; i++) path[n++] = p1[i];
        for (m = 0; pid[m] && n < sizeof(path) - 8; m++) path[n++] = pid[m];
        for (i = 0; i < sizeof(p2) - 1 && n < sizeof(path) - 1; i++) path[n++] = p2[i];
        path[n] = 0;
    }
    fd = sys_call6(56 /* openat */, -100L /* AT_FDCWD */, (long)path,
                   2L /* O_RDWR */, 0, 0, 0);
    if (fd < 0)
        sys_exit((long)(-fd) & 0xff);
    /* status 变量在页首：直接写 va 处 8 字节 */
    r = sys_call6(68 /* pwrite64 */, fd, (long)&val, 8, (long)va, 0, 0);
    sys_call6(57 /* close */, fd, 0, 0, 0, 0, 0);
    sys_exit(r == 8 ? 0 : ((long)-r) & 0xff);
}

static unsigned long slen(const char *s)
{
    unsigned long n = 0;
    while (s[n])
        n++;
    return n;
}

/* cow <superkey> <module> <pid> <hex-tva>：COW bake-in。
 * 经 ctl0 read 读 16 字节（目标 mm 页表 walk → 影子页上的入口桩），
 * 再向同一 VA 写回相同字节，强制内核原生 COW 换页 + flush_tlb_page。
 * 用途：旧 KPM（无 per-CPU 懒安装）跨核可见性的兜底修复；
 * 新 KPM 的 __switch_to 懒安装已覆盖，--cow 可不用。 */
static int do_cow(const char *key, const char *mod, const char *pid,
                  const char *tva_s, char *out_buf)
{
    char path[48];
    char ctl[64];
    unsigned long tva = parse_hex(tva_s);
    unsigned long i, n = 0, m;
    long ret, fd, r;

    /* ctl_args = "read <tva> 10"（内核按 hex 解析长度：10 = 16 字节） */
    {
        static const char r1[] = "read ";
        for (i = 0; i < sizeof(r1) - 1; i++) ctl[n++] = r1[i];
        for (m = 0; tva_s[m] && n < sizeof(ctl) - 8; m++) ctl[n++] = tva_s[m];
        ctl[n++] = ' ';
        ctl[n++] = '1';
        ctl[n++] = '0';
        ctl[n] = 0;
    }
    ret = sys_call6(__NR_supercall, (long)key,
                    ver_and_cmd(SUPERCALL_KPM_CONTROL),
                    (long)mod, (long)ctl, (long)out_buf, 0x10);
    if (ret != 0x10)
        sys_exit(0x40);            /* 读失败：桩未装 / VA 不对 / 视图未翻 */

    {
        static const char p1[] = "/proc/";
        static const char p2[] = "/mem";
        n = 0;
        for (i = 0; i < sizeof(p1) - 1; i++) path[n++] = p1[i];
        for (m = 0; pid[m] && n < sizeof(path) - 8; m++) path[n++] = pid[m];
        for (i = 0; i < sizeof(p2) - 1 && n < sizeof(path) - 1; i++) path[n++] = p2[i];
        path[n] = 0;
    }
    fd = sys_call6(56 /* openat */, -100L /* AT_FDCWD */, (long)path,
                   2L /* O_RDWR */, 0, 0, 0);
    if (fd < 0)
        sys_exit((long)(-fd) & 0xff);
    r = sys_call6(68 /* pwrite64 */, fd, (long)out_buf, 16, (long)tva, 0, 0);
    sys_call6(57 /* close */, fd, 0, 0, 0, 0, 0);
    sys_exit(r == 16 ? 0 : ((long)-r) & 0xff);
}

static unsigned long parse_hex(const char *p)
{
    unsigned long v = 0;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        p += 2;
    for (;; p++) {
        char c = *p;
        if (c >= '0' && c <= '9') { v = v * 16 + (c - '0'); continue; }
        if (c >= 'a' && c <= 'f') { v = v * 16 + (c - 'a' + 10); continue; }
        if (c >= 'A' && c <= 'F') { v = v * 16 + (c - 'A' + 10); continue; }
        break;
    }
    return v;
}

/* ---- mstat pretty print（结构镜像 caoin_kpm.c mstat v4，magic 校验）---- */
#define MP_MAGIC 0xCA0F6554UL
#define MP_MAX_HOOKS 4
#define MP_LOG 16

struct mp_st {
    unsigned long magic;
    unsigned long mprot_hits, madv_hits, munmap_hits, mmap_hits, mdeny_hits;
    unsigned long which, addr, len, arg2, ret;
    unsigned long hit_view[MP_MAX_HOOKS];
    unsigned long now_view[MP_MAX_HOOKS];
    unsigned long seq, jiffies_now, nrec;
    struct {
        unsigned long ts, which, addr, len, arg2, ret, view, denied;
    } rec[MP_LOG];
};

static char *put_str(char *b, const char *s)
{
    while (*s)
        *b++ = *s++;
    return b;
}

static char *put_u64_dec(char *b, unsigned long v)
{
    char tmp[24];
    int n = 0;
    do {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    } while (v);
    while (n)
        *b++ = tmp[--n];
    return b;
}

static char *put_u64_hex(char *b, unsigned long v)
{
    static const char hc[] = "0123456789abcdef";
    int i, started = 0;

    *b++ = '0';
    *b++ = 'x';
    for (i = 60; i >= 4; i -= 4) {
        char c = hc[(v >> i) & 0xF];
        if (c != '0')
            started = 1;
        if (started)
            *b++ = c;
    }
    *b++ = hc[v & 0xF];            /* 最低 nibble 恒输出（v=0 → "0x0"） */
    return b;
}

static char *put_s64_dec(char *b, long v)
{
    unsigned long u;

    if (v < 0) {
        *b++ = '-';
        u = (unsigned long)(-v);
    } else {
        u = (unsigned long)v;
    }
    return put_u64_dec(b, u);
}

static const char *which_s(unsigned long w)
{
    return w == 4 ? "munmap" : w == 3 ? "mmap"
         : w == 2 ? "madvise" : w == 1 ? "mprotect" : "-";
}

static void print_mstat(const struct mp_st *st)
{
    char buf[2048];
    char *b = buf;
    unsigned long i;

    b = put_str(b, "mstat: mprot=");
    b = put_u64_dec(b, st->mprot_hits);
    b = put_str(b, " madv=");
    b = put_u64_dec(b, st->madv_hits);
    b = put_str(b, " munmap=");
    b = put_u64_dec(b, st->munmap_hits);
    b = put_str(b, " mmap=");
    b = put_u64_dec(b, st->mmap_hits);
    b = put_str(b, " denied=");
    b = put_u64_dec(b, st->mdeny_hits);
    b = put_str(b, " seq=");
    b = put_u64_dec(b, st->seq);
    b = put_str(b, " now_jiffies=");
    b = put_u64_dec(b, st->jiffies_now);
    *b++ = '\n';

    for (i = 0; i < st->nrec && i < MP_LOG; i++) {
        if ((char *)b + 160 > buf + sizeof(buf))
            break;
        b = put_str(b, "  #");
        b = put_u64_dec(b, st->seq - st->nrec + i + 1);
        b = put_str(b, " ts=");
        b = put_u64_dec(b, st->rec[i].ts);
        b = put_str(b, " ");
        b = put_str(b, which_s(st->rec[i].which));
        b = put_str(b, " addr=");
        b = put_u64_hex(b, st->rec[i].addr);
        b = put_str(b, " len=");
        b = put_u64_hex(b, st->rec[i].len);
        b = put_str(b, " arg2=");
        b = put_u64_hex(b, st->rec[i].arg2);
        b = put_str(b, " ret=");
        b = put_s64_dec(b, (long)st->rec[i].ret);
        b = put_str(b, " view=");
        b = put_u64_dec(b, st->rec[i].view);
        if (st->rec[i].denied)
            b = put_str(b, " DENIED");
        *b++ = '\n';
    }
    sys_write(1, buf, (unsigned long)(b - buf));
}

/* ctl_args == "mstat" 且出参 magic 匹配 → pretty print；否则透传二进制 */
static void maybe_print_mstat(const char *ctl_args, const char *out_buf,
                              long ret)
{
    const struct mp_st *st = (const void *)out_buf;

    if (ctl_args[0] != 'm' || ctl_args[1] != 's' || ctl_args[2] != 't'
        || ctl_args[3] != 'a' || ctl_args[4] != 't' || ctl_args[5])
        return;
    if (ret != (long)sizeof(*st) || st->magic != MP_MAGIC)
        return;
    print_mstat(st);
    sys_exit(0);
}

int kpm_main(long argc, char **argv)
{
    static const char usage[] =
        "usage: kpmctl <superkey> <module> \"<ctl_args>\" [outlen]\n"
        "       kpmctl p <pid> <hex-va> <hex-val>\n"
        "       kpmctl cow <superkey> <module> <pid> <hex-tva>\n";
    char key_buf[32];
    char mod_buf[64];
    char args_buf[256];
    unsigned long outlen;
    char *out_buf;
    long ret;
    unsigned long i;

    if (argc >= 5 && argv[1][0] == 'p' && argv[1][1] == 0) {
        do_poke(argv[2], argv[3], argv[4]);
    }
    if (argc >= 6 && argv[1][0] == 'c' && argv[1][1] == 'o'
        && argv[1][2] == 'w' && argv[1][3] == 0) {
        out_buf = sys_mmap_anon(4096);
        if (!out_buf)
            sys_exit(3);
        do_cow(argv[2], argv[3], argv[4], argv[5], out_buf);
    }
    if (argc < 4) {
        sys_write(2, usage, sizeof(usage) - 1);
        sys_exit(2);
    }
    for (i = 0; i < sizeof(key_buf) - 1 && argv[1][i]; i++) key_buf[i] = argv[1][i];
    key_buf[i] = 0;
    for (i = 0; i < sizeof(mod_buf) - 1 && argv[2][i]; i++) mod_buf[i] = argv[2][i];
    mod_buf[i] = 0;
    for (i = 0; i < sizeof(args_buf) - 1 && argv[3][i]; i++) args_buf[i] = argv[3][i];
    args_buf[i] = 0;

    outlen = (argc > 4) ? parse_hex(argv[4]) : 0;
    if (outlen < 4096)
        outlen = 4096;
    out_buf = sys_mmap_anon(outlen);
    if (!out_buf)
        sys_exit(3);

    /* supercall(key, ver_and_cmd(KPM_CONTROL), name, ctl_args, out_msg, outlen) */
    ret = sys_call6(__NR_supercall, (long)key_buf,
                    ver_and_cmd(SUPERCALL_KPM_CONTROL),
                    (long)mod_buf, (long)args_buf,
                    (long)out_buf, (long)outlen);
    if (ret > 0) {
        maybe_print_mstat(args_buf, out_buf, ret);
        sys_write(1, out_buf, (unsigned long)ret);
    }
    sys_exit(ret);
}
