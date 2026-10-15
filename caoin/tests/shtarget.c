/*
 * caoin_prep 全链路测试目标：循环调用 shtarget_func 并打印返回值。
 * 不自备 shadow/status 页（由 caoin_prep 远程准备）——验证"符号解析自动化"
 * 端到端：目标零配合 → 工具解析符号 + 准备页 → KPM arm → 函数行为改变。
 *
 * 编译（同 tdyn4：动态链接 bionic，符号进 .dynsym 供远程解析）：
 *   aarch64-linux-gnu-gcc -Wall -O2 -nostdlib -pie tests/shtarget.c -o build/shtarget \
 *     -Wl,--dynamic-linker=/system/bin/linker64 \
 *     -Wl,--allow-shlib-undefined -Wl,--export-dynamic \
 *     -Lbuild -l:libc_bionic.so
 * 注：静态链接程序的 local 符号在 .symtab（不映射内存），远程不可读——
 *     实战目标是共享库，其导出符号天然在 .dynsym。
 */
extern long write(int, const void *, unsigned long);
extern int getpid(void);
extern unsigned int usleep(unsigned int);

/* 受管页布局：section 页对齐 → 页首 64 字节填充 → 受管函数（off = 64）。
 * caoin-shadow 的跷跷板是页级的：受管页内**被执行**的其他代码会干扰状态机，
 * 故受管函数须"独占页"（tdyn4 用 aligned(4096)+fill）。这里用汇编填充而非
 * 占位函数——占位函数会被编译器重排/删除，填充字节确定可控。 */
asm(".pushsection .shtarget.text, \"ax\"\n.balign 4096\n.fill 64, 1, 0\n.popsection");

/* 受管函数：页内偏移 64（验证 KPM 的 shva_off 自动推导） */
__attribute__((noinline, visibility("default"), section(".shtarget.text")))
long shtarget_func(long x)
{
    return x * 3 + 7;
}

asm(".pushsection .shtarget.text, \"ax\"\n.fill 4000, 1, 0\n.popsection");

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
    out_str("SH pid=");
    out_int((long)getpid());
    out_str(" func=");
    out_hex((unsigned long)(void *)shtarget_func);
    out_str(" off=");
    out_hex((unsigned long)(void *)shtarget_func & 0xFFFUL);
    out_str("\n");
    for (i = 0; ; i++) {
        out_str("call#");
        out_int(i);
        out_str(" shtarget_func(");
        out_int(i);
        out_str(")=");
        out_int(shtarget_func(i));
        out_str("\n");
        usleep(200000);
    }
}
