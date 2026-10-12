/*
 * agent_dummy（P2.1 验证用）：-nostdlib，纯 syscall shim。
 * constructor 写标记文件，证明 dlopen 成功且初始化代码在目标进程内执行。
 * glibc 运行时的 so 不能注入 bionic 进程，agent 路线必须保持 no-libc。
 */
typedef unsigned long word;

static word sys3(word n, word a, word b, word c)
{
    register word x8 asm("x8") = n;
    register word x0 asm("x0") = a;
    register word x1 asm("x1") = b;
    register word x2 asm("x2") = c;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory", "cc");
    return x0;
}

#define SYS_openat 56
#define SYS_write  64
#define SYS_close  57

__attribute__((constructor))
static void caoin_agent_on_load(void)
{
    const char path[] = "/data/local/tmp/caoin_agent_marker";
    const char msg[] = "caoin-agent-loaded\n";
    word fd = sys3(SYS_openat, (word)-100 /*AT_FDCWD*/, (word)path,
                   0x241 /*O_WRONLY|O_CREAT|O_TRUNC*/);
    if ((long)fd < 0)
        return;
    sys3(SYS_write, fd, (word)msg, sizeof(msg) - 1);
    sys3(SYS_close, fd, 0, 0);
}
