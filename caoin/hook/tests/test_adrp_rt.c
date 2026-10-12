/*
 * 真机执行级测试 2：ADRP 重定位正确性。
 * 目标函数经 volatile 全局强制生成 ADRP(+LDR) 访问，若 ADRP 重定位错误，
 * 全局读到错误页数据 → 返回值断言失败（语义级验证，非仅"不崩溃"）。
 * 运行时自检：窗口内必须有 ADRP，否则 SKIP（防编译器布局变化造成假通过）。
 */
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include "tramp.h"

static void ill_handler(int sig, siginfo_t *si, void *uc)
{
    ucontext_t *u = uc;
    uint64_t pc = u->uc_mcontext.pc;
    uint32_t *p = (uint32_t *)(uintptr_t)pc;
    fprintf(stderr, "SIGILL pc=%llx lr=%llx sp=%llx\n",
            (unsigned long long)pc,
            (unsigned long long)u->uc_mcontext.regs[30],
            (unsigned long long)u->uc_mcontext.sp);
    for (int i = -2; i <= 3; i++)
        fprintf(stderr, "  %llx: %08x\n",
                (unsigned long long)(pc + 4 * i), p[i]);
    _exit(3);
}

static volatile int g_val = 0x1234;
static volatile long g_l = 0x556677885566LL;
static volatile int g_seen_i;
static volatile long g_seen_l;

__attribute__((noinline))
static long target_adrp(int x)
{
    g_seen_i = g_val;
    g_seen_l = g_l;
    return (long)x + g_seen_i + g_seen_l;
}

static long (*volatile fp)(int) = target_adrp;

static caoin_hook_t hk;
static int hook_calls;

static long handler_adrp(int x)
{
    hook_calls++;
    return CAOIN_ORIG(&hk, long (*)(int))(x) + 100;
}

static int count_adrp(const uint32_t *code)
{
    int n = 0;
    for (int i = 0; i < 4; i++)
        if ((code[i] & 0x9F000000) == 0x90000000)
            n++;
    return n;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    struct sigaction sa = {0};
    sa.sa_sigaction = ill_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGILL, &sa, NULL);
    const uint32_t *code = (const uint32_t *)(void *)target_adrp;
    printf("window: %08x %08x %08x %08x\n", code[0], code[1], code[2], code[3]);

    int nad = count_adrp(code);
    if (nad == 0) {
        puts("SKIP: no ADRP in entry window (recompile with -O2/volatile)");
        return 2;
    }
    printf("ADRP in window: %d\n", nad);

    long before = fp(5);
    if (caoin_hook_attach((void *)target_adrp, handler_adrp, &hk) != 0) {
        puts("ADRP RT FAIL: attach");
        return 1;
    }
    printf("target=%p tramp=%p\n", (void *)target_adrp, hk.tramp);
    uint32_t *tp = (uint32_t *)hk.tramp;
    for (int i = 0; i < 8; i++)
        printf("  tramp[%d]=%08x\n", i, tp[i]);
    long hooked = fp(5);
    int seen_i = g_seen_i;
    long seen_l = g_seen_l;
    caoin_hook_detach(&hk);
    long after = fp(5);

    printf("before=%ld hooked=%ld after=%ld seen_i=%x seen_l=%lx calls=%d\n",
           before, hooked, after, seen_i, seen_l, hook_calls);

    int ok = seen_i == 0x1234
          && seen_l == 0x556677885566LL
          && hooked == before + 100
          && after == before
          && hook_calls == 1;
    puts(ok ? "ADRP RT OK" : "ADRP RT FAIL");
    return ok ? 0 : 1;
}
