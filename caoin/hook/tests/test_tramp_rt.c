/*
 * 真机运行时测试：hook 一个真实函数，验证
 *   1) 调用被劫持到 handler
 *   2) handler 经 trampoline 调原实现，语义不变
 *   3) detach 后行为完全恢复
 * 目标函数刻意写得超过 16 字节（入口桩覆盖窗口）。
 */
#include <stdio.h>
#include "tramp.h"

__attribute__((noinline))
static int target_mix(int x)
{
    int r = x;
    r = r * 2;
    r += 3;
    r ^= 0x55;
    r = r * 2 + 1;
    return r;
}

/* volatile 函数指针调用，防内联/去优化 */
static int (*volatile fp)(int) = target_mix;

static caoin_hook_t hk;
static int hook_calls;
static int last_arg;

static int handler_mix(int x)
{
    hook_calls++;
    last_arg = x;
    return CAOIN_ORIG(&hk, int (*)(int))(x) + 100;
}

int main(void)
{
    int before = fp(5);

    if (caoin_hook_attach((void *)target_mix, handler_mix, &hk) != 0) {
        puts("TRAMP RT FAIL: attach");
        return 1;
    }
    int hooked = fp(5);
    int orig_direct = CAOIN_ORIG(&hk, int (*)(int))(7);
    caoin_hook_detach(&hk);
    int after = fp(5);
    int after7 = target_mix(7);

    printf("before=%d hooked=%d orig(7)=%d after=%d after7=%d calls=%d last_arg=%d\n",
           before, hooked, orig_direct, after, after7, hook_calls, last_arg);

    int ok = hooked == before + 100
          && orig_direct == after7
          && after == before
          && hook_calls == 1
          && last_arg == 5;
    puts(ok ? "TRAMP RT OK" : "TRAMP RT FAIL");
    return ok ? 0 : 1;
}
