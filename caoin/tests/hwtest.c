/* caoin-hw 测试目标：循环调用 hw_victim 并打印返回值。无握手，纯静态。 */
#include <stdio.h>
#include <unistd.h>

__attribute__((noinline, aligned(4096)))
long hw_victim(long x)
{
    return x * 2 + 1;
}

int main(void)
{
    long i;
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("HWTEST pid=%d victim=%p\n", (int)getpid(), (void *)hw_victim);
    for (i = 0; ; i++) {
        long r = hw_victim(i);
        printf("call#%ld hw_victim(%ld)=%ld\n", i, i, r);
        usleep(200000);
    }
    return 0;
}
