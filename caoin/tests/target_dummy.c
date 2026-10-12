/* 注入测试目标：打印 pid 后静睡，等被注入 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("target pid=%d\n", (int)getpid());
    for (;;)
        pause();
    return 0;
}
