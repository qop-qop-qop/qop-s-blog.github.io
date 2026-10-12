#ifndef CAOIN_TRAMP_H
#define CAOIN_TRAMP_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    void *target;
    void *tramp;            /* RX 执行视图，语义 = 原 target 实现 */
    void *tramp_rw;         /* RW 写入视图（memfd 双映射；单映射时与 tramp 相同） */
    long tramp_fd;          /* memfd（双映射时），-1 单映射 */
    uint32_t orig[4];       /* 入口原始指令备份 */
    int attached;
} caoin_hook_t;

/*
 * 返回：0 成功；-1 trampoline 就近分配失败；-2 relocator 拒绝（入口模式不可重定位）；
 *      -3 写入口桩失败（mprotect/写入，常见于 SELinux 拒改系统库代码段）
 */
int caoin_hook_attach(void *target, void *handler, caoin_hook_t *h);
int caoin_hook_detach(caoin_hook_t *h);

/* trampoline 强转回原函数类型直接调用 */
#define CAOIN_ORIG(h, fn_type) ((fn_type)(h)->tramp)

#endif
