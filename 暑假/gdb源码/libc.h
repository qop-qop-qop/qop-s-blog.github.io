#ifndef MINI_GDB_LIBC_H
#define MINI_GDB_LIBC_H

#include "mini_gdb.h"

/* 扫描 /proc/pid/maps 找到 libc.so.6 映射,加载其符号(dynsym + 若有的话 symtab
   或 /usr/lib/debug 里的分离调试文件),按 libc 加载基址补偿,合并到 d->symbols。
   将 libc 加载基址写到 *out_base(可为 NULL)。返回加载符号数,失败返回 -1。 */
int libc_load(debugger_t *d, uint64_t *out_base);

/* 记录已解析出的 libc 上下文,供 bins 使用。 */
typedef struct {
    uint64_t base;              /* libc 加载基址(load_base = start - offset) */
    char path[512];             /* libc.so.6 绝对路径 */
    uint64_t main_arena_addr;   /* 若能定位 main_arena 则填,否则 0 */
    int version_major;          /* glibc 主版本,如 2 */
    int version_minor;          /* glibc 次版本,如 43 */
    int safe_linking;           /* glibc >= 2.32 tcache/fastbin 用 XOR 保护 */
} libc_ctx_t;

/* 检测当前调试会话的 libc 信息;结果缓存在 d 内。ok 时返回同一个指针。 */
const libc_ctx_t *libc_ctx(debugger_t *d);

#endif
