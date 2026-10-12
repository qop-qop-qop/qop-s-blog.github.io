#ifndef CAOIN_SYMSOLVE_H
#define CAOIN_SYMSOLVE_H

#include <stdint.h>

/*
 * 本进程符号解析（no-libc，agent 内用）：
 * /proc/self/maps 找模块基址 + 内存直读 ELF dynsym 找符号。
 * 返回符号运行时地址，0 = 未找到。
 */
uintptr_t caoin_resolve(const char *module_pat, const char *symbol);

/* 模块基址；pat==NULL 或 "@" 表示主程序（第一个文件映射）。0 = 未找到。 */
uintptr_t caoin_module_base(const char *pat);

#endif
