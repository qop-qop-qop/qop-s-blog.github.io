#ifndef MINI_GDB_HEAP_H
#define MINI_GDB_HEAP_H

#include "mini_gdb.h"

/* 遍历 [heap] 段中的 malloc_chunk,打印每个 chunk 的地址、大小、标志位。
   仅支持 glibc x86_64。要求 tracee 处于停下状态。 */
int heap_dump(debugger_t *d, int max_chunks);

/* 打印 tcache_perthread_struct(通常是 [heap] 起始处的第一个 chunk)里
   每个 tcache bin 的 count 和链表头。glibc 2.32+ 会解 safe-linking。 */
int heap_tcache(debugger_t *d);

/* 打印 main_arena 里的 fastbinsY[]、unsorted、small bins、large bins。
   需要能在符号表里找到 main_arena(通常靠 libc6-dbg)。 */
int heap_bins(debugger_t *d);

#endif
