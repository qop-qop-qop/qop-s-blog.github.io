#ifndef CAOIN_RELOC_H
#define CAOIN_RELOC_H

#include <stdint.h>
#include <stddef.h>

/* 入口桩覆盖的指令数：LDR X16,#8; BR X16; <addr64> = 16 字节 */
#define CAOIN_TRAMP_INSN 4

/* trampoline 最大指令数：重定位指令 + 尾桩 4 条 + LDR literal 搬迁数据余量 */
#define CAOIN_TRAMP_CAP_INSN 16

typedef enum {
    CAOIN_RELOC_COPY = 0,       /* 非 PC 相对，原样拷贝 */
    CAOIN_RELOC_FIXED = 1,      /* PC 相对偏移已按新地址重写 */
    CAOIN_RELOC_LITERAL = 2,    /* LDR literal，数据已搬入 trampoline */
    CAOIN_RELOC_UNSUPPORTED = -1, /* 结构无法安全重定位（窗口内分支目标等） */
    CAOIN_RELOC_RANGE = -2,     /* 重写后偏移超出编码范围 */
} caoin_reloc_status;

/*
 * 把 src 处 CAOIN_TRAMP_INSN 条指令重定位到 dst，并追加跳回 src+16 的尾桩。
 * 语义不变量：所有 PC 相对目标/literal 数据的绝对地址不变。
 *
 * src     目标函数入口（被覆盖的 4 条指令）
 * dst     trampoline 缓冲（至少 CAOIN_TRAMP_CAP_INSN 条）
 * 返回写入的指令总数（含尾桩），0 = 失败；out_status 回填每条源指令的处理结果。
 */
size_t caoin_reloc_block(uint32_t *dst, uintptr_t dst_addr,
                         const uint32_t *src, uintptr_t src_addr,
                         int out_status[CAOIN_TRAMP_INSN]);

/* 入口桩：LDR X16,#8; BR X16; <handler> 共 4 条，写入目标函数头 */
void caoin_make_entry_stub(uint32_t dst[CAOIN_TRAMP_INSN], uintptr_t handler);

/* 预扫：窗口内含 PC 相对指令（B/BL/ADR/ADRP/条件分支/literal）则非 0。
 * trampoline 远近分配的依据——只有这类指令才有 trampoline 距离约束。 */
int caoin_window_pc_relative(const uint32_t *src);

#endif
