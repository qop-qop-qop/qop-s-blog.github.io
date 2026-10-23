/*
 * 重定位分类器回归：LDR/STR(register) 不得被当成 LDR literal。
 *
 * 旧掩码 0x1F000000 只看 bits[28:24]=11000；LDR/STR(register) 在 V=0 时
 * bits[28:24] 同样是 11000（真正的区别在 bit29：literal 是 011，register 是 111）。
 * 误判后重定位器按 imm19 去读垃圾、并改写指令字段 —— 真机表现是桩装完就崩。
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "reloc.h"

struct blk {
    uint32_t insn[4];
    uint64_t lit;
};

int main(void)
{
    static struct blk b;
    uint32_t dst[CAOIN_TRAMP_CAP_INSN];
    int st[CAOIN_TRAMP_INSN];
    size_t n;
    int ok = 1;

    /* 1) STR x0, [x1, x2, lsl #3] = 0xF8A26820（load/store register 族，V=0） */
    memset(&b, 0, sizeof(b));
    b.insn[0] = 0xF8A26820u;
    b.insn[1] = 0xD503201Fu;    /* nop */
    b.insn[2] = 0xD503201Fu;
    b.insn[3] = 0xD503201Fu;
    n = caoin_reloc_block(dst, (uintptr_t)dst, b.insn, (uintptr_t)b.insn, st);
    printf("STR reg: n=%zu st0=%d dst0=%08x\n", n, st[0], dst[0]);
    if (!n || st[0] != CAOIN_RELOC_COPY || dst[0] != b.insn[0]) ok = 0;

    /* 2) LDR x0, literal（imm19=4 → 数据在 b.lit，即 b.insn+16） */
    memset(&b, 0, sizeof(b));
    b.lit = 0x1122334455667788ULL;
    b.insn[0] = 0x58000000u | (4u << 5);    /* ldr x0, #16 */
    b.insn[1] = 0xD503201Fu;
    b.insn[2] = 0xD503201Fu;
    b.insn[3] = 0xD503201Fu;
    n = caoin_reloc_block(dst, (uintptr_t)dst, b.insn, (uintptr_t)b.insn, st);
    {
        uint64_t got;
        memcpy(&got, &dst[1], sizeof(got));   /* 数据紧随 LDR，位于 dst[1..2] */
        printf("LDR lit: n=%zu st0=%d dst0=%08x data=%016llx\n",
               n, st[0], dst[0], (unsigned long long)got);
        if (got != b.lit) ok = 0;
    }
    if (!n || st[0] != CAOIN_RELOC_LITERAL) ok = 0;

    /* imm19 应重算为指向 dst+4 */
    {
        uint32_t imm19 = (dst[0] >> 5) & 0x7FFFF;
        uintptr_t tgt = (uintptr_t)dst + (uintptr_t)(((int64_t)imm19 << 45) >> 45) * 4;
        if (tgt != (uintptr_t)&dst[1]) ok = 0;
    }

    /* 3) 窗口预扫：STR(register) 不是 PC 相对，LDR literal 是 */
    {
        const uint32_t str_reg[4] = { 0xF8A26820u, 0xD503201Fu, 0xD503201Fu, 0xD503201Fu };
        const uint32_t ldr_lit[4] = { 0x58000040u, 0xD503201Fu, 0xD503201Fu, 0xD503201Fu };
        int w_str = caoin_window_pc_relative(str_reg);
        int w_lit = caoin_window_pc_relative(ldr_lit);
        printf("window: STR reg=%d LDR lit=%d\n", w_str, w_lit);
        if (w_str != 0 || w_lit != 1) ok = 0;
    }

    puts(ok ? "RELOC CLASSIFY OK" : "RELOC CLASSIFY FAIL");
    return ok ? 0 : 1;
}
