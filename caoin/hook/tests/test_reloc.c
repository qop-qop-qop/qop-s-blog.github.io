/*
 * reloc 主机端单测：语义不变量 = PC 相对目标 / literal 数据的绝对地址不变。
 * src_addr / dst_addr 用真实缓冲地址（K_LIT 需要从 literal 地址实读）。
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "reloc.h"

static int fails;
#define CHECK(cond) do { \
    if (!(cond)) { printf("FAIL at line %d\n", __LINE__); fails++; } \
} while (0)

static int64_t sext(uint32_t v, int bits)
{
    uint32_t m = 1u << (bits - 1);
    return (int64_t)((int64_t)(v ^ m) - (int64_t)m);
}

static uint64_t rd64(const void *p) { uint64_t v; memcpy(&v, p, 8); return v; }
static void wr64(void *p, uint64_t v) { memcpy(p, &v, 8); }

int main(void)
{
    uint32_t dst[CAOIN_TRAMP_CAP_INSN];
    int st[CAOIN_TRAMP_INSN];

    /* ---- 1. 标准序言（PACIASP/STP/MOV/普通 LDR）：原样拷贝 + 尾桩 ---- */
    {
        uint32_t src[8] = { 0xD503233F, 0xA9BF7BFD, 0x910003FD, 0xF94003FA };
        uintptr_t sa = (uintptr_t)src, da = (uintptr_t)dst;
        size_t n = caoin_reloc_block(dst, da, src, sa, st);
        CHECK(n == 8);
        CHECK(dst[0] == 0xD503233F && dst[1] == 0xA9BF7BFD && dst[2] == 0x910003FD && dst[3] == 0xF94003FA);
        CHECK(dst[4] == 0x58000050 && dst[5] == 0xD61F0200);
        CHECK(rd64(&dst[6]) == sa + 16);
        CHECK(st[0] == CAOIN_RELOC_COPY && st[1] == CAOIN_RELOC_COPY);
    }

    /* ---- 2. BL +0x100：目标绝对地址不变 ---- */
    {
        uint32_t src[8] = { 0x94000040, 0xA9BF7BFD, 0x910003FD, 0xD503233F };
        uintptr_t sa = (uintptr_t)src, da = (uintptr_t)dst;
        size_t n = caoin_reloc_block(dst, da, src, sa, st);
        CHECK(n == 8);
        CHECK(st[0] == CAOIN_RELOC_FIXED);
        uintptr_t want = sa + 0x100;
        uintptr_t got = da + (uintptr_t)(sext(dst[0] & 0x03FFFFFF, 26) << 2);
        CHECK(got == want);
        CHECK((dst[0] & 0xFC000000) == 0x94000000);      /* 仍是 BL */
    }

    /* ---- 3. ADRP X0, +0x57000：目标页地址不变 ---- */
    {
        uint32_t src[8] = { 0xF00002A0, 0xA9BF7BFD, 0x910003FD, 0xD503233F };
        uintptr_t sa = (uintptr_t)src, da = (uintptr_t)dst;
        size_t n = caoin_reloc_block(dst, da, src, sa, st);
        CHECK(n == 8);
        CHECK(st[0] == CAOIN_RELOC_FIXED);
        uint32_t imm21 = ((((dst[0] >> 5) & 0x7FFFF) << 2) | ((dst[0] >> 29) & 3));
        uintptr_t got = (da & ~(uintptr_t)0xFFF) + (uintptr_t)(sext(imm21, 21) << 12);
        uintptr_t want = (sa & ~(uintptr_t)0xFFF) + 0x57000;
        CHECK(got == want);
        CHECK((dst[0] & 0x9F000000) == 0x90000000);      /* 仍是 ADRP，Rd=0 */
        CHECK((dst[0] & 0x1F) == 0);
    }

    /* ---- 3b. ADRP 负偏移（trampoline 在目标之后，真机 alloc_near 场景） ---- */
    {
        uint32_t src[8] = { 0xF00002A0, 0xA9BF7BFD, 0x910003FD, 0xD503233F };
        uintptr_t sa = (uintptr_t)src, da = (uintptr_t)src + 0x200000;  /* 假地址：dst 视作 +2MB 处 */
        uint32_t dst2[CAOIN_TRAMP_CAP_INSN];
        size_t n = caoin_reloc_block(dst2, da, src, sa, st);
        CHECK(n == 8);
        CHECK(st[0] == CAOIN_RELOC_FIXED);
        CHECK((dst2[0] & 0x9F000000) == 0x90000000);     /* opcode 不被符号位污染 */
        uint32_t imm21 = ((((dst2[0] >> 5) & 0x7FFFF) << 2) | ((dst2[0] >> 29) & 3));
        uintptr_t got = (da & ~(uintptr_t)0xFFF) + (uintptr_t)(sext(imm21, 21) << 12);
        CHECK(got == (sa & ~(uintptr_t)0xFFF) + 0x57000);
    }

    /* ---- 4. CBZ X0, +0x40：目标绝对地址不变 ---- */
    {
        uint32_t src[8] = { 0xD503233F, 0x34000200, 0x910003FD, 0xA9BF7BFD };
        uintptr_t sa = (uintptr_t)src, da = (uintptr_t)dst;
        size_t n = caoin_reloc_block(dst, da, src, sa, st);
        CHECK(n == 8);
        CHECK(st[1] == CAOIN_RELOC_FIXED);
        uintptr_t got = da + 4 + (uintptr_t)(sext((dst[1] >> 5) & 0x7FFFF, 19) << 2);
        CHECK(got == sa + 4 + 0x40);
    }

    /* ---- 5. LDR X0, [pc,+0x10]：literal 数据搬到 trampoline 且值不变 ---- */
    {
        uint32_t src[12];
        memset(src, 0, sizeof(src));
        src[0] = 0xD503233F; src[1] = 0xA9BF7BFD; src[2] = 0x910003FD;
        src[3] = 0x58000080;                      /* LDR X0, #0x10：literal 在指令自身(sa+12)+0x10 = sa+28 */
        wr64(&src[7], 0x1122334455667788ULL);
        uintptr_t sa = (uintptr_t)src, da = (uintptr_t)dst;
        size_t n = caoin_reloc_block(dst, da, src, sa, st);
        CHECK(n > 8);
        CHECK(st[3] == CAOIN_RELOC_LITERAL);
        uintptr_t data = da + 12 + (uintptr_t)(sext((dst[3] >> 5) & 0x7FFFF, 19) << 2);
        CHECK(rd64((void *)data) == 0x1122334455667788ULL);
        /* 尾桩仍指向 src+16 */
        CHECK(rd64(&dst[n - 2]) == sa + 16);
    }

    /* ---- 6. B 目标在被覆盖窗口内：拒绝 ---- */
    {
        uint32_t src[8] = { 0x14000002, 0xA9BF7BFD, 0x910003FD, 0xD503233F };  /* B +0x8 → 目标 src+8，窗口内 */
        uintptr_t sa = (uintptr_t)src, da = (uintptr_t)dst;
        size_t n = caoin_reloc_block(dst, da, src, sa, st);
        CHECK(n == 0);
        CHECK(st[0] == CAOIN_RELOC_UNSUPPORTED);
    }

    /* ---- 6b. B +0x10（跳过序言到窗口后）：合法，目标绝对地址不变 ---- */
    {
        uint32_t src[8] = { 0x14000004, 0xA9BF7BFD, 0x910003FD, 0xD503233F };
        uintptr_t sa = (uintptr_t)src, da = (uintptr_t)dst;
        size_t n = caoin_reloc_block(dst, da, src, sa, st);
        CHECK(n == 8);
        CHECK(st[0] == CAOIN_RELOC_FIXED);
        uintptr_t got = da + (uintptr_t)(sext(dst[0] & 0x03FFFFFF, 26) << 2);
        CHECK(got == sa + 0x10);
    }

    /* ---- 7. 入口桩编码 ---- */
    {
        uint32_t stub[4];
        caoin_make_entry_stub(stub, 0xDEADBEEF00ULL);
        CHECK(stub[0] == 0x58000050 && stub[1] == 0xD61F0200);
        CHECK(rd64(&stub[2]) == 0xDEADBEEF00ULL);
    }

    if (fails) { printf("%d FAILED\n", fails); return 1; }
    printf("all passed\n");
    return 0;
}
