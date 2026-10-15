/*
 * caoin_reloc.c — KPM 侧 arm64 指令重定位器（从 hook/reloc.c 移植）
 *
 * 为什么移植而不是共用：KPM 的构建带 -nostdinc（reloc.h/platform.h 顶部的
 * <stdint.h>/<stddef.h> 解析不了），而且原版 caoin_memcpy 会**直接解引用用户 VA**
 * 去读 LDR literal 的数据 —— KPM 在 EL1，SW_TTBR0_PAN 下必 fault（README 有记录）。
 *
 * 这份移植相对原版只有两处刻意改动：
 *   1. 类型改用 KP 的 u32/s64/unsigned long（不依赖 stdint.h/stddef.h）
 *   2. 所有"读目标进程 VA"一律走 caoin_kpm_read_va()（由 caoin_kpm.c 提供：
 *      受管页 VA 重定向到影子页线性地址，其余用 probe_read 安全读，失败即放弃）
 * 重定位语义与原版逐条一致：保持 PC 相对目标的**绝对地址**不变。
 *
 * 覆盖范围与原版相同：B/BL(imm26)、ADR/ADRP(imm21)、CBZ/CBNZ(imm19)、
 * TBZ/TBNZ(imm14)、LDR/PRFM literal(imm19，数据搬入 trampoline)；
 * 其余指令无 PC 依赖，原样拷贝。窗口内的分支目标保守拒绝（返回 0）。
 */

#include <ktypes.h>

#define CAOIN_TRAMP_INSN      4    /* 入口桩覆盖 16 字节 = 4 条指令 */
#define CAOIN_TRAMP_CAP_INSN  16   /* trampoline 容量：4 条 + 尾桩 4 条 + literal 余量 */

#define CAOIN_RELOC_COPY        0
#define CAOIN_RELOC_FIXED       1
#define CAOIN_RELOC_LITERAL     2
#define CAOIN_RELOC_UNSUPPORTED (-1)
#define CAOIN_RELOC_RANGE       (-2)
#define CAOIN_RELOC_READFAIL    (-3)

/* caoin_kpm.c 提供：把目标进程 va 处的 n 字节安全读到 dst。
 * 0 = 成功；非 0 = 失败（调用方须放弃重定位）。 */
extern int caoin_kpm_read_va(void *dst, unsigned long va, unsigned long n);

static s64 caoin_sext(u32 v, int bits)
{
    u32 m = 1u << (bits - 1);
    return (s64)((s64)(v ^ m) - (s64)m);
}

/* 指令分类（armv8 ARM DDI 0487） */
enum {
    K_OTHER = 0,
    K_B,        /* B / BL */
    K_ADR,      /* ADR / ADRP */
    K_CB,       /* CBZ / CBNZ */
    K_TB,       /* TBZ / TBNZ */
    K_LIT,      /* LDR/PRFM literal */
};

static int caoin_classify(u32 insn)
{
    if ((insn & 0x7C000000) == 0x14000000) return K_B;
    if ((insn & 0x1F000000) == 0x10000000) return K_ADR;
    if ((insn & 0x7E000000) == 0x34000000) return K_CB;
    if ((insn & 0x7E000000) == 0x36000000) return K_TB;
    if ((insn & 0x1F000000) == 0x18000000) return K_LIT;
    return K_OTHER;
}

#define GET_IMM19(i)    (((i) >> 5) & 0x7FFFF)
#define PUT_IMM19(i, v) (((i) & ~0x00FFFFE0u) | (((u32)(v) & 0x7FFFF) << 5))
#define GET_IMM26(i)    ((i) & 0x03FFFFFF)
#define PUT_IMM26(i, v) (((i) & ~0x03FFFFFFu) | ((u32)(v) & 0x03FFFFFF))
#define GET_IMM14(i)    (((i) >> 5) & 0x3FFF)
#define PUT_IMM14(i, v) (((i) & ~0x0007FFE0u) | (((u32)(v) & 0x3FFF) << 5))

static int caoin_fit(s64 v, s64 lo, s64 hi)
{
    return v >= lo && v <= hi;
}

/* LDR literal 的数据宽度：opc=bits[31:30]，V=bit29 */
static unsigned long caoin_lit_width(u32 insn)
{
    u32 opc = insn >> 30;
    if ((insn >> 29) & 1) {
        if (opc == 2) return 16;        /* LDR Qt */
        return 4;                       /* LDR St */
    }
    switch (opc) {
    case 0:  return 4;                  /* LDR Wt */
    case 1:  return 8;                  /* LDR Xt */
    default: return 8;                  /* LDRSW 实读 4B 搬 8B 无害；PRFM 8B */
    }
}

/* 纯字节拷贝（内核地址之间，不需要任何保护） */
static void caoin_kcopy(void *dst, const void *src, unsigned long n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--)
        *d++ = *s++;
}

/*
 * 把 src 处 CAOIN_TRAMP_INSN 条指令重定位到 dst，并追加跳回 src+16 的尾桩。
 * 语义不变量：所有 PC 相对目标 / literal 数据的绝对地址不变。
 * 返回写入的指令总数（含尾桩）；0 = 失败（out_status 给出每条的原因）。
 */
unsigned long caoin_reloc_block(u32 *dst, unsigned long dst_addr,
                                const u32 *src, unsigned long src_addr,
                                int out_status[CAOIN_TRAMP_INSN])
{
    unsigned long n = 0;
    int i;

    for (i = 0; i < CAOIN_TRAMP_INSN; i++) {
        u32 insn = src[i];
        unsigned long old_pc = src_addr + (unsigned long)i * 4;
        unsigned long new_pc = dst_addr + n * 4;
        out_status[i] = CAOIN_RELOC_COPY;

        switch (caoin_classify(insn)) {
        case K_B: {
            unsigned long target =
                old_pc + (unsigned long)(caoin_sext(GET_IMM26(insn), 26) << 2);
            s64 off;
            if (target >= src_addr && target < src_addr + CAOIN_TRAMP_INSN * 4) {
                out_status[i] = CAOIN_RELOC_UNSUPPORTED;  /* 目标在被覆盖窗口内 */
                return 0;
            }
            off = (s64)target - (s64)new_pc;
            if (!caoin_fit(off, -(1LL << 27), (1LL << 27) - 4)) {
                out_status[i] = CAOIN_RELOC_RANGE;
                return 0;
            }
            dst[n++] = PUT_IMM26(insn, (u32)(off >> 2));
            out_status[i] = CAOIN_RELOC_FIXED;
            break;
        }
        case K_ADR: {
            int is_adrp = (insn >> 31) & 1;
            u32 imm21 = ((((insn >> 5) & 0x7FFFF) << 2) | ((insn >> 29) & 3));
            unsigned long base = is_adrp ? (old_pc & ~0xFFFUL) : old_pc;
            unsigned long target =
                base + (unsigned long)(caoin_sext(imm21, 21) << (is_adrp ? 12 : 0));
            unsigned long new_base = is_adrp ? (new_pc & ~0xFFFUL) : new_pc;
            s64 off = (s64)target - (s64)new_base;
            s64 lim = is_adrp ? (4LL << 30) : (1LL << 20);
            u32 s21, v;
            if (!caoin_fit(off, -lim, lim - 1)) {
                out_status[i] = CAOIN_RELOC_RANGE;
                return 0;
            }
            /* imm21 有符号：负偏移须截断到低 21 位，防符号位污染 opcode */
            s21 = (u32)(off >> (is_adrp ? 12 : 0)) & 0x1FFFFFu;
            v = ((s21 >> 2) << 5) | ((s21 & 3) << 29);
            dst[n++] = (insn & ~((0x60000000u) | (0x7FFFFu << 5))) | v;
            out_status[i] = CAOIN_RELOC_FIXED;
            break;
        }
        case K_CB: {
            unsigned long target =
                old_pc + (unsigned long)(caoin_sext(GET_IMM19(insn), 19) << 2);
            s64 off;
            if (target >= src_addr && target < src_addr + CAOIN_TRAMP_INSN * 4) {
                out_status[i] = CAOIN_RELOC_UNSUPPORTED;
                return 0;
            }
            off = (s64)target - (s64)new_pc;
            if (!caoin_fit(off, -(1LL << 20), (1LL << 20) - 4)) {
                out_status[i] = CAOIN_RELOC_RANGE;
                return 0;
            }
            dst[n++] = PUT_IMM19(insn, (u32)(off >> 2));
            out_status[i] = CAOIN_RELOC_FIXED;
            break;
        }
        case K_TB: {
            unsigned long target =
                old_pc + (unsigned long)(caoin_sext(GET_IMM14(insn), 14) << 2);
            s64 off;
            if (target >= src_addr && target < src_addr + CAOIN_TRAMP_INSN * 4) {
                out_status[i] = CAOIN_RELOC_UNSUPPORTED;
                return 0;
            }
            off = (s64)target - (s64)new_pc;
            if (!caoin_fit(off, -(1LL << 15), (1LL << 15) - 4)) {
                out_status[i] = CAOIN_RELOC_RANGE;
                return 0;
            }
            dst[n++] = PUT_IMM14(insn, (u32)(off >> 2));
            out_status[i] = CAOIN_RELOC_FIXED;
            break;
        }
        case K_LIT: {
            /* literal 数据紧随当前写入位置追加，重算 imm19 指向它。
             * 数据来自目标进程 —— 走 caoin_kpm_read_va（EL1 不能直接解引用用户 VA）。 */
            unsigned long target =
                old_pc + (unsigned long)(caoin_sext(GET_IMM19(insn), 19) << 2);
            unsigned long w = caoin_lit_width(insn);
            s64 off;
            if (n + 1 + (w / 4) + 4 > CAOIN_TRAMP_CAP_INSN) {
                out_status[i] = CAOIN_RELOC_RANGE;
                return 0;
            }
            off = (s64)(dst_addr + (n + 1) * 4) - (s64)new_pc;
            dst[n++] = PUT_IMM19(insn, (u32)(off >> 2));
            if (caoin_kpm_read_va(&dst[n], target, w)) {
                out_status[i] = CAOIN_RELOC_READFAIL;
                return 0;
            }
            n += w / 4;
            out_status[i] = CAOIN_RELOC_LITERAL;
            break;
        }
        default:
            dst[n++] = insn;
            break;
        }
    }

    /* 尾桩：跳回 src_addr + 16。
     * 刻意不用 `LDR X16,#8; BR X16; <addr>`（原版 agent 的写法）——那个 literal
     * 就在受管页内，而 D 的自指读模拟是从**原页**读的（CRC 场景的正确语义），
     * 于是 LDR 会拿到原页的字节 = 垃圾地址 → BR 飞掉 → SIGSEGV（真机实测）。
     * 改成 adrp+add+br：三条、不读任何内存，绕开这个语义冲突。 */
    {
        unsigned long tgt = src_addr + CAOIN_TRAMP_INSN * 4;
        unsigned long base = dst_addr + n * 4;          /* 尾桩自己的地址 */
        unsigned long pdelta = (tgt >> 12) - (base >> 12);
        u32 immlo = (u32)(pdelta & 3);
        u32 immhi = (u32)((pdelta >> 2) & 0x7FFFF);
        dst[n++] = 0x90000000u | (immlo << 29) | (immhi << 5) | 16;   /* adrp x16 */
        dst[n++] = 0x91000000u | ((u32)(tgt & 0xFFF) << 10) | (16 << 5) | 16;
        dst[n++] = 0xD61F0200u;                                       /* br x16 */
    }
    return n;
}

/* 注意：这里**不提供** caoin_make_entry_stub（原版 agent 的 `LDR X16,#8; BR X16;
 * <handler>` 写法）。它的 literal 在受管页内，与 D 的"从原页读"语义冲突 →
 * 拿到垃圾地址 → 崩。KPM 侧的入口桩改用 adrp+add+br，见 caoin_kpm.c。 */
