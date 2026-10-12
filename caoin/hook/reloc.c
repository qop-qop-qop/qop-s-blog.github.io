/*
 * caoin arm64 指令重定位器
 *
 * 只处理函数入口 16 字节内可能出现且 PC 相对的指令：
 *   B/BL (imm26, ±128MB)
 *   ADR/ADRP (immhi:immlo = imm21)
 *   CBZ/CBNZ (imm19, ±1MB)、TBZ/TBNZ (imm14, ±32KB)
 *   LDR/PRFM literal (imm19, literal 数据搬入 trampoline)
 * 其余指令（含 PACIASP、stp 序言、ADR 系之外的 ALU/load-store）无 PC 依赖，原样拷贝。
 */
#include "reloc.h"
#include "platform.h"

int64_t caoin_sext(uint32_t v, int bits)
{
    uint32_t m = 1u << (bits - 1);
    return (int64_t)((int64_t)(v ^ m) - (int64_t)m);
}

/* 指令分类，内部约定编码见 armv8 ARM DDI 0487 */
enum {
    K_OTHER = 0,
    K_B,        /* B / BL */
    K_ADR,      /* ADR / ADRP */
    K_CB,       /* CBZ / CBNZ */
    K_TB,       /* TBZ / TBNZ */
    K_LIT,      /* LDR/PRFM literal */
};

static int classify(uint32_t insn)
{
    if ((insn & 0x7C000000) == 0x14000000) return K_B;
    if ((insn & 0x1F000000) == 0x10000000) return K_ADR;   /* bits[28:24]=10000，bit31 区分 ADR/ADRP */
    if ((insn & 0x7E000000) == 0x34000000) return K_CB;
    if ((insn & 0x7E000000) == 0x36000000) return K_TB;
    if ((insn & 0x1F000000) == 0x18000000) return K_LIT;   /* bits[28:24]=11000，含 Wt/Xt/SWt/PRFM/St/Qt */
    return K_OTHER;
}

/* imm19: bits[23:5]，imm26: bits[25:0]，imm14: bits[18:5] */
#define GET_IMM19(i)  (((i) >> 5) & 0x7FFFF)
#define PUT_IMM19(i, v) (((i) & ~0x00FFFFE0u) | (((uint32_t)(v) & 0x7FFFF) << 5))
#define GET_IMM26(i)  ((i) & 0x03FFFFFF)
#define PUT_IMM26(i, v) (((i) & ~0x03FFFFFFu) | ((uint32_t)(v) & 0x03FFFFFF))
#define GET_IMM14(i)  (((i) >> 5) & 0x3FFF)
#define PUT_IMM14(i, v) (((i) & ~0x0007FFE0u) | (((uint32_t)(v) & 0x3FFF) << 5))

static int fit(int64_t v, int64_t lo, int64_t hi)
{
    return v >= lo && v <= hi;
}

/* LDR literal 数据宽度：opc=bits[31:30]，V=bit29 */
static size_t literal_width(uint32_t insn)
{
    uint32_t opc = insn >> 30;
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

int caoin_window_pc_relative(const uint32_t *src)
{
    for (int i = 0; i < CAOIN_TRAMP_INSN; i++) {
        uint32_t insn = src[i];
        if ((insn & 0x7C000000) == 0x14000000) return 1;   /* B/BL */
        if ((insn & 0x1F000000) == 0x10000000) return 1;   /* ADR/ADRP */
        if ((insn & 0x7E000000) == 0x34000000) return 1;   /* CBZ/CBNZ */
        if ((insn & 0x7E000000) == 0x36000000) return 1;   /* TBZ/TBNZ */
        if ((insn & 0x1F000000) == 0x18000000) return 1;   /* LDR literal */
    }
    return 0;
}

size_t caoin_reloc_block(uint32_t *dst, uintptr_t dst_addr,
                         const uint32_t *src, uintptr_t src_addr,
                         int out_status[CAOIN_TRAMP_INSN])
{
    size_t n = 0;
    for (int i = 0; i < CAOIN_TRAMP_INSN; i++) {
        uint32_t insn = src[i];
        uintptr_t old_pc = src_addr + (uintptr_t)i * 4;
        uintptr_t new_pc = dst_addr + (uintptr_t)n * 4;
        out_status[i] = CAOIN_RELOC_COPY;

        switch (classify(insn)) {
        case K_B: {
            uintptr_t target = old_pc + (uintptr_t)(caoin_sext(GET_IMM26(insn), 26) << 2);
            if (target >= src_addr && target < src_addr + CAOIN_TRAMP_INSN * 4) {
                out_status[i] = CAOIN_RELOC_UNSUPPORTED;  /* 分支目标在被覆盖窗口内 */
                return 0;
            }
            int64_t off = (int64_t)target - (int64_t)new_pc;
            if (!fit(off, -(1LL << 27), (1LL << 27) - 4)) {
                out_status[i] = CAOIN_RELOC_RANGE;
                return 0;
            }
            dst[n++] = PUT_IMM26(insn, (uint32_t)(off >> 2));
            out_status[i] = CAOIN_RELOC_FIXED;
            break;
        }
        case K_ADR: {
            int is_adrp = (insn >> 31) & 1;
            uint32_t imm21 = ((((insn >> 5) & 0x7FFFF) << 2) | ((insn >> 29) & 3));
            uintptr_t base = is_adrp ? (old_pc & ~(uintptr_t)0xFFF) : old_pc;
            uintptr_t target = base + (uintptr_t)(caoin_sext(imm21, 21) << (is_adrp ? 12 : 0));
            uintptr_t new_base = is_adrp ? (new_pc & ~(uintptr_t)0xFFF) : new_pc;
            int64_t off = (int64_t)target - (int64_t)new_base;
            int64_t lim = is_adrp ? (4LL << 30) : (1LL << 20);
            if (!fit(off, -lim, lim - 1)) {
                out_status[i] = CAOIN_RELOC_RANGE;
                return 0;
            }
            /* imm21 为有符号 21 位：负偏移须截断到低 21 位，防符号位污染 opcode */
            uint32_t s21 = (uint32_t)(off >> (is_adrp ? 12 : 0)) & 0x1FFFFFu;
            uint32_t v = ((s21 >> 2) << 5) | (s21 & 3) << 29;       /* immhi<<5 | immlo<<29 */
            dst[n++] = (insn & ~((0x60000000u) | (0x7FFFFu << 5))) | v;
            out_status[i] = CAOIN_RELOC_FIXED;
            break;
        }
        case K_CB: {
            uintptr_t target = old_pc + (uintptr_t)(caoin_sext(GET_IMM19(insn), 19) << 2);
            if (target >= src_addr && target < src_addr + CAOIN_TRAMP_INSN * 4) {
                out_status[i] = CAOIN_RELOC_UNSUPPORTED;  /* 窗口内分支，保守拒绝 */
                return 0;
            }
            int64_t off = (int64_t)target - (int64_t)new_pc;
            if (!fit(off, -(1LL << 20), (1LL << 20) - 4)) {
                out_status[i] = CAOIN_RELOC_RANGE;
                return 0;
            }
            dst[n++] = PUT_IMM19(insn, (uint32_t)(off >> 2));
            out_status[i] = CAOIN_RELOC_FIXED;
            break;
        }
        case K_TB: {
            uintptr_t target = old_pc + (uintptr_t)(caoin_sext(GET_IMM14(insn), 14) << 2);
            if (target >= src_addr && target < src_addr + CAOIN_TRAMP_INSN * 4) {
                out_status[i] = CAOIN_RELOC_UNSUPPORTED;
                return 0;
            }
            int64_t off = (int64_t)target - (int64_t)new_pc;
            if (!fit(off, -(1LL << 15), (1LL << 15) - 4)) {
                out_status[i] = CAOIN_RELOC_RANGE;
                return 0;
            }
            dst[n++] = PUT_IMM14(insn, (uint32_t)(off >> 2));
            out_status[i] = CAOIN_RELOC_FIXED;
            break;
        }
        case K_LIT: {
            /* literal 数据紧随当前已写入位置追加，重算 imm19 指向它 */
            uintptr_t target = old_pc + (uintptr_t)(caoin_sext(GET_IMM19(insn), 19) << 2);
            size_t w = literal_width(insn);
            if (n + 1 + (w / 4) + 4 > CAOIN_TRAMP_CAP_INSN) {
                out_status[i] = CAOIN_RELOC_RANGE;
                return 0;
            }
            int64_t off = (int64_t)(dst_addr + (uintptr_t)(n + 1) * 4) - (int64_t)new_pc;
            dst[n++] = PUT_IMM19(insn, (uint32_t)(off >> 2));
            caoin_memcpy(&dst[n], (const void *)target, w);   /* NOLINT: 目标进程内读取，地址有效 */
            n += w / 4;
            out_status[i] = CAOIN_RELOC_LITERAL;
            break;
        }
        default:
            dst[n++] = insn;
            break;
        }
    }

    /* 尾桩：LDR X16,#8; BR X16; <src_addr + 16> */
    dst[n++] = 0x58000050;
    dst[n++] = 0xD61F0200;
    uintptr_t back = src_addr + CAOIN_TRAMP_INSN * 4;
    caoin_memcpy(&dst[n], &back, sizeof back);
    n += sizeof(back) / 4;
    return n;
}

void caoin_make_entry_stub(uint32_t dst[CAOIN_TRAMP_INSN], uintptr_t handler)
{
    dst[0] = 0x58000050;    /* LDR X16, #8 */
    dst[1] = 0xD61F0200;    /* BR X16 */
    caoin_memcpy(&dst[2], &handler, sizeof handler);
}
