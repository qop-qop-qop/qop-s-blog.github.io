/*
 * caoin payload v7 - self-contained param block (fixed base 0x7f00000000)
 *
 * KPM copies payload bin AND a 32-byte param block at +0x7F0:
 *   +0x7F0: status_va | return_pc | tva | shva
 * Payload reads params via absolute addresses (position is fixed).
 * Register params proved unreliable across do_page_fault return path.
 *
 * Stages written to [status_va]:
 *   0xCA0FCA00 entry | 0xCA0FCA01 self-store done
 *   0xCA0FCA02 stub done | 0xCA0FCA03 exit -> br return_pc
 *
 * build: aarch64-linux-gnu-gcc -nostdlib -static -fno-pic \
 *        -Ttext=0x7f00000000 -e payload_entry tests/caoin_payload.c \
 *        -o build/caoin_payload.elf -Wl,--build-id=none
 */
__asm__(
".globl payload_entry\n"
"payload_entry:\n"
"    /* x20 = INJ_BASE = 0x7f00000000 (fixed) */\n"
"    movz x20, #0x0000\n"
"    movk x20, #0x7f00, lsl #16\n"
"    movk x20, #0x0000, lsl #32\n"
"    movk x20, #0x0000, lsl #48\n"
"    /* x19 = param block base = INJ_BASE + 0x7F0 */\n"
"    add x19, x20, #0x7F0\n"
"    /* stage 0: entry proof -> [status_va] (arg0 at [x19]) */\n"
"    movz x16, #0xCA00\n"
"    movk x16, #0xCA0F, lsl #16\n"
"    ldr x0, [x19]\n"
"    str x16, [x0]\n"
"    /* stage 1: self-store at INJ_BASE+0xFF8 */\n"
"    movz x16, #0xCA01\n"
"    movk x16, #0xCA0F, lsl #16\n"
"    str x16, [x20, #0xFF8]\n"
"    str x16, [x0]\n"
"    /* 777 stub: movz w0,#777; ret -> shva page start (arg3 = [x19,#24]) */\n"
"    movz w3, #0x6120\n"
"    movk w3, #0x5280, lsl #16\n"
"    mov w4, #0xD65F\n"
"    movk w4, #0x03C0, lsl #16\n"
"    ldr x6, [x19, #24]\n"
"    str w3, [x6]\n"
"    str w4, [x6, #4]\n"
"    dc cvac, x6\n"
"    dsb ish\n"
"    ic ivau, x6\n"
"    dsb ish\n"
"    isb\n"
"    /* stage 2 done -> stage 3 exit */\n"
"    movz x16, #0xCA03\n"
"    movk x16, #0xCA0F, lsl #16\n"
"    str x16, [x0]\n"
"    /* return: pc = arg1 at [x19,#8] */\n"
"    ldr x17, [x19, #8]\n"
"    br x17\n"
);
