#include "disasm.h"
#include "memory.h"
#include "symbols.h"
#include "registers.h"
#include "breakpoint.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int disasm_init(debugger_t *d) {
    if (d->cs_ready) return 0;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &d->cs_handle) != CS_ERR_OK) {
        fprintf(stderr, "cs_open failed\n");
        return -1;
    }
    cs_option(d->cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
    d->cs_ready = 1;
    return 0;
}

void disasm_shutdown(debugger_t *d) {
    if (d->cs_ready) {
        cs_close(&d->cs_handle);
        d->cs_ready = 0;
    }
}

/* Copy up to `len` bytes from tracee at `addr` and, for each byte that belongs
   to a currently-armed breakpoint, restore the original.  Without this, disasm
   would show 0xCC where we injected INT3. */
static int read_code(debugger_t *d, uint64_t addr, size_t len, uint8_t *out) {
    if (mem_read(d->pid, addr, out, len) != 0) return -1;
    for (breakpoint_t *bp = d->bps; bp; bp = bp->next) {
        if (!bp->enabled) continue;
        if (bp->addr >= addr && bp->addr < addr + len) {
            out[bp->addr - addr] = (uint8_t)(bp->original_word & 0xff);
        }
    }
    return 0;
}

static void print_bytes(uint8_t *b, size_t n) {
    for (size_t i = 0; i < n && i < 8; i++) printf("%02x ", b[i]);
    for (size_t i = n; i < 8; i++) printf("   ");
}

int disasm_at(debugger_t *d, uint64_t addr, int count, uint64_t mark_rip) {
    if (disasm_init(d) != 0) return -1;
    if (count <= 0) count = 16;

    size_t buf_sz = (size_t)count * 15 + 16;
    uint8_t *buf = malloc(buf_sz);
    if (!buf) return -1;
    if (read_code(d, addr, buf_sz, buf) != 0) {
        fprintf(stderr, "cannot read memory at 0x%lx\n", addr);
        free(buf);
        return -1;
    }

    cs_insn *ins;
    size_t n = cs_disasm(d->cs_handle, buf, buf_sz, addr, count, &ins);
    if (n == 0) {
        fprintf(stderr, "cs_disasm failed at 0x%lx\n", addr);
        free(buf);
        return -1;
    }

    const symbol_t *cur_sym = NULL;
    for (size_t i = 0; i < n; i++) {
        const symbol_t *s = symbols_by_addr(d, ins[i].address);
        if (s && s != cur_sym) {
            printf(ANSI_MAGENTA "%s:" ANSI_RESET "\n", s->name);
            cur_sym = s;
        }
        int is_rip = (mark_rip == ins[i].address);
        printf(" %s 0x%016lx  ",
               is_rip ? ANSI_YELLOW "=>" ANSI_RESET : "  ", ins[i].address);
        print_bytes(ins[i].bytes, ins[i].size);
        printf(" %-8s %s", ins[i].mnemonic, ins[i].op_str);
        if ((ins[i].id == X86_INS_CALL || ins[i].id == X86_INS_JMP) &&
            ins[i].op_str[0]) {
            uint64_t tgt = strtoull(ins[i].op_str, NULL, 0);
            if (tgt) {
                const symbol_t *ts = symbols_by_addr(d, tgt);
                if (ts)
                    printf(ANSI_DIM "  ; %s+0x%lx" ANSI_RESET,
                           ts->name, tgt - ts->addr);
            }
        }
        printf("\n");
    }
    cs_free(ins, n);
    free(buf);
    return 0;
}

int disasm_nearpc(debugger_t *d, int count) {
    if (count <= 0) count = 12;
    struct user_regs_struct r;
    if (regs_get(d->pid, &r) != 0) return -1;
    uint64_t start = r.rip >= 32 ? r.rip - 32 : r.rip;
    return disasm_at(d, start, count, r.rip);
}

size_t disasm_one(debugger_t *d, uint64_t addr, unsigned int *out_id,
                  char *out_mnemonic, size_t mnemonic_sz,
                  char *out_op_str, size_t op_str_sz) {
    if (disasm_init(d) != 0) return 0;
    uint8_t buf[16];
    if (read_code(d, addr, sizeof(buf), buf) != 0) return 0;
    cs_insn *ins;
    size_t n = cs_disasm(d->cs_handle, buf, sizeof(buf), addr, 1, &ins);
    if (n == 0) return 0;
    size_t sz = ins[0].size;
    if (out_id) *out_id = ins[0].id;
    if (out_mnemonic && mnemonic_sz) {
        strncpy(out_mnemonic, ins[0].mnemonic, mnemonic_sz - 1);
        out_mnemonic[mnemonic_sz - 1] = '\0';
    }
    if (out_op_str && op_str_sz) {
        strncpy(out_op_str, ins[0].op_str, op_str_sz - 1);
        out_op_str[op_str_sz - 1] = '\0';
    }
    cs_free(ins, n);
    return sz;
}
