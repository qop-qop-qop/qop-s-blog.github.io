#ifndef MINI_GDB_DISASM_H
#define MINI_GDB_DISASM_H

#include "mini_gdb.h"

/* Ensure d->cs_handle is initialized (idempotent). */
int disasm_init(debugger_t *d);
void disasm_shutdown(debugger_t *d);

/* Disassemble up to `count` instructions starting at addr. If count<=0, use a
   heuristic default (16). `mark_rip` will highlight the rip line. */
int disasm_at(debugger_t *d, uint64_t addr, int count, uint64_t mark_rip);

/* Print `count` instructions around current rip (defaults to 12 when count<=0). */
int disasm_nearpc(debugger_t *d, int count);

/* Disassemble a single instruction at `addr`, returning its length (or 0 on
   failure) and copying its mnemonic/op_str/id into out_* (if non-NULL). Used
   by `next` to detect CALL. */
size_t disasm_one(debugger_t *d, uint64_t addr, unsigned int *out_id,
                  char *out_mnemonic, size_t mnemonic_sz,
                  char *out_op_str, size_t op_str_sz);

#endif
