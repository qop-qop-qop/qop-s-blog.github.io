#ifndef MINI_GDB_SYMBOLS_H
#define MINI_GDB_SYMBOLS_H

#include "mini_gdb.h"

/* Parse ELF at `path`, populate d->symbols with runtime addresses (adding
   d->base_addr for ET_DYN binaries). Sets d->is_pie. Returns 0 on success. */
int symbols_load(debugger_t *d, const char *path);

/* Free all symbols. */
void symbols_free(debugger_t *d);

/* Look up a symbol by name (exact, case-sensitive). */
const symbol_t *symbols_by_name(debugger_t *d, const char *name);

/* Look up the symbol containing an address (largest .addr <= addr where
   addr < .addr + .size, or fallback nearest lower). */
const symbol_t *symbols_by_addr(debugger_t *d, uint64_t addr);

/* Print all symbols matching optional substring `filter` (NULL => all). */
void symbols_print(debugger_t *d, const char *filter);

/* Parse a target expression:
     "0xNNN"      -> numeric
     "symbol"     -> symbol lookup
     "symbol+off" -> symbol + hex offset
   Returns 0 on success, -1 on parse/lookup failure. */
int symbols_resolve(debugger_t *d, const char *expr, uint64_t *out);

#endif
