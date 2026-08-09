#ifndef MINI_GDB_BREAKPOINT_H
#define MINI_GDB_BREAKPOINT_H

#include "mini_gdb.h"

/* Install a new breakpoint at addr. Returns the new bp on success, NULL on
   failure (e.g. address unreadable, or breakpoint already exists there). */
breakpoint_t *bp_add(debugger_t *d, uint64_t addr, int is_temp);

/* Remove a breakpoint by numeric id. Returns 0 on success, -1 if not found. */
int bp_remove_by_id(debugger_t *d, int id);

/* Free every breakpoint (used when child exits / detaches). Does not touch
   process memory. */
void bp_clear_all(debugger_t *d);

/* Find bp by exact address; NULL if none. */
breakpoint_t *bp_find(debugger_t *d, uint64_t addr);

/* Physically restore original byte at bp->addr in the tracee.  Used when the
   breakpoint fires so the child can continue past the trapped instruction. */
int bp_disarm(debugger_t *d, breakpoint_t *bp);

/* Re-inject 0xCC at bp->addr. */
int bp_arm(debugger_t *d, breakpoint_t *bp);

/* List all breakpoints for `info break`. */
void bp_list(debugger_t *d);

#endif
