#ifndef MINI_GDB_DEBUGGER_H
#define MINI_GDB_DEBUGGER_H

#include "mini_gdb.h"

void dbg_init(debugger_t *d, const char *prog, char **argv, int argc);
void dbg_shutdown(debugger_t *d);

/* Fork+exec the tracee, then run wait_for_signal until it stops or exits.
   Existing (deferred) breakpoints are installed once the child appears. */
int dbg_run(debugger_t *d);

/* Attach to an already-running pid via PTRACE_ATTACH. */
int dbg_attach(debugger_t *d, pid_t pid);

/* Detach: disarm all breakpoints, PTRACE_DETACH, clear state. */
int dbg_detach(debugger_t *d);

/* Restart the child if it has exited (fresh fork+exec). */

/* Continue the tracee. Handles the "stepping over an in-flight breakpoint"
   dance. Blocks until next stop/exit. */
int dbg_continue(debugger_t *d);

/* Single instruction step. */
int dbg_stepi(debugger_t *d);

/* Step over: if current insn is CALL, set a temp bp at next insn and continue.
   Otherwise same as stepi. */
int dbg_nexti(debugger_t *d);

/* Run until current function returns (temp bp at *(rbp+8)). */
int dbg_finish(debugger_t *d);

/* Ensure child is stopped and usable; used as a precondition check in
   command handlers. Prints an error and returns -1 if not. */
int dbg_require_stopped(debugger_t *d);

#endif
