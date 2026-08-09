#ifndef MINI_GDB_BACKTRACE_H
#define MINI_GDB_BACKTRACE_H

#include "mini_gdb.h"

/* Print the stopped tracee's call stack, resolving each frame to
   symbol+offset via d->symbols. */
int bt_print(debugger_t *d);

#endif
