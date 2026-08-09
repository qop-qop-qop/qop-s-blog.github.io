#ifndef MINI_GDB_COMMAND_H
#define MINI_GDB_COMMAND_H

#include "mini_gdb.h"

typedef int (*cmd_handler_fn)(debugger_t *d, int argc, char **argv);

typedef struct command {
    const char *name;
    const char *aliases[4];
    cmd_handler_fn handler;
    const char *help_short;
    const char *help_long;
} command_t;

/* Parse and dispatch one input line. Return 1 to keep looping, 0 to quit. */
int cmd_dispatch(debugger_t *d, char *line);

/* Retrieve the command table (used by help/completion). */
const command_t *cmd_table(size_t *out_n);

#endif
