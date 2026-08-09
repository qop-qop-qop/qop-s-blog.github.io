#ifndef MINI_GDB_REGISTERS_H
#define MINI_GDB_REGISTERS_H

#include "mini_gdb.h"
#include <sys/user.h>

int regs_get(pid_t pid, struct user_regs_struct *r);
int regs_set(pid_t pid, const struct user_regs_struct *r);

/* Print all registers in three grouped rows. If `filter` is non-NULL, print
   only that one register. Returns 0 on success. */
int regs_print(pid_t pid, const char *filter);

/* Assign `value` to the named register. Returns 0 on success, -1 if the name
   is unknown or ptrace fails. */
int regs_write_by_name(pid_t pid, const char *name, uint64_t value);

/* Read a named register into *out. */
int regs_read_by_name(pid_t pid, const char *name, uint64_t *out);

#endif
