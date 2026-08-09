#ifndef MINI_GDB_MEMORY_H
#define MINI_GDB_MEMORY_H

#include "mini_gdb.h"

/* Read `len` bytes from the tracee's virtual memory at `addr` into `out`.
   Returns 0 on success, -1 on error. Tries process_vm_readv first, falls back
   to PTRACE_PEEKDATA word-by-word. */
int mem_read(pid_t pid, uint64_t addr, void *out, size_t len);

/* Write `len` bytes from `in` into the tracee at `addr`. Uses word-aligned
   PTRACE_POKEDATA (must PEEK first to preserve neighbor bytes when len % 8). */
int mem_write(pid_t pid, uint64_t addr, const void *in, size_t len);

/* Read a NUL-terminated string from the tracee, up to `max`-1 bytes.
   Guarantees NUL termination. Returns bytes copied excluding NUL. */
ssize_t mem_read_string(pid_t pid, uint64_t addr, char *out, size_t max);

/* Print /proc/pid/maps, optionally highlighting the line containing `rip`. */
void mem_print_maps(pid_t pid, uint64_t rip);

/* Find load base of `prog_path` in /proc/pid/maps (first r-xp mapping).
   Returns 0 if not found. */
uint64_t mem_find_base(pid_t pid, const char *prog_path);

#endif
