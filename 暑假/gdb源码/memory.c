#include "memory.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>

int mem_read(pid_t pid, uint64_t addr, void *out, size_t len) {
    if (len == 0) return 0;

    struct iovec local  = { .iov_base = out, .iov_len = len };
    struct iovec remote = { .iov_base = (void *)(uintptr_t)addr, .iov_len = len };
    ssize_t got = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (got == (ssize_t)len) return 0;

    /* Fallback: PEEKDATA word-by-word. Useful when process_vm_readv is blocked
       by yama ptrace_scope or partial-cross-page reads fail. */
    uint8_t *dst = (uint8_t *)out;
    size_t off = 0;
    while (off < len) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, addr + off, 0);
        if (word == -1 && errno) return -1;
        size_t chunk = len - off < sizeof(long) ? len - off : sizeof(long);
        memcpy(dst + off, &word, chunk);
        off += chunk;
    }
    return 0;
}

int mem_write(pid_t pid, uint64_t addr, const void *in, size_t len) {
    const uint8_t *src = (const uint8_t *)in;
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off < sizeof(long) ? len - off : sizeof(long);
        long word;
        if (chunk < sizeof(long)) {
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, pid, addr + off, 0);
            if (word == -1 && errno) return -1;
        } else {
            word = 0;
        }
        memcpy(&word, src + off, chunk);
        if (ptrace(PTRACE_POKEDATA, pid, addr + off, word) == -1) return -1;
        off += chunk;
    }
    return 0;
}

ssize_t mem_read_string(pid_t pid, uint64_t addr, char *out, size_t max) {
    if (max == 0) return 0;
    size_t n = 0;
    while (n < max - 1) {
        char buf[8];
        size_t chunk = max - 1 - n;
        if (chunk > sizeof(buf)) chunk = sizeof(buf);
        if (mem_read(pid, addr + n, buf, chunk) != 0) break;
        for (size_t i = 0; i < chunk; i++) {
            out[n++] = buf[i];
            if (buf[i] == '\0') {
                return (ssize_t)(n - 1);
            }
        }
    }
    out[n] = '\0';
    return (ssize_t)n;
}

void mem_print_maps(pid_t pid, uint64_t rip) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno));
        return;
    }
    char line[1024];
    printf("  %-33s %-6s %-10s %-6s %-8s %s\n",
           "地址范围", "权限", "偏移", "设备", "inode", "路径");
    while (fgets(line, sizeof(line), f)) {
        size_t l = strlen(line);
        if (l && line[l - 1] == '\n') line[l - 1] = '\0';

        uint64_t start = 0, end = 0;
        if (sscanf(line, "%lx-%lx", &start, &end) == 2 &&
            rip >= start && rip < end) {
            printf("* " ANSI_YELLOW "%s" ANSI_RESET "\n", line);
        } else {
            printf("  %s\n", line);
        }
    }
    fclose(f);
}

uint64_t mem_find_base(pid_t pid, const char *prog_path) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    /* Resolve the tracee's absolute binary path via /proc/pid/exe (handles
       relative arg0 and PATH lookup done by execvp). */
    char exe_link[64];
    snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", (int)pid);
    char abs_prog[4096] = {0};
    readlink(exe_link, abs_prog, sizeof(abs_prog) - 1);

    uint64_t base = 0;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        uint64_t start, end, offset;
        char perms[8], dev[16];
        char pth[1024] = {0};
        int n = sscanf(line, "%lx-%lx %7s %lx %15s %*d %1023[^\n]",
                       &start, &end, perms, &offset, dev, pth);
        if (n < 5) continue;
        if (perms[2] != 'x') continue;
        /* strip leading spaces */
        char *p = pth;
        while (*p == ' ') p++;
        /* True load base = mapping_start - file_offset. On modern layouts the
           r-xp LOAD segment lives at file offset 0x1000 (headers/rodata are a
           separate r--p LOAD at file offset 0), so we MUST subtract offset
           to recover the address of ELF byte 0 -- which is what st_value is
           relative to. */
        if (*abs_prog && strcmp(p, abs_prog) == 0) { base = start - offset; break; }
        if (prog_path && strstr(p, prog_path)) { base = start - offset; break; }
    }
    fclose(f);
    return base;
}
