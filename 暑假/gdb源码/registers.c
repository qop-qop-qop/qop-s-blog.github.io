#include "registers.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/ptrace.h>

typedef struct {
    const char *name;
    size_t off;
} reg_map_t;

#define R(field) { #field, offsetof(struct user_regs_struct, field) }

static const reg_map_t kRegMap[] = {
    R(rax), R(rbx), R(rcx), R(rdx),
    R(rsi), R(rdi), R(rbp), R(rsp),
    R(r8),  R(r9),  R(r10), R(r11),
    R(r12), R(r13), R(r14), R(r15),
    R(rip), R(eflags),
    R(cs),  R(ss),  R(ds),  R(es),
    R(fs),  R(gs),
    R(fs_base), R(gs_base),
    R(orig_rax),
    { NULL, 0 },
};

int regs_get(pid_t pid, struct user_regs_struct *r) {
    if (ptrace(PTRACE_GETREGS, pid, 0, r) == -1) {
        fprintf(stderr, "GETREGS failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

int regs_set(pid_t pid, const struct user_regs_struct *r) {
    if (ptrace(PTRACE_SETREGS, pid, 0, (void *)r) == -1) {
        fprintf(stderr, "SETREGS failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static const reg_map_t *find_reg(const char *name) {
    for (const reg_map_t *m = kRegMap; m->name; m++)
        if (strcasecmp(m->name, name) == 0) return m;
    /* GDB compat: allow rflags -> eflags */
    if (strcasecmp(name, "rflags") == 0) {
        for (const reg_map_t *m = kRegMap; m->name; m++)
            if (strcmp(m->name, "eflags") == 0) return m;
    }
    return NULL;
}

int regs_read_by_name(pid_t pid, const char *name, uint64_t *out) {
    struct user_regs_struct r;
    if (regs_get(pid, &r) != 0) return -1;
    const reg_map_t *m = find_reg(name);
    if (!m) return -1;
    *out = *(uint64_t *)((char *)&r + m->off);
    return 0;
}

int regs_write_by_name(pid_t pid, const char *name, uint64_t value) {
    struct user_regs_struct r;
    if (regs_get(pid, &r) != 0) return -1;
    const reg_map_t *m = find_reg(name);
    if (!m) return -1;
    *(uint64_t *)((char *)&r + m->off) = value;
    return regs_set(pid, &r);
}

static void print_one(const char *name, uint64_t v) {
    printf(ANSI_CYAN "%-8s" ANSI_RESET " 0x%016lx  ", name, v);
}

int regs_print(pid_t pid, const char *filter) {
    struct user_regs_struct r;
    if (regs_get(pid, &r) != 0) return -1;

    if (filter) {
        uint64_t v;
        if (regs_read_by_name(pid, filter, &v) != 0) {
            fprintf(stderr, "未知寄存器: %s\n", filter);
            return -1;
        }
        printf(ANSI_CYAN "%-8s" ANSI_RESET " 0x%016lx  (%lu)\n", filter, v, v);
        return 0;
    }

    /* Row layout: 4 registers per row for readability. */
    static const char *rows[][4] = {
        { "rax", "rbx", "rcx", "rdx" },
        { "rsi", "rdi", "rbp", "rsp" },
        { "r8",  "r9",  "r10", "r11" },
        { "r12", "r13", "r14", "r15" },
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        for (int j = 0; j < 4; j++) {
            uint64_t v;
            regs_read_by_name(pid, rows[i][j], &v);
            print_one(rows[i][j], v);
        }
        printf("\n");
    }
    print_one("rip",    r.rip);
    print_one("eflags", r.eflags);
    printf("\n");
    print_one("cs", r.cs); print_one("ss", r.ss);
    print_one("ds", r.ds); print_one("es", r.es);
    printf("\n");
    print_one("fs", r.fs); print_one("gs", r.gs);
    printf("\n");
    return 0;
}
