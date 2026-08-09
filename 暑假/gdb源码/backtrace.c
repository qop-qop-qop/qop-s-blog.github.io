#include "backtrace.h"
#include "symbols.h"

#include <libunwind.h>
#include <libunwind-ptrace.h>
#include <stdio.h>

int bt_print(debugger_t *d) {
    unw_addr_space_t as = unw_create_addr_space(&_UPT_accessors, 0);
    if (!as) {
        fprintf(stderr, "unw_create_addr_space failed\n");
        return -1;
    }
    void *ui = _UPT_create(d->pid);
    if (!ui) {
        fprintf(stderr, "_UPT_create failed\n");
        unw_destroy_addr_space(as);
        return -1;
    }

    unw_cursor_t c;
    int rc = unw_init_remote(&c, as, ui);
    if (rc != 0) {
        fprintf(stderr, "unw_init_remote: %d\n", rc);
        _UPT_destroy(ui);
        unw_destroy_addr_space(as);
        return -1;
    }

    int frame = 0;
    do {
        unw_word_t ip = 0, sp = 0;
        unw_get_reg(&c, UNW_REG_IP, &ip);
        unw_get_reg(&c, UNW_REG_SP, &sp);

        char proc[256] = {0};
        unw_word_t off = 0;
        int gp = unw_get_proc_name(&c, proc, sizeof(proc), &off);

        /* Prefer our own symbol table; fall back to libunwind's guess. */
        const symbol_t *s = symbols_by_addr(d, (uint64_t)ip);
        const char *name;
        uint64_t noff;
        if (s) {
            name = s->name;
            noff = (uint64_t)ip - s->addr;
        } else if (gp == 0 && proc[0]) {
            name = proc;
            noff = off;
        } else {
            name = "??";
            noff = 0;
        }

        printf(" #%-2d 0x%016lx in " ANSI_GREEN "%s" ANSI_RESET "+0x%lx  "
               ANSI_DIM "(sp=0x%lx)" ANSI_RESET "\n",
               frame++, (uint64_t)ip, name, noff, (uint64_t)sp);

        if (frame > 64) {
            printf(" ... (truncated at 64 frames)\n");
            break;
        }
    } while (unw_step(&c) > 0);

    _UPT_destroy(ui);
    unw_destroy_addr_space(as);
    return 0;
}
