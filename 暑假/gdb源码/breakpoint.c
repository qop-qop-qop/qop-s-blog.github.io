#include "breakpoint.h"
#include "symbols.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>

/* Helper: peek 8 bytes, then poke back with byte 0 replaced by `low`.
   Returns the original 8-byte word via *orig, or -1 on failure. */
static int poke_low_byte(pid_t pid, uint64_t addr, uint8_t low, uint64_t *orig) {
    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
    if (word == -1 && errno) return -1;
    if (orig) *orig = (uint64_t)word;
    long patched = (long)((((uint64_t)word) & ~0xffULL) | (uint64_t)low);
    if (ptrace(PTRACE_POKEDATA, pid, addr, patched) == -1) return -1;
    return 0;
}

breakpoint_t *bp_find(debugger_t *d, uint64_t addr) {
    for (breakpoint_t *bp = d->bps; bp; bp = bp->next)
        if (bp->addr == addr) return bp;
    return NULL;
}

breakpoint_t *bp_add(debugger_t *d, uint64_t addr, int is_temp) {
    if (bp_find(d, addr)) {
        fprintf(stderr, "地址 0x%lx 已经有断点了\n", addr);
        return NULL;
    }

    breakpoint_t *bp = calloc(1, sizeof(*bp));
    if (!bp) return NULL;
    bp->addr    = addr;
    bp->id      = ++d->next_bp_id;
    bp->enabled = 1;
    bp->is_temp = is_temp;

    /* If child is running/stopped, physically install now.  Otherwise defer
       until run() has spawned the process. */
    if (d->pid > 0) {
        if (poke_low_byte(d->pid, addr, 0xCC, &bp->original_word) != 0) {
            fprintf(stderr, "在 0x%lx 写入 INT3 失败: %s\n",
                    addr, strerror(errno));
            free(bp);
            return NULL;
        }
    }

    bp->next = d->bps;
    d->bps = bp;

    if (!is_temp) {
        const symbol_t *s = symbols_by_addr(d, addr);
        if (s) {
            printf("断点 %d 已设置在 0x%lx (%s+0x%lx)\n",
                   bp->id, addr, s->name, addr - s->addr);
        } else {
            printf("断点 %d 已设置在 0x%lx\n", bp->id, addr);
        }
    }
    return bp;
}

int bp_disarm(debugger_t *d, breakpoint_t *bp) {
    if (d->pid <= 0 || !bp) return -1;
    uint8_t orig = (uint8_t)(bp->original_word & 0xff);
    return poke_low_byte(d->pid, bp->addr, orig, NULL);
}

int bp_arm(debugger_t *d, breakpoint_t *bp) {
    if (d->pid <= 0 || !bp) return -1;
    /* Re-peek so we don't stomp on any concurrent memory writes to bytes 1..7. */
    int rc = poke_low_byte(d->pid, bp->addr, 0xCC, &bp->original_word);
    if (getenv("MGDB_DEBUG")) {
        fprintf(stderr, "[bp_arm] id=%d addr=0x%lx orig_low=0x%02x rc=%d errno=%d\n",
                bp->id, bp->addr, (unsigned)(bp->original_word & 0xff), rc, errno);
    }
    return rc;
}

int bp_remove_by_id(debugger_t *d, int id) {
    breakpoint_t **pp = &d->bps;
    while (*pp) {
        if ((*pp)->id == id) {
            breakpoint_t *dead = *pp;
            if (d->pid > 0 && dead->enabled) {
                bp_disarm(d, dead);
            }
            if (d->pending_reset_bp == dead) d->pending_reset_bp = NULL;
            *pp = dead->next;
            free(dead);
            return 0;
        }
        pp = &(*pp)->next;
    }
    fprintf(stderr, "没有编号为 %d 的断点\n", id);
    return -1;
}

void bp_clear_all(debugger_t *d) {
    breakpoint_t *bp = d->bps;
    while (bp) {
        breakpoint_t *n = bp->next;
        free(bp);
        bp = n;
    }
    d->bps = NULL;
    d->pending_reset_bp = NULL;
    d->next_bp_id = 0;
}

void bp_list(debugger_t *d) {
    if (!d->bps) {
        printf("当前没有断点\n");
        return;
    }
    printf("  %-4s %-4s %-18s %s\n", "编号", "启用", "地址", "位置");
    for (breakpoint_t *bp = d->bps; bp; bp = bp->next) {
        const symbol_t *s = symbols_by_addr(d, bp->addr);
        char loc[128];
        if (s) snprintf(loc, sizeof(loc), "%s+0x%lx", s->name, bp->addr - s->addr);
        else   snprintf(loc, sizeof(loc), "-");
        printf("  %-4d %-4s 0x%016lx %s%s\n",
               bp->id,
               bp->enabled ? "是" : "否",
               bp->addr,
               loc,
               bp->is_temp ? "  (临时)" : "");
    }
}
