#include "debugger.h"
#include "breakpoint.h"
#include "symbols.h"
#include "memory.h"
#include "registers.h"
#include "libc.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <capstone/x86.h>
#include <libunwind.h>
#include <libunwind-ptrace.h>
#include "disasm.h"

void dbg_init(debugger_t *d, const char *prog, char **argv, int argc) {
    memset(d, 0, sizeof(*d));
    d->prog_path = prog ? strdup(prog) : NULL;
    d->prog_argv = argv;
    d->prog_argc = argc;
    d->input_file = NULL;  /* 初始化为 NULL */
    d->state = ST_NOT_STARTED;
}

void dbg_shutdown(debugger_t *d) {
    if (d->pid > 0 && d->state != ST_EXITED) {
        if (d->attached) {
            /* Restore any INT3s so the tracee doesn't SIGTRAP itself to death
               after we let go. */
            for (breakpoint_t *bp = d->bps; bp; bp = bp->next)
                if (bp->enabled) bp_disarm(d, bp);
            ptrace(PTRACE_DETACH, d->pid, 0, 0);
        } else {
            kill(d->pid, SIGKILL);
            waitpid(d->pid, NULL, 0);
        }
    }
    bp_clear_all(d);
    symbols_free(d);
    if (d->libc) { free(d->libc); d->libc = NULL; }
    free(d->prog_path);
    free(d->input_file);  /* 释放输入文件路径 */
}

int dbg_require_stopped(debugger_t *d) {
    if (d->state != ST_STOPPED) {
        fprintf(stderr, "子进程当前不在停下状态 (state=%d)\n", d->state);
        return -1;
    }
    return 0;
}

static const char *signame(int sig) {
    switch (sig) {
        case SIGSEGV: return "SIGSEGV";
        case SIGBUS:  return "SIGBUS";
        case SIGILL:  return "SIGILL";
        case SIGFPE:  return "SIGFPE";
        case SIGABRT: return "SIGABRT";
        case SIGINT:  return "SIGINT";
        case SIGTERM: return "SIGTERM";
        case SIGSTOP: return "SIGSTOP";
        case SIGTRAP: return "SIGTRAP";
        default:      return "SIG?";
    }
}

/* When we hit our own INT3, kernel already advanced RIP past 0xCC.  Rewind by
   1 and mark the bp so `continue` knows to disarm-step-rearm. */
static void handle_sigtrap(debugger_t *d) {
    struct user_regs_struct r;
    if (regs_get(d->pid, &r) != 0) return;
    breakpoint_t *bp = bp_find(d, r.rip - 1);
    if (bp && bp->enabled) {
        r.rip -= 1;
        regs_set(d->pid, &r);
        bp_disarm(d, bp);
        d->pending_reset_bp = bp;

        const symbol_t *s = symbols_by_addr(d, bp->addr);
        if (s) {
            printf(ANSI_GREEN "* 命中断点 %d" ANSI_RESET
                   "  地址 0x%lx (%s+0x%lx)\n",
                   bp->id, bp->addr, s->name, bp->addr - s->addr);
        } else {
            printf(ANSI_GREEN "* 命中断点 %d" ANSI_RESET "  地址 0x%lx\n",
                   bp->id, bp->addr);
        }
        if (bp->is_temp) {
            int id = bp->id;
            bp_remove_by_id(d, id);
        }
    }
}

/* Block until the child stops or exits. Updates d->state. */
static int wait_for_signal(debugger_t *d) {
    int status = 0;
    if (waitpid(d->pid, &status, 0) < 0) {
        fprintf(stderr, "waitpid: %s\n", strerror(errno));
        return -1;
    }

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        if (WIFEXITED(status))
            printf(ANSI_YELLOW "[程序正常退出,返回码 %d]" ANSI_RESET "\n",
                   WEXITSTATUS(status));
        else
            printf(ANSI_RED "[程序被信号 %s (%d) 杀死]" ANSI_RESET "\n",
                   signame(WTERMSIG(status)), WTERMSIG(status));
        d->state = ST_EXITED;
        d->pid = 0;
        d->pending_reset_bp = NULL;
        /* Prune any temp breakpoints that never fired (e.g. `next` past an
           unreachable return). */
        breakpoint_t **pp = &d->bps;
        while (*pp) {
            if ((*pp)->is_temp) {
                breakpoint_t *dead = *pp;
                *pp = dead->next;
                free(dead);
            } else {
                pp = &(*pp)->next;
            }
        }
        return 0;
    }
    if (WIFSTOPPED(status)) {
        int sig = WSTOPSIG(status);
        d->state = ST_STOPPED;
        /* 第一次真正停下时(通常是首个用户断点或用户 ^C),尝试合并 libc 符号。 */
        if (!d->libc_symbols_loaded) {
            if (libc_load(d, NULL) > 0) d->libc_symbols_loaded = 1;
        }
        if (sig == SIGTRAP || sig == SIGSTOP) {
            /* Our own INT3 or the post-attach SIGSTOP -- consume it. */
            d->last_signal = 0;
            if (sig == SIGTRAP) handle_sigtrap(d);
        } else {
            /* Fatal-ish signal from the program itself: report it and set
               up to redeliver on the next continue so the child sees it. */
            d->last_signal = sig;
            struct user_regs_struct r;
            regs_get(d->pid, &r);
            printf(ANSI_RED "[收到信号 %s (%d),停在 0x%lx]" ANSI_RESET "\n",
                   signame(sig), sig, (unsigned long)r.rip);
        }
        return 0;
    }
    return 0;
}

/* Step across the byte that was 0xCC. Restores original, single-steps, rearms. */
static int step_over_pending(debugger_t *d) {
    if (!d->pending_reset_bp) return 0;
    breakpoint_t *bp = d->pending_reset_bp;

    if (ptrace(PTRACE_SINGLESTEP, d->pid, 0, 0) == -1) {
        fprintf(stderr, "SINGLESTEP failed: %s\n", strerror(errno));
        return -1;
    }
    int status;
    if (waitpid(d->pid, &status, 0) < 0) return -1;
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        /* Program ended mid-step (e.g. exit() at bp address); leave state to
           the next real wait_for_signal to handle. */
        d->state = ST_EXITED;
        d->pid = 0;
        d->pending_reset_bp = NULL;
        return 0;
    }
    bp_arm(d, bp);
    d->pending_reset_bp = NULL;
    return 0;
}

int dbg_continue(debugger_t *d) {
    if (dbg_require_stopped(d) != 0) return -1;
    if (step_over_pending(d) != 0) return -1;
    if (d->state == ST_EXITED) return 0;

    /* Forward any pending signal from a prior stop (e.g. SIGSEGV). */
    if (ptrace(PTRACE_CONT, d->pid, 0, d->last_signal) == -1) {
        fprintf(stderr, "PTRACE_CONT failed: %s\n", strerror(errno));
        return -1;
    }
    d->last_signal = 0;
    d->state = ST_RUNNING;
    return wait_for_signal(d);
}

int dbg_stepi(debugger_t *d) {
    if (dbg_require_stopped(d) != 0) return -1;
    /* If we're sitting on a pending bp, the single step naturally resolves it. */
    if (d->pending_reset_bp) {
        return step_over_pending(d);
    }
    if (ptrace(PTRACE_SINGLESTEP, d->pid, 0, 0) == -1) {
        fprintf(stderr, "SINGLESTEP failed: %s\n", strerror(errno));
        return -1;
    }
    d->state = ST_RUNNING;
    return wait_for_signal(d);
}

int dbg_nexti(debugger_t *d) {
    if (dbg_require_stopped(d) != 0) return -1;

    struct user_regs_struct r;
    regs_get(d->pid, &r);
    unsigned int id = 0;
    size_t sz = disasm_one(d, r.rip, &id, NULL, 0, NULL, 0);
    if (sz == 0 || id != X86_INS_CALL) {
        return dbg_stepi(d);
    }

    /* Add a temp bp right after the CALL and continue. */
    breakpoint_t *tbp = bp_add(d, r.rip + sz, 1);
    if (!tbp) return -1;
    return dbg_continue(d);
}

int dbg_finish(debugger_t *d) {
    if (dbg_require_stopped(d) != 0) return -1;

    /* Use libunwind to find the caller's IP -- correct regardless of whether
       the frame pointer has been set up yet, and works with -fomit-frame-
       pointer via .eh_frame. */
    unw_addr_space_t as = unw_create_addr_space(&_UPT_accessors, 0);
    if (!as) { fprintf(stderr, "unw_create_addr_space failed\n"); return -1; }
    void *ui = _UPT_create(d->pid);
    if (!ui) { unw_destroy_addr_space(as); return -1; }
    unw_cursor_t c;
    uint64_t ret_addr = 0;
    if (unw_init_remote(&c, as, ui) == 0 && unw_step(&c) > 0) {
        unw_word_t ip = 0;
        unw_get_reg(&c, UNW_REG_IP, &ip);
        ret_addr = (uint64_t)ip;
    }
    _UPT_destroy(ui);
    unw_destroy_addr_space(as);

    if (ret_addr == 0) {
        fprintf(stderr, "finish: cannot determine caller frame\n");
        return -1;
    }
    breakpoint_t *tbp = bp_add(d, ret_addr, 1);
    if (!tbp) return -1;
    return dbg_continue(d);
}

/* After the tracee is stopped for the first time (either post-exec SIGTRAP or
   post-attach SIGSTOP), we determine the load base, load symbols and arm any
   breakpoints the user set before the child existed. */
static int post_launch_setup(debugger_t *d) {
    const char *path = d->prog_path;
    char exe[4096] = {0};

    if (d->attached) {
        /* Attach path: resolve the tracee's binary via /proc/pid/exe. */
        char link[64];
        snprintf(link, sizeof(link), "/proc/%d/exe", (int)d->pid);
        if (readlink(link, exe, sizeof(exe) - 1) > 0) {
            free(d->prog_path);
            d->prog_path = strdup(exe);
            path = d->prog_path;
        }
    }

    if (!path) return 0;

    uint64_t old_base = d->base_addr;
    uint64_t new_base = mem_find_base(d->pid, path);

    if (getenv("MGDB_DEBUG")) {
        fprintf(stderr, "[post_launch] pid=%d path=%s is_pie=%d "
                        "old_base=0x%lx new_base=0x%lx\n",
                d->pid, path, d->is_pie, old_base, new_base);
    }

    /* If we already loaded symbols at startup with base=0, and the binary
       is PIE, patch existing breakpoint addresses forward by the shift so a
       pre-run `b main` still refers to the right instruction. */
    if (d->is_pie && new_base != old_base) {
        uint64_t shift = new_base - old_base;
        for (breakpoint_t *bp = d->bps; bp; bp = bp->next)
            bp->addr += shift;
    }
    d->base_addr = new_base;

    /* Rebuild symbol table with the correct base. */
    symbols_load(d, path);

    /* 注意:此时子进程刚 execvp 完,动态链接器还没把 libc 映射进来,
       所以不在这里加载 libc 符号。改由 wait_for_signal 停下后懒加载。 */
    d->libc_symbols_loaded = 0;
    if (d->libc) { free(d->libc); d->libc = NULL; }

    /* Arm any deferred breakpoints. */
    for (breakpoint_t *bp = d->bps; bp; bp = bp->next) {
        if (!bp->enabled) continue;
        bp_arm(d, bp);
    }
    d->state = ST_STOPPED;
    return 0;
}

int dbg_run(debugger_t *d) {
    if (!d->prog_path) {
        fprintf(stderr, "no program specified\n");
        return -1;
    }
    if (d->state == ST_RUNNING || d->state == ST_STOPPED) {
        printf("[重新启动,杀掉旧进程 pid %d]\n", d->pid);
        kill(d->pid, SIGKILL);
        waitpid(d->pid, NULL, 0);
        /* Keep breakpoints across restarts: ADDR_NO_RANDOMIZE plus a fixed
           load base means their addresses are still valid. Just mark them
           as "not physically injected" so post_launch_setup re-arms them. */
        d->pending_reset_bp = NULL;
        symbols_free(d);
        d->state = ST_NOT_STARTED;
        d->pid = 0;
    }

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }
    if (pid == 0) {
        /* 子进程 - 即将被调试的程序 */
        if (personality(ADDR_NO_RANDOMIZE) == -1) perror("personality");

        /* 如果指定了输入重定向文件，重定向 stdin */
        if (d->input_file) {
            int fd = open(d->input_file, O_RDONLY);
            if (fd < 0) {
                perror(d->input_file);
                _exit(127);
            }
            if (dup2(fd, STDIN_FILENO) < 0) {
                perror("dup2");
                close(fd);
                _exit(127);
            }
            close(fd);
        }

        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
            perror("PTRACE_TRACEME");
            _exit(127);
        }
        execvp(d->prog_path, d->prog_argv);
        perror("execvp");
        _exit(127);
    }

    d->pid = pid;
    d->attached = 0;
    d->state = ST_RUNNING;

    int status;
    if (waitpid(pid, &status, 0) < 0) { perror("waitpid"); return -1; }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "child died before exec\n");
        d->state = ST_EXITED; d->pid = 0;
        return -1;
    }

    post_launch_setup(d);

    printf(ANSI_CYAN "[已启动 pid %d, 加载基址 0x%lx]" ANSI_RESET "\n",
           d->pid, d->base_addr);

    return dbg_continue(d);
}

int dbg_attach(debugger_t *d, pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
        fprintf(stderr, "PTRACE_ATTACH pid=%d: %s\n", pid, strerror(errno));
        return -1;
    }
    int status;
    if (waitpid(pid, &status, 0) < 0) { perror("waitpid"); return -1; }
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "target didn't stop after attach\n");
        return -1;
    }
    d->pid = pid;
    d->attached = 1;
    d->state = ST_STOPPED;
    post_launch_setup(d);
    printf(ANSI_CYAN "[已附着到 pid %d, 加载基址 0x%lx]" ANSI_RESET "\n",
           d->pid, d->base_addr);
    return 0;
}

int dbg_detach(debugger_t *d) {
    if (d->pid <= 0) {
        fprintf(stderr, "当前没有可分离的子进程\n");
        return -1;
    }
    for (breakpoint_t *bp = d->bps; bp; bp = bp->next) {
        if (bp->enabled) bp_disarm(d, bp);
    }
    d->pending_reset_bp = NULL;
    if (ptrace(PTRACE_DETACH, d->pid, 0, 0) == -1) {
        fprintf(stderr, "PTRACE_DETACH: %s\n", strerror(errno));
        return -1;
    }
    printf("[已从 pid %d 分离]\n", d->pid);
    bp_clear_all(d);
    d->pid = 0;
    d->state = ST_NOT_STARTED;
    d->attached = 0;
    return 0;
}
