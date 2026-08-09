#include "debugger.h"
#include "command.h"
#include "disasm.h"
#include "symbols.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <readline/readline.h>
#include <readline/history.h>

static void banner(void) {
    printf(ANSI_BOLD ANSI_CYAN
           "mini_gdb  —  基于 ptrace 的简易调试器 (x86_64)\n"
           ANSI_RESET
           "输入 `help` 查看命令列表, `q` 退出\n\n");
}

static void usage(const char *arg0) {
    fprintf(stderr,
        "用法: %s <程序> [参数...]\n"
        "      %s -p <pid>\n", arg0, arg0);
}

/* Readline completion over command names. */
static char *cmd_generator(const char *text, int state) {
    static size_t idx;
    static size_t len;
    size_t n;
    const command_t *tbl = cmd_table(&n);
    if (!state) { idx = 0; len = strlen(text); }
    while (idx < n) {
        const command_t *c = &tbl[idx++];
        if (strncasecmp(c->name, text, len) == 0)
            return strdup(c->name);
    }
    return NULL;
}

static char **completer(const char *text, int start, int end) {
    (void)end;
    if (start == 0) return rl_completion_matches(text, cmd_generator);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 1; }

    debugger_t d;

    if (strcmp(argv[1], "-p") == 0) {
        if (argc < 3) { usage(argv[0]); return 1; }
        dbg_init(&d, NULL, NULL, 0);
        pid_t pid = (pid_t)atoi(argv[2]);
        banner();
        if (dbg_attach(&d, pid) != 0) return 1;
    } else {
        /* Build tracee argv (must be NULL-terminated). */
        char **prog_argv = calloc((size_t)argc, sizeof(char *));
        if (!prog_argv) return 1;
        for (int i = 1; i < argc; i++) prog_argv[i - 1] = argv[i];
        prog_argv[argc - 1] = NULL;

        dbg_init(&d, argv[1], prog_argv, argc - 1);
        banner();
        /* Preload symbols with base=0 so `info sym` and `b <symbol>` work
           before the child exists; dbg_run() will shift breakpoints and
           reload the table once the PIE base is known. */
        symbols_load(&d, argv[1]);
        printf("[已加载 %s%s,先 `b <符号>` 再 `r` 启动]\n",
               argv[1], d.is_pie ? " (PIE)" : "");
    }

    rl_readline_name = "mini_gdb";
    rl_attempted_completion_function = completer;
    using_history();
    read_history(".mini_gdb_history");

    for (;;) {
        char prompt[64];
        const char *state = "无进程";
        switch (d.state) {
            case ST_NOT_STARTED: state = "空闲"; break;
            case ST_RUNNING:     state = "运行"; break;
            case ST_STOPPED:     state = "停下"; break;
            case ST_EXITED:      state = "退出"; break;
        }
        snprintf(prompt, sizeof(prompt),
                 ANSI_BOLD ANSI_BLUE "(mgdb %s)" ANSI_RESET " ", state);
        char *line = readline(prompt);
        if (!line) { printf("\n"); break; }
        if (*line) add_history(line);
        int keep = cmd_dispatch(&d, line);
        free(line);
        if (!keep) break;
    }

    write_history(".mini_gdb_history");
    disasm_shutdown(&d);
    dbg_shutdown(&d);
    return 0;
}
