#include "command.h"
#include "debugger.h"
#include "breakpoint.h"
#include "symbols.h"
#include "disasm.h"
#include "memory.h"
#include "registers.h"
#include "backtrace.h"
#include "heap.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>

/* Forward decls for handlers. */
static int h_run(debugger_t *d, int argc, char **argv);
static int h_start(debugger_t *d, int argc, char **argv);
static int h_continue(debugger_t *d, int argc, char **argv);
static int h_step(debugger_t *d, int argc, char **argv);
static int h_next(debugger_t *d, int argc, char **argv);
static int h_finish(debugger_t *d, int argc, char **argv);
static int h_quit(debugger_t *d, int argc, char **argv);
static int h_break(debugger_t *d, int argc, char **argv);
static int h_delete(debugger_t *d, int argc, char **argv);
static int h_info(debugger_t *d, int argc, char **argv);
static int h_regs(debugger_t *d, int argc, char **argv);
static int h_set(debugger_t *d, int argc, char **argv);
static int h_bt(debugger_t *d, int argc, char **argv);
static int h_disas(debugger_t *d, int argc, char **argv);
static int h_nearpc(debugger_t *d, int argc, char **argv);
static int h_vmmap(debugger_t *d, int argc, char **argv);
static int h_examine(debugger_t *d, int argc, char **argv);
static int h_attach(debugger_t *d, int argc, char **argv);
static int h_detach(debugger_t *d, int argc, char **argv);
static int h_heap(debugger_t *d, int argc, char **argv);
static int h_tcache(debugger_t *d, int argc, char **argv);
static int h_bins(debugger_t *d, int argc, char **argv);
static int h_help(debugger_t *d, int argc, char **argv);

/* Return code convention: >=0 = keep looping, -1 = error but keep looping,
   -99 = quit. */

static const command_t kCmds[] = {
    { "run",         { "r", NULL },              h_run,      "启动(或重启)被调试程序",
      "run [args...]   fork+exec 目标进程,可选参数会传给子进程" },
    { "start",       { NULL },                   h_start,    "启动并停在 main 入口",
      "start [args...] 在 main 处下临时断点后 run,程序会停在 main 第一条指令\n"
      "                (要求 ELF 里存在名为 main 的符号,通常是没被 strip 的可执行文件)" },
    { "continue",    { "c", "cont", NULL },      h_continue, "继续执行",
      "continue        从当前停下的地方恢复运行,直到下一次断点/信号/退出" },
    { "step",        { "s", "stepi", "si", NULL }, h_step,   "单条汇编指令步进",
      "step            执行一条机器指令后停下(不区分函数边界)" },
    { "next",        { "n", "nexti", "ni", NULL }, h_next,   "步过 CALL 指令",
      "next            若当前指令是 CALL,在返回地址下临时断点后继续,否则等价 step" },
    { "finish",      { NULL },                   h_finish,   "运行到当前函数返回",
      "finish          用 libunwind 上滑一帧拿到返回地址,下临时断点后继续" },
    { "quit",        { "q", "exit", NULL },      h_quit,     "退出调试器",
      "quit            退出;若子进程还活着会先 kill/detach 干净" },
    { "break",       { "b", NULL },              h_break,    "设置断点",
      "break <目标>    目标可以是: 0xADDR / 符号名 / 符号+偏移(如 main+0x10)\n"
      "                run 之前设置的符号断点会在启动后按 PIE 基址自动重定位" },
    { "delete",      { "d", "del", NULL },       h_delete,   "删除断点",
      "delete <编号>   编号见 `info break`" },
    { "info",        { "i", NULL },              h_info,     "info break / info sym[bols] [过滤词]",
      "info break              列出所有断点\n"
      "info sym[bols] [过滤]   列出符号表(可选子串过滤)" },
    { "registers",   { "regs", "reg", NULL },    h_regs,     "显示寄存器",
      "registers [name]  不带参数打印全部通用/段/标志寄存器;带 name 只打印一个" },
    { "set",         { NULL },                   h_set,      "修改寄存器",
      "set <寄存器> <值>   例如: set rax 0xdead" },
    { "backtrace",   { "bt", "stack", NULL },    h_bt,       "调用栈回溯(libunwind)",
      "backtrace       打印当前调用栈;每帧解析为 符号+偏移" },
    { "disassemble", { "disas", "dis", NULL },   h_disas,    "反汇编",
      "disassemble <addr|符号> [条数]\n"
      "                不给条数时,若目标是函数则按符号 size 估算,否则默认 16 条" },
    { "nearpc",      { "pc", NULL },             h_nearpc,   "反汇编 RIP 附近",
      "nearpc [条数]   默认 12 条,并用 => 标出 RIP 所在行" },
    { "vmmap",       { "maps", "vm", NULL },     h_vmmap,    "显示 /proc/pid/maps",
      "vmmap           打印内存映射,包含 RIP 的段用 * 高亮" },
    { "examine",     { "x", NULL },              h_examine,  "查看内存(GDB 风格 x/Nfmt)",
      "x/<数量><格式><大小> <地址>\n"
      "  格式: x=十六进制 d=十进制 u=无符号 o=八进制 s=字符串 i=反汇编\n"
      "  大小: b=1字节 h=2字节 w=4字节 g=8字节\n"
      "  地址可用 $reg(如 $rsp)、符号名或数字\n"
      "  例: x/16xb main   x/4gx $rsp   x/s 0x400500   x/8i $rip" },
    { "attach",      { NULL },                   h_attach,   "附着到已运行进程",
      "attach <pid>    通过 PTRACE_ATTACH 附着,子进程会立刻停在 SIGSTOP" },
    { "detach",      { NULL },                   h_detach,   "分离当前 tracee",
      "detach          卸掉所有 INT3 后 PTRACE_DETACH,子进程继续独立运行" },
    { "heap",        { NULL },                   h_heap,     "遍历 [heap] 段的 malloc chunk",
      "heap [最大数量]  从 /proc/pid/maps 里找到 [heap] 段,按 malloc_chunk 结构\n"
      "                依次解析,打印每块的地址/大小/标志(A/M/P)/是否 in-use。\n"
      "                默认最多 256 块。仅支持 glibc x86_64。" },
    { "tcache",      { NULL },                   h_tcache,   "打印当前线程的 tcache",
      "tcache          解析 [heap] 起始的 tcache_perthread_struct,列出每个非空 bin\n"
      "                的 count 和链表。glibc 2.32+ 自动解 safe-linking。" },
    { "bins",        { NULL },                   h_bins,     "打印 main_arena 的 fastbins/unsorted/small/large",
      "bins            从 main_arena 读 fastbinsY[] 和 bins[],遍历每个非空 bin。\n"
      "                需要能定位 main_arena 符号,通常靠 libc6-dbg。" },
    { "help",        { "?", "h", NULL },         h_help,     "显示帮助",
      "help [命令]     不带参数列出所有命令;带命令名显示详细说明" },
};
#define NCMDS (sizeof(kCmds) / sizeof(kCmds[0]))

const command_t *cmd_table(size_t *out_n) {
    if (out_n) *out_n = NCMDS;
    return kCmds;
}

static int name_matches(const command_t *c, const char *tok) {
    if (strcasecmp(c->name, tok) == 0) return 1;
    for (int i = 0; c->aliases[i]; i++)
        if (strcasecmp(c->aliases[i], tok) == 0) return 1;
    return 0;
}

static const command_t *find_cmd(const char *tok) {
    for (size_t i = 0; i < NCMDS; i++)
        if (name_matches(&kCmds[i], tok)) return &kCmds[i];
    return NULL;
}

/* Simple whitespace tokenizer.  argv points into `line` (which is mutated). */
static int tokenize(char *line, char **argv, int max) {
    int argc = 0;
    char *p = line;
    while (*p && argc < max) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) break;
        argv[argc++] = p;
        while (*p && !isspace((unsigned char)*p)) p++;
        if (*p) *p++ = '\0';
    }
    return argc;
}

int cmd_dispatch(debugger_t *d, char *line) {
    /* Strip trailing whitespace / comments */
    for (size_t i = strlen(line); i > 0 && isspace((unsigned char)line[i - 1]); i--)
        line[i - 1] = '\0';
    if (!*line) return 1;

    char *argv[32];
    int argc = tokenize(line, argv, 32);
    if (argc == 0) return 1;

    /* Special case: GDB-style x/Nfmt tokens (e.g. "x/4gx", "x/s", "x/16xb")
       route to the `examine` handler, which will parse the format spec from
       argv[0] itself. */
    const command_t *c = NULL;
    if (argv[0][0] == 'x' && argv[0][1] == '/') {
        c = find_cmd("examine");
    } else {
        c = find_cmd(argv[0]);
    }
    if (!c) {
        fprintf(stderr, "未知命令: %s  (输入 `help` 查看列表)\n", argv[0]);
        return 1;
    }
    int rc = c->handler(d, argc, argv);
    if (rc == -99) return 0;
    return 1;
}

/* ================= handlers ================= */

static int h_run(debugger_t *d, int argc, char **argv) {
    /* 清除之前的输入重定向 */
    free(d->input_file);
    d->input_file = NULL;

    /* 解析输入重定向: r < file 或 r arg1 arg2 < file */
    int redirect_idx = -1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "<") == 0) {
            redirect_idx = i;
            break;
        }
    }

    if (redirect_idx > 0) {
        /* 找到了 < */
        if (redirect_idx + 1 >= argc) {
            fprintf(stderr, "错误: '<' 后缺少文件名\n");
            return 1;
        }
        d->input_file = strdup(argv[redirect_idx + 1]);
        /* 移除 < file 部分，保留前面的参数 */
        argc = redirect_idx;
    }

    /* Rebuild prog_argv from remaining args (argv[0] retained as prog_path). */
    if (argc > 1) {
        /* keep existing prog_argv[0], override the rest */
        static char *new_argv[64];
        new_argv[0] = d->prog_path;
        int i;
        for (i = 1; i < argc && i < 63; i++) new_argv[i] = argv[i];
        new_argv[i] = NULL;
        d->prog_argv = new_argv;
    }

    if (d->input_file) {
        printf("[将从文件读取输入: %s]\n", d->input_file);
    }

    return dbg_run(d);
}

static int h_start(debugger_t *d, int argc, char **argv) {
    /* 复用 h_run 的 argv 覆盖逻辑(如果用户传了额外参数) */
    const symbol_t *s = symbols_by_name(d, "main");
    if (!s) {
        fprintf(stderr, "找不到符号 main —— 可执行文件可能被 strip 过,"
                        "改用 `b <地址> && r` 手动下断点\n");
        return -1;
    }
    /* 主符号在 run 之前的地址仍是文件相对值(base=0),post_launch_setup
       会跟其它 pre-run 断点一起按 PIE 基址整体 shift。 */
    breakpoint_t *tbp = bp_add(d, s->addr, 1);
    if (!tbp) return -1;
    printf("[临时断点 %d @ main = 0x%lx]\n", tbp->id, s->addr);
    return h_run(d, argc, argv);
}

static int h_continue(debugger_t *d, int argc, char **argv) {
    return dbg_continue(d);
}

static int h_step(debugger_t *d, int argc, char **argv) {
    return dbg_stepi(d);
}

static int h_next(debugger_t *d, int argc, char **argv) {
    return dbg_nexti(d);
}

static int h_finish(debugger_t *d, int argc, char **argv) {
    return dbg_finish(d);
}

static int h_quit(debugger_t *d, int argc, char **argv) {
    return -99;
}

static int h_break(debugger_t *d, int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "用法: break <地址|符号|符号+偏移>\n"); return -1; }
    uint64_t addr;
    if (symbols_resolve(d, argv[1], &addr) != 0) return -1;
    bp_add(d, addr, 0);
    return 0;
}

static int h_delete(debugger_t *d, int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "用法: delete <编号>\n"); return -1; }
    int id = atoi(argv[1]);
    return bp_remove_by_id(d, id);
}

static int h_info(debugger_t *d, int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "用法: info break | info sym[bols] [过滤词]\n");
        return -1;
    }
    if (strncasecmp(argv[1], "break", strlen(argv[1])) == 0 && strlen(argv[1]) >= 1) {
        bp_list(d);
        return 0;
    }
    if (strncasecmp(argv[1], "sym", 3) == 0) {
        symbols_print(d, argc > 2 ? argv[2] : NULL);
        return 0;
    }
    fprintf(stderr, "info 未识别的子命令: %s\n", argv[1]);
    return -1;
}

static int h_regs(debugger_t *d, int argc, char **argv) {
    if (dbg_require_stopped(d) != 0) return -1;
    return regs_print(d->pid, argc >= 2 ? argv[1] : NULL);
}

static int h_set(debugger_t *d, int argc, char **argv) {
    if (dbg_require_stopped(d) != 0) return -1;
    if (argc < 3) { fprintf(stderr, "用法: set <寄存器> <值>\n"); return -1; }
    char *end;
    errno = 0;
    uint64_t v = strtoull(argv[2], &end,
        (argv[2][0] == '0' && (argv[2][1] == 'x' || argv[2][1] == 'X')) ? 16 : 0);
    if (errno || *end) { fprintf(stderr, "无法解析的数值: %s\n", argv[2]); return -1; }
    if (regs_write_by_name(d->pid, argv[1], v) != 0) return -1;
    printf("%s = 0x%lx\n", argv[1], v);
    return 0;
}

static int h_bt(debugger_t *d, int argc, char **argv) {
    if (dbg_require_stopped(d) != 0) return -1;
    return bt_print(d);
}

static int h_disas(debugger_t *d, int argc, char **argv) {
    if (dbg_require_stopped(d) != 0) return -1;
    if (argc < 2) { fprintf(stderr, "用法: disas <地址|符号> [条数]\n"); return -1; }
    uint64_t addr;
    if (symbols_resolve(d, argv[1], &addr) != 0) return -1;
    int count = argc >= 3 ? atoi(argv[2]) : 0;
    if (count == 0) {
        const symbol_t *s = symbols_by_addr(d, addr);
        if (s && s->size) {
            /* Rough estimate: ~3 bytes per x86-64 insn on average. */
            count = (int)(s->size / 3 + 4);
        } else {
            count = 16;
        }
    }
    struct user_regs_struct r;
    regs_get(d->pid, &r);
    return disasm_at(d, addr, count, r.rip);
}

static int h_nearpc(debugger_t *d, int argc, char **argv) {
    if (dbg_require_stopped(d) != 0) return -1;
    return disasm_nearpc(d, argc >= 2 ? atoi(argv[1]) : 0);
}

static int h_vmmap(debugger_t *d, int argc, char **argv) {
    if (d->pid <= 0) { fprintf(stderr, "当前没有被调试进程\n"); return -1; }
    uint64_t rip = 0;
    if (d->state == ST_STOPPED) {
        struct user_regs_struct r;
        if (regs_get(d->pid, &r) == 0) rip = r.rip;
    }
    mem_print_maps(d->pid, rip);
    return 0;
}

/* Parse `x`, `x/<n><fmt><size>`, `x/xg`, etc.  Defaults: 4 words in hex. */
static int parse_x_spec(const char *tok, int *count, char *fmt, char *sz) {
    *count = 4; *fmt = 'x'; *sz = 'w';
    const char *slash = strchr(tok, '/');
    if (!slash) return 0;
    const char *p = slash + 1;
    const char *digit_start = p;
    while (*p && isdigit((unsigned char)*p)) p++;
    if (p > digit_start) {
        *count = atoi(digit_start);
        if (*count <= 0) *count = 1;
    }
    while (*p) {
        if (strchr("xdoutsi", *p)) *fmt = *p;
        else if (strchr("bhwg", *p)) *sz = *p;
        p++;
    }
    return 0;
}

static size_t sz_bytes(char sz) {
    switch (sz) { case 'b': return 1; case 'h': return 2; case 'w': return 4; case 'g': return 8; }
    return 4;
}

static int h_examine(debugger_t *d, int argc, char **argv) {
    if (dbg_require_stopped(d) != 0) return -1;
    if (argc < 2) { fprintf(stderr, "用法: x/<数量><格式><大小> <地址>\n"); return -1; }
    int count; char fmt, sz;
    if (parse_x_spec(argv[0], &count, &fmt, &sz) != 0) return -1;

    /* 地址支持 $reg(如 $rsp) */
    uint64_t addr;
    if (argv[1][0] == '$') {
        if (regs_read_by_name(d->pid, argv[1] + 1, &addr) != 0) {
            fprintf(stderr, "未知寄存器: %s\n", argv[1]);
            return -1;
        }
    } else if (symbols_resolve(d, argv[1], &addr) != 0) {
        return -1;
    }

    if (fmt == 's') {
        char buf[512];
        ssize_t n = mem_read_string(d->pid, addr, buf, sizeof(buf));
        if (n < 0) { fprintf(stderr, "读取失败\n"); return -1; }
        printf("0x%lx: \"%s\"\n", addr, buf);
        return 0;
    }
    if (fmt == 'i') {
        return disasm_at(d, addr, count, 0);
    }

    size_t unit = sz_bytes(sz);
    size_t total = (size_t)count * unit;
    uint8_t *buf = calloc(1, total);
    if (!buf) return -1;
    if (mem_read(d->pid, addr, buf, total) != 0) {
        fprintf(stderr, "读取 0x%lx 处内存失败\n", addr);
        free(buf); return -1;
    }
    int per_line = unit == 1 ? 16 : (unit == 2 ? 8 : (unit == 4 ? 4 : 2));
    for (int i = 0; i < count; i++) {
        if (i % per_line == 0) printf("0x%lx: ", addr + i * unit);
        uint64_t v = 0;
        memcpy(&v, buf + i * unit, unit);
        switch (fmt) {
            case 'd': printf("%*ld ", (int)(unit * 2), (long)v);         break;
            case 'u': printf("%*lu ", (int)(unit * 2), (unsigned long)v); break;
            case 'o': printf("0%*lo ", (int)(unit * 2), (unsigned long)v); break;
            case 'x':
            default:  printf("0x%0*lx ", (int)(unit * 2), (unsigned long)v); break;
        }
        if ((i + 1) % per_line == 0 || i == count - 1) printf("\n");
    }
    free(buf);
    return 0;
}

static int h_attach(debugger_t *d, int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "用法: attach <pid>\n"); return -1; }
    pid_t pid = (pid_t)atoi(argv[1]);
    return dbg_attach(d, pid);
}

static int h_detach(debugger_t *d, int argc, char **argv) {
    return dbg_detach(d);
}

static int h_heap(debugger_t *d, int argc, char **argv) {
    if (dbg_require_stopped(d) != 0) return -1;
    int max_chunks = argc >= 2 ? atoi(argv[1]) : 0;
    return heap_dump(d, max_chunks);
}

static int h_tcache(debugger_t *d, int argc, char **argv) {
    if (dbg_require_stopped(d) != 0) return -1;
    return heap_tcache(d);
}

static int h_bins(debugger_t *d, int argc, char **argv) {
    if (dbg_require_stopped(d) != 0) return -1;
    return heap_bins(d);
}

static int h_help(debugger_t *d, int argc, char **argv) {
    if (argc >= 2) {
        const command_t *c = find_cmd(argv[1]);
        if (!c) { fprintf(stderr, "没有这个命令: %s\n", argv[1]); return -1; }
        printf(ANSI_BOLD "%s" ANSI_RESET, c->name);
        for (int i = 0; c->aliases[i]; i++) printf(", %s", c->aliases[i]);
        printf("\n  %s\n", c->help_short);
        if (c->help_long) printf("\n%s\n", c->help_long);
        return 0;
    }
    printf(ANSI_BOLD "mini_gdb 命令列表" ANSI_RESET
           " (输入 `help <命令>` 查看详情):\n");
    for (size_t i = 0; i < NCMDS; i++) {
        char buf[64];
        int off = snprintf(buf, sizeof(buf), "%s", kCmds[i].name);
        for (int j = 0; kCmds[i].aliases[j] && off < (int)sizeof(buf); j++) {
            off += snprintf(buf + off, sizeof(buf) - off, "|%s", kCmds[i].aliases[j]);
        }
        printf("  %-24s  %s\n", buf, kCmds[i].help_short);
    }
    return 0;
}
