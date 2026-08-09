#ifndef MINI_GDB_H
#define MINI_GDB_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <capstone/capstone.h>

typedef struct breakpoint {
    uint64_t addr;
    uint64_t original_word;
    int enabled;
    int is_temp;
    int id;
    struct breakpoint *next;
} breakpoint_t;

typedef struct symbol {
    char *name;
    uint64_t addr;
    uint64_t size;
    unsigned char st_info;
    struct symbol *next;
} symbol_t;

typedef enum {
    ST_NOT_STARTED = 0,
    ST_RUNNING,
    ST_STOPPED,
    ST_EXITED,
} dbg_state_t;

/* 前置声明,避免和 libc.h 循环依赖 */
struct libc_ctx;

typedef struct debugger {
    pid_t pid;
    char *prog_path;
    char **prog_argv;
    int prog_argc;
    char *input_file;         /* 输入重定向文件路径 (用于 r < file) */
    dbg_state_t state;
    int last_signal;
    uint64_t base_addr;
    int is_pie;
    breakpoint_t *bps;
    int next_bp_id;
    symbol_t *symbols;
    csh cs_handle;
    int cs_ready;
    breakpoint_t *pending_reset_bp;
    int attached;
    struct libc_ctx *libc;    /* 首次 heap/bins 命令时懒加载 */
    int libc_symbols_loaded;  /* libc 符号是否已合并到 d->symbols */
} debugger_t;

#define ANSI_RED     "\x1b[31m"
#define ANSI_GREEN   "\x1b[32m"
#define ANSI_YELLOW  "\x1b[33m"
#define ANSI_BLUE    "\x1b[34m"
#define ANSI_MAGENTA "\x1b[35m"
#define ANSI_CYAN    "\x1b[36m"
#define ANSI_BOLD    "\x1b[1m"
#define ANSI_DIM     "\x1b[2m"
#define ANSI_RESET   "\x1b[0m"

#endif
