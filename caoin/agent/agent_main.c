/*
 * caoin agent（P2.3+）：配置驱动 hook + 通用参数/返回值记录 + dump 动作。
 *
 * 配置 /data/local/tmp/caoin_config，每行一个 hook 点，字段以 | 分隔：
 *   <mod_pattern 或 @=主程序> | <symbol 或 0xoffset> [ | ret=0xhex ] [ | if<N>=0xhex ] [ | s<N> ] [ | m<N>=<len> ]
 *     ret=0xhex  固定返回值（行为验证）
 *     if<N>=0xhex 参数 N 不等于值时静默透传（热点函数过滤）
 *     s<N>       把第 N 个参数(0-7)当 C 字符串记录（orig 调用前抓取）
 *     m<N>=<len> 把第 N 个参数指向的内存 hex 记录 len 字节（上限 256）
 * 最多 CAOIN_MAX_HOOKS 点；# 开头注释。
 *
 * 日志 /data/local/tmp/caoin_log_<pid>：每条 hook 记录 x0-x7、dump、返回值。
 */
#include "../hook/tramp.h"
#include "../hook/platform.h"
#include "symsolve.h"

#define CAOIN_MAX_HOOKS 16
#define CAOIN_SYS_getpid 172

static caoin_hook_t g_hooks[CAOIN_MAX_HOOKS];
static int g_hook_ret_fixed[CAOIN_MAX_HOOKS];   /* 0=透传，非0=固定返回 */
static long g_hook_ret_val[CAOIN_MAX_HOOKS];
static int g_act_str[CAOIN_MAX_HOOKS];          /* -1 无；0-7 记字符串的参数号 */
static int g_act_mem[CAOIN_MAX_HOOKS];          /* -1 无；0-7 记内存的参数号 */
static int g_act_mem_size[CAOIN_MAX_HOOKS];
static int g_act_if[CAOIN_MAX_HOOKS];           /* -1 无；0-7 过滤参数号 */
static long g_act_if_val[CAOIN_MAX_HOOKS];      /* 期望值，不匹配则静默透传 */
static int g_act_sw[CAOIN_MAX_HOOKS];           /* 1=吞掉调用：不调 orig，直接返回（exit 类自杀拦截） */
static int g_nhooks;
static long g_logfd = -1;

/* ---------- 基础小工具（no-libc） ---------- */

static long self_pid(void)
{
    return caoin_sys6(CAOIN_SYS_getpid, 0, 0, 0, 0, 0, 0);
}

static long st_len(const char *s) { long n = 0; while (s[n]) n++; return n; }

static void log_raw(const char *s, long n)
{
    if (g_logfd >= 0)
        caoin_sys6(CAOIN_SYS_write, g_logfd, (long)s, n, 0, 0, 0);
}
static void log_str(const char *s) { log_raw(s, st_len(s)); }

static void log_hex(unsigned long v)
{
    static const char digits[] = "0123456789abcdef";
    char b[19];
    b[0] = '0'; b[1] = 'x';
    int n = 2;
    char t[16];
    int d = 0;
    do { t[d++] = digits[v & 0xF]; v >>= 4; } while (v && d < 16);
    while (d) b[n++] = t[--d];
    log_raw(b, n);
}

/* ---------- 通用 handler ---------- */

typedef long (*orig8_t)(long, long, long, long, long, long, long, long);

static void log_str_safe(const char *s, int max)
{
    log_str("\"");
    for (int i = 0; i < max && s[i]; i++) {
        char c = s[i];
        if (c < 32 || c > 126) c = '.';
        log_raw(&c, 1);
    }
    log_str("\"");
}

static void log_mem_hex(const unsigned char *p, int n)
{
    if (n > 256) n = 256;
    for (int i = 0; i < n; i++) {
        if (i) log_str(" ");
        log_hex(p[i]);
    }
}

static long caoin_generic(int id, long *a)
{
    /* if 过滤：不匹配 → 静默透传（热点函数的最快路径，dump/记录全跳过） */
    int silent = g_act_if[id] >= 0 && a[g_act_if[id]] != g_act_if_val[id];

    /* dump 在 orig 前抓取：调用时刻的数据 */
    if (!silent && g_act_str[id] >= 0) {
        log_str(" s"); log_hex((unsigned long)g_act_str[id]); log_str("=");
        log_str_safe((const char *)a[g_act_str[id]], 128);
    }
    if (!silent && g_act_mem[id] >= 0) {
        log_str(" m"); log_hex((unsigned long)g_act_mem[id]); log_str("=");
        log_mem_hex((const unsigned char *)a[g_act_mem[id]], g_act_mem_size[id]);
    }

    long ret;
    if (g_act_sw[id] && !silent) {
        /* swallow：不调 orig（exit/abort/kill 类自杀拦截），返回 ret= 值或 0 */
        ret = g_hook_ret_fixed[id] ? g_hook_ret_val[id] : 0;
    } else {
        orig8_t orig = (orig8_t)g_hooks[id].tramp;
        ret = orig(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
    }
    if (silent)
        return g_hook_ret_fixed[id] ? g_hook_ret_val[id] : ret;
    if (g_hook_ret_fixed[id])
        ret = g_hook_ret_val[id];

    log_str("#"); log_hex((unsigned long)id);
    log_str(" lr="); log_hex((unsigned long)(intptr_t)__builtin_return_address(0));
    log_str(" a0="); log_hex((unsigned long)a[0]);
    log_str(" a1="); log_hex((unsigned long)a[1]);
    log_str(" a2="); log_hex((unsigned long)a[2]);
    log_str(" a3="); log_hex((unsigned long)a[3]);
    log_str(" a4="); log_hex((unsigned long)a[4]);
    log_str(" a5="); log_hex((unsigned long)a[5]);
    log_str(" a6="); log_hex((unsigned long)a[6]);
    log_str(" a7="); log_hex((unsigned long)a[7]);
    log_str(" ret="); log_hex((unsigned long)ret);
    log_str("\n");
    return ret;
}

#define DEF_HANDLER(n) \
    static long handler_##n(long a0, long a1, long a2, long a3, \
                            long a4, long a5, long a6, long a7) \
    { long a[8] = { a0, a1, a2, a3, a4, a5, a6, a7 }; \
      return caoin_generic(n, a); }

DEF_HANDLER(0)  DEF_HANDLER(1)  DEF_HANDLER(2)  DEF_HANDLER(3)
DEF_HANDLER(4)  DEF_HANDLER(5)  DEF_HANDLER(6)  DEF_HANDLER(7)
DEF_HANDLER(8)  DEF_HANDLER(9)  DEF_HANDLER(10) DEF_HANDLER(11)
DEF_HANDLER(12) DEF_HANDLER(13) DEF_HANDLER(14) DEF_HANDLER(15)

static void *handlers[CAOIN_MAX_HOOKS] = {
    handler_0, handler_1, handler_2, handler_3,
    handler_4, handler_5, handler_6, handler_7,
    handler_8, handler_9, handler_10, handler_11,
    handler_12, handler_13, handler_14, handler_15,
};

/* ---------- 配置解析 ---------- */

static int parse_hex(const char *s, uintptr_t *out)
{
    if (s[0] != '0' || (s[1] != 'x' && s[1] != 'X')) return 0;
    s += 2;
    uintptr_t v = 0;
    int any = 0;
    for (; *s; s++) {
        char c = *s;
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return 0;
        v = (v << 4) | (uintptr_t)d;
        any = 1;
    }
    *out = v;
    return any;
}

/* 行格式 mod|spec[|action...]；mod 为 "@" 表示主程序；action: ret=0x.. / s<N> / m<N>=len */
static void install_line(char *line)
{
    if (line[0] == '#' || line[0] == '\n' || !line[0]) return;
    if (g_nhooks >= CAOIN_MAX_HOOKS) return;

    char *f[6] = { 0, 0, 0, 0, 0, 0 };
    int nf = 0;
    char *p = line;
    f[0] = p;
    for (; *p; p++) {
        if (*p == '|' && nf < 5) { *p = 0; f[++nf] = p + 1; }
        else if (*p == '\n') { *p = 0; break; }
    }
    if (nf < 1) return;

    const char *mod = (f[0][0] == '@' || !f[0][0]) ? 0 : f[0];
    uintptr_t addr = 0;
    if (parse_hex(f[1], &addr) && addr) {
        uintptr_t base = caoin_module_base(mod);
        if (!base) { log_str("ERR base not found\n"); return; }
        addr += base;
    } else {
        addr = caoin_resolve(mod, f[1]);
    }
    if (!addr) {
        extern unsigned long caoin_dbg_base, caoin_dbg_nsyms;
        log_str("ERR resolve failed: "); log_str(f[1]);
        log_str(" base="); log_hex(caoin_dbg_base);
        log_str(" nsyms="); log_hex(caoin_dbg_nsyms);
        log_str("\n");
        return;
    }

    int id = g_nhooks;
    g_act_str[id] = -1;
    g_act_mem[id] = -1;
    g_act_if[id] = -1;
    g_act_sw[id] = 0;
    for (int fi = 2; fi <= nf && f[fi]; fi++) {
        /* 每字段可含 ; 分隔的多个动作 */
        char *seg = f[fi];
        while (seg) {
            char *nx = seg;
            while (*nx && *nx != ';') nx++;
            int has = (*nx == ';');
            if (has) *nx = 0;

            char *a = seg;
            if (a[0] == 'r' && a[1] == 'e' && a[2] == 't' && a[3] == '=') {
                uintptr_t rv;
                if (parse_hex(a + 4, &rv)) {
                    g_hook_ret_fixed[id] = 1;
                    g_hook_ret_val[id] = (long)rv;
                }
            } else if (a[0] == 's' && a[1] == 'w' && !a[2]) {
                g_act_sw[id] = 1;
            } else if (a[0] == 'i' && a[1] == 'f' && a[2] >= '0' && a[2] <= '7'
                       && a[3] == '=') {
                int argn = a[2] - '0';
                uintptr_t v;
                if (parse_hex(a + 4, &v)) {
                    g_act_if[id] = argn;
                    g_act_if_val[id] = (long)v;
                }
            } else if ((a[0] == 's' || a[0] == 'm') && a[1] >= '0' && a[1] <= '7') {
                int argn = a[1] - '0';
                if (a[0] == 's') {
                    g_act_str[id] = argn;
                } else if (a[2] == '=') {
                    int v = 0;
                    for (const char *q = a + 3; *q >= '0' && *q <= '9'; q++)
                        v = v * 10 + (*q - '0');
                    if (v > 0) {
                        g_act_mem[id] = argn;
                        g_act_mem_size[id] = v;
                    }
                }
            }
            seg = has ? nx + 1 : 0;
        }
    }

    int rc = caoin_hook_attach((void *)addr, handlers[id], &g_hooks[id]);
    if (rc != 0) {
        log_str("ERR attach rc="); log_hex((unsigned long)(unsigned int)rc);
        log_str(": "); log_str(f[1]);
        log_str("\n");
        g_hook_ret_fixed[id] = 0;
        g_act_str[id] = -1;
        g_act_mem[id] = -1;
        return;
    }
    log_str("OK #"); log_hex((unsigned long)id);
    log_str(" "); log_str(f[1]);
    log_str(" @"); log_hex((unsigned long)addr);
    log_str("\n");
    g_nhooks++;
}

/* ---------- 入口 ---------- */

static void write_marker(const char *msg)
{
    long n = st_len(msg);
    long fd = caoin_sys6(CAOIN_SYS_openat, -100,
                         (long)"/data/local/tmp/caoin_agent_marker",
                         0x241, 0644, 0, 0);
    if (fd < 0) return;
    caoin_sys6(CAOIN_SYS_write, fd, (long)msg, n, 0, 0, 0);
    caoin_sys6(CAOIN_SYS_close, fd, 0, 0, 0, 0, 0);
}

__attribute__((constructor))
static void caoin_agent_on_load(void)
{
    /* 日志文件：caoin_log_<pid> */
    char path[64];
    const char pre[] = "/data/local/tmp/caoin_log_";
    long n = st_len(pre);
    for (long i = 0; i < n; i++) path[i] = pre[i];
    long pid = self_pid();
    char t[8]; int d = 0;
    do { t[d++] = (char)('0' + pid % 10); pid /= 10; } while (pid);
    while (d) path[n++] = t[--d];
    path[n] = 0;
    g_logfd = caoin_sys6(CAOIN_SYS_openat, -100, (long)path,
                         0x441 /*O_WRONLY|O_CREAT|O_APPEND*/, 0644, 0, 0);

    /* 权限地形自诊断：本域能拿到哪种可执行内存 */
    {
        void *t = caoin_mmap(0, 4096, CAOIN_PROT_RWX, CAOIN_MAP_PRIVATE_ANON, -1, 0);
        log_str("diag rwx_anon="); log_hex((unsigned long)(intptr_t)t); log_str("\n");
        if (t != (void *)-1) caoin_munmap(t, 4096);
        long fd = caoin_memfd_create();
        log_str("diag memfd="); log_hex((unsigned long)fd); log_str("\n");
        if (fd >= 0) {
            void *r = caoin_mmap(0, 4096, CAOIN_PROT_RX, 0x1, (int)fd, 0);
            log_str("diag memfd_rx="); log_hex((unsigned long)(intptr_t)r); log_str("\n");
            if (r != (void *)-1) caoin_munmap(r, 4096);
            caoin_close_fd(fd);
        }
    }

    /* 配置 */
    static char cfg[4096];
    long fd = caoin_sys6(CAOIN_SYS_openat, -100,
                         (long)"/data/local/tmp/caoin_config", 0, 0, 0, 0);
    if (fd < 0) { write_marker("no-config"); return; }
    long r = caoin_sys6(CAOIN_SYS_read, fd, (long)cfg, sizeof(cfg) - 1, 0, 0, 0);
    caoin_sys6(CAOIN_SYS_close, fd, 0, 0, 0, 0, 0);
    if (r <= 0) { write_marker("empty-config"); return; }
    cfg[r] = 0;

    char *line = cfg;
    while (line && *line) {
        char *nl = line;
        while (*nl && *nl != '\n') nl++;
        int has_nl = *nl == '\n';
        if (has_nl) *nl = 0;
        install_line(line);
        line = has_nl ? nl + 1 : 0;
    }

    write_marker(g_nhooks > 0 ? "hooks-installed" : "no-hooks");

    /* 模块布局快照（日志尾部）：死后离线定位 LR/参数地址落在哪个 so */
    {
        long mfd = caoin_sys6(CAOIN_SYS_openat, -100, (long)"/proc/self/maps", 0, 0, 0, 0);
        if (mfd >= 0) {
            static char mbuf[4096];
            log_str("\n== maps begin ==\n");
            for (;;) {
                long r = caoin_sys6(CAOIN_SYS_read, mfd, (long)mbuf, sizeof(mbuf), 0, 0, 0);
                if (r <= 0) break;
                log_raw(mbuf, r);
            }
            caoin_sys6(CAOIN_SYS_close, mfd, 0, 0, 0, 0, 0);
            log_str("== maps end ==\n");
        }
    }
}
