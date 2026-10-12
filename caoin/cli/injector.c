/*
 * caoin injector/CLI（P2.3+）：
 *   caoin_inject <pid> <agent.so> [hook-spec] [memfd]
 *
 * hook-spec（可选，写入 /data/local/tmp/caoin_config 后注入）：
 *   <mod_pattern 或 @=主程序>|<symbol 或 0xoffset>[|ret=0xhex]
 * 第 4 参数 "memfd"：agent 经目标进程 memfd 加载——maps 无 /data/local/tmp 路径
 * （显示 /memfd:<name> (deleted)），对抗 maps 黑名单扫描。
 *
 * 设计约束：
 *  - 本体静态 glibc，无法 dlsym bionic 符号 → 自解析远程 ELF dynsym
 *  - 远程调用返回捕获：LR=0，函数返回后跳 0 触发 SIGSEGV，读 x0 即返回值
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <asm/ptrace.h>

#define CONFIG_PATH "/data/local/tmp/caoin_config"

#define LOG(...) do { fprintf(stderr, "[caoin] " __VA_ARGS__); fprintf(stderr, "\n"); } while (0)
#define DIE(...) do { LOG(__VA_ARGS__); exit(1); } while (0)

static int g_memfd = -1;

/* ---------- 远程内存读写（/proc/pid/mem） ---------- */

static void rd_mem(uintptr_t addr, void *buf, size_t len)
{
    if (pread(g_memfd, buf, len, (off_t)addr) != (ssize_t)len)
        DIE("remote read @%llx failed: %s", (unsigned long long)addr, strerror(errno));
}

static void wr_mem(uintptr_t addr, const void *buf, size_t len)
{
    if (pwrite(g_memfd, buf, len, (off_t)addr) != (ssize_t)len)
        DIE("remote write @%llx failed: %s", (unsigned long long)addr, strerror(errno));
}

/* ---------- 模块基址（/proc/pid/maps） ---------- */

static uintptr_t find_module(pid_t pid, const char *name)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) DIE("open maps: %s", strerror(errno));

    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, name)) continue;
        uintptr_t start, end, off;
        char perms[8], dev[8], fpath[256] = "";
        int n = sscanf(line, "%lx-%lx %7s %lx %7s %*d %255s",
                       &start, &end, perms, &off, dev, fpath);
        if (n >= 4 && off == 0 && strstr(fpath, name)) {   /* 文件头映射 = 加载基址 */
            base = start;
            break;
        }
    }
    fclose(f);
    return base;
}

/* ---------- 远程 ELF dynsym 解析 ---------- */

/* DT_GNU_HASH 链解析准确符号数 */
static uint32_t gnu_hash_nsyms(uintptr_t gh_addr)
{
    uint32_t hdr[4];    /* nbuckets, symoffset, bloom_size, bloom_shift */
    rd_mem(gh_addr, hdr, sizeof(hdr));
    uint32_t nbuckets = hdr[0], symoffset = hdr[1], bloom_n = hdr[2];

    uint32_t *buckets = malloc((size_t)nbuckets * 4);
    rd_mem(gh_addr + 16 + (uintptr_t)bloom_n * 8, buckets, (size_t)nbuckets * 4);

    uint32_t max = 0;
    for (uint32_t i = 0; i < nbuckets; i++)
        if (buckets[i] > max) max = buckets[i];
    free(buckets);
    if (max < symoffset)
        return symoffset;

    /* 从 max 沿 chain 走到 end 标志（最低位 1） */
    uintptr_t chain_addr = gh_addr + 16 + (uintptr_t)bloom_n * 8 + (uintptr_t)nbuckets * 4;
    uint32_t c;
    uintptr_t ca = chain_addr + (uintptr_t)(max - symoffset) * 4;
    do {
        rd_mem(ca, &c, 4);
        ca += 4;
    } while (!(c & 1));
    return max + 1 + 1;    /* 走过的最后一个含 end 标志也算有效符号 */
}

static uintptr_t remote_symbol(uintptr_t base, const char *name)
{
    Elf64_Ehdr eh;
    rd_mem(base, &eh, sizeof(eh));
    if (memcmp(eh.e_ident, ELFMAG, 4) != 0)
        DIE("remote ELF magic mismatch @%llx", (unsigned long long)base);

    Elf64_Phdr *ph = malloc(sizeof(Elf64_Phdr) * eh.e_phnum);
    rd_mem(base + eh.e_phoff, ph, sizeof(Elf64_Phdr) * eh.e_phnum);

    uintptr_t symtab = 0, strtab = 0, gnuh = 0;
    Elf64_Dyn dyn;
    for (int i = 0; i < eh.e_phnum; i++) {
        if (ph[i].p_type != PT_DYNAMIC) continue;
        uintptr_t da = base + ph[i].p_vaddr;
        for (uintptr_t p = da; p < da + ph[i].p_memsz; p += sizeof(dyn)) {
            rd_mem(p, &dyn, sizeof(dyn));
            if (dyn.d_tag == DT_NULL) break;
            if (dyn.d_tag == DT_SYMTAB)  symtab = base + dyn.d_un.d_ptr;
            if (dyn.d_tag == DT_STRTAB)  strtab = base + dyn.d_un.d_ptr;
            if (dyn.d_tag == DT_GNU_HASH) gnuh = base + dyn.d_un.d_ptr;
        }
    }
    free(ph);
    if (!symtab || !strtab) DIE("no dynsym in remote ELF");

    uint32_t nsyms = gnuh ? gnu_hash_nsyms(gnuh) : (uint32_t)((strtab - symtab) / sizeof(Elf64_Sym));
    LOG("dynsym: %u symbols", nsyms);

    char *strs = malloc(4096);
    Elf64_Sym sym;
    for (uint32_t i = 0; i < nsyms; i++) {
        rd_mem(symtab + (uintptr_t)i * sizeof(sym), &sym, sizeof(sym));
        if (!sym.st_name || sym.st_shndx == SHN_UNDEF) continue;   /* UND 是外部引用，非本模块地址 */
        if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC) continue;
        rd_mem(strtab + sym.st_name, strs, 256);
        strs[255] = 0;
        if (strcmp(strs, name) == 0) {
            free(strs);
            return base + sym.st_value;
        }
    }
    free(strs);
    return 0;
}

/* ---------- 远程调用（aarch64: x0-5 参数，x0 返回，LR=0 触发 SIGSEGV） ---------- */

static struct user_pt_regs g_saved;

static void get_regs(pid_t pid, struct user_pt_regs *r)
{
    struct iovec iov = { r, sizeof(*r) };
    if (ptrace(PTRACE_GETREGSET, pid, (void *)1 /*NT_PRSTATUS*/, &iov) != 0)
        DIE("GETREGSET: %s", strerror(errno));
}

static void set_regs(pid_t pid, struct user_pt_regs *r)
{
    struct iovec iov = { r, sizeof(*r) };
    if (ptrace(PTRACE_SETREGSET, pid, (void *)1, &iov) != 0)
        DIE("SETREGSET: %s", strerror(errno));
}

static uintptr_t call_remote(pid_t pid, uintptr_t func,
                             const uintptr_t args[6])
{
    struct user_pt_regs r = g_saved;
    for (int i = 0; i < 6; i++)
        r.regs[i] = args[i];
    r.regs[30] = 0;         /* LR = 0：返回后跳 0 */
    r.pc = func;
    set_regs(pid, &r);

    if (ptrace(PTRACE_CONT, pid, 0, 0) != 0)
        DIE("CONT: %s", strerror(errno));

    int st;
    if (waitpid(pid, &st, 0) != pid)
        DIE("waitpid");
    if (!WIFSTOPPED(st))
        DIE("target died during remote call (status=%x)", st);

    struct user_pt_regs r2;
    get_regs(pid, &r2);
    if (r2.pc != 0)
        LOG("warn: stop pc=%llx != 0 (sig=%d)", (unsigned long long)r2.pc, WSTOPSIG(st));

    set_regs(pid, &g_saved);       /* 调用完恢复 */
    return (uintptr_t)r2.regs[0];
}

/* ---------- 主流程 ---------- */

static void usage(void)
{
    fprintf(stderr, "usage: caoin_inject <pid> <agent.so> [mod|symbol|0xoff[|ret=0xhex]] [memfd]\n");
    exit(1);
}

/* memfd 加载：目标自建 memfd → so 内容经远程 write 灌入 → /proc/self/fd/N dlopen */
static uintptr_t remote_memfd_dlopen(pid_t pid, uintptr_t f_mmap, uintptr_t f_write,
                                     uintptr_t f_memfd, uintptr_t f_dlopen,
                                     const char *so_data, size_t so_len)
{
    /* 1. 目标内 RW 缓冲 */
    size_t pg = 4096;
    size_t bufsz = (so_len + pg - 1) / pg * pg;
    uintptr_t a_mmap[6] = { 0, bufsz, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, (uintptr_t)-1, 0 };
    uintptr_t buf = call_remote(pid, f_mmap, a_mmap);
    if (buf == (uintptr_t)-1) { LOG("remote mmap failed"); return 0; }

    /* 2. so 内容写入目标缓冲 */
    wr_mem(buf, so_data, so_len);

    /* 3. memfd（名字用无害词，出现在 /memfd:<name> (deleted)） */
    uintptr_t namep = buf + bufsz - 64;      /* 借缓冲尾部放名字 */
    wr_mem(namep, "cache", 6);
    uintptr_t a_mfd[6] = { namep, 0, 0, 0, 0, 0 };
    uintptr_t fd = call_remote(pid, f_memfd, a_mfd);
    LOG("remote memfd = %llx", (unsigned long long)fd);
    if ((long)fd < 0) return 0;

    /* 4. write(fd, buf, so_len)：so 流入 memfd */
    uintptr_t a_wr[6] = { fd, buf, so_len, 0, 0, 0 };
    uintptr_t written = call_remote(pid, f_write, a_wr);
    if (written != so_len) { LOG("remote write=%llx", (unsigned long long)written); return 0; }

    /* 5. 路径 /proc/self/fd/N → dlopen */
    char path[48];
    int n = snprintf(path, sizeof(path), "/proc/self/fd/%d", (int)fd);
    wr_mem(namep, path, (size_t)n + 1);
    uintptr_t a_dl[6] = { namep, RTLD_NOW, 0, 0, 0, 0 };
    uintptr_t handle = call_remote(pid, f_dlopen, a_dl);
    return handle;
}

int main(int argc, char **argv)
{
    if (argc != 3 && argc != 4 && argc != 5) usage();
    pid_t pid = (pid_t)atoi(argv[1]);
    const char *so_path = argv[2];
    const char *spec = argc >= 4 ? argv[3] : 0;
    int use_memfd = argc == 5 && strcmp(argv[4], "memfd") == 0;

    if (spec) {
        FILE *cf = fopen(CONFIG_PATH, "w");
        if (!cf) DIE("write config: %s", strerror(errno));
        fprintf(cf, "%s\n", spec);
        fclose(cf);
        LOG("config written: %s", spec);
    }

    /* 回传文件预建 + 0666：app 域对 /data/local/tmp 目录无写权限，
       agent（app 身份）无法自行创建日志/marker，须注入方预放行 */
    {
        char lp[64];
        snprintf(lp, sizeof(lp), "/data/local/tmp/caoin_log_%d", pid);
        const char *files[2] = { "/data/local/tmp/caoin_agent_marker", lp };
        for (int i = 0; i < 2; i++) {
            int fd = open(files[i], O_CREAT | O_WRONLY, 0666);
            if (fd >= 0) close(fd);
            chmod(files[i], 0666);   /* umask 会削 open 权限位，显式放开 */
        }
    }

    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/mem", pid);
    g_memfd = open(p, O_RDWR);
    if (g_memfd < 0) DIE("open mem: %s", strerror(errno));

    uintptr_t libc = find_module(pid, "libc.so");
    uintptr_t linker = find_module(pid, "linker64");
    if (!libc || !linker) DIE("libc.so/linker64 not found in maps");
    LOG("target libc=%llx linker64=%llx",
        (unsigned long long)libc, (unsigned long long)linker);

    /* bionic 的 dlopen 在 libc 是 UND，真身是 linker 导出的 __loader_dlopen */
    uintptr_t f_mmap = remote_symbol(libc, "mmap");
    uintptr_t f_dlopen = remote_symbol(linker, "__loader_dlopen");
    LOG("mmap=%llx dlopen=%llx",
        (unsigned long long)f_mmap, (unsigned long long)f_dlopen);
    if (!f_mmap || !f_dlopen) DIE("symbol resolve failed");

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0)
        DIE("attach: %s", strerror(errno));
    int st;
    waitpid(pid, &st, 0);
    LOG("attached, target stopped");
    get_regs(pid, &g_saved);

    /* 远程 mmap 一页 RW */
    uintptr_t a_mmap[6] = { 0, 4096, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, (uintptr_t)-1, 0 };
    uintptr_t page = call_remote(pid, f_mmap, a_mmap);
    LOG("remote page = %llx", (unsigned long long)page);
    if (page == (uintptr_t)-1) DIE("remote mmap failed");

    uintptr_t handle;
    if (use_memfd) {
        /* 读本地 so → memfd 路线 */
        FILE *sf = fopen(so_path, "rb");
        if (!sf) DIE("open so: %s", strerror(errno));
        fseek(sf, 0, SEEK_END);
        long so_len = ftell(sf);
        fseek(sf, 0, SEEK_SET);
        char *so_data = malloc((size_t)so_len);
        if (fread(so_data, 1, (size_t)so_len, sf) != (size_t)so_len) DIE("read so");
        fclose(sf);

        uintptr_t f_write = remote_symbol(libc, "write");
        uintptr_t f_memfd = remote_symbol(libc, "memfd_create");
        LOG("write=%llx memfd_create=%llx",
            (unsigned long long)f_write, (unsigned long long)f_memfd);
        if (!f_write || !f_memfd) DIE("write/memfd_create resolve failed");

        handle = remote_memfd_dlopen(pid, f_mmap, f_write, f_memfd, f_dlopen,
                                     so_data, (size_t)so_len);
        free(so_data);
    } else {
        wr_mem(page, so_path, strlen(so_path) + 1);
        uintptr_t a_dlopen[6] = { page, RTLD_NOW, 0, 0, 0, 0 };
        handle = call_remote(pid, f_dlopen, a_dlopen);
    }
    LOG("dlopen handle = %llx", (unsigned long long)handle);

    if (handle == 0) {
        /* 问 linker 拒载原因 */
        uintptr_t f_dlerror = remote_symbol(linker, "__loader_dlerror");
        if (f_dlerror) {
            uintptr_t zero[6] = { 0, 0, 0, 0, 0, 0 };
            uintptr_t errp = call_remote(pid, f_dlerror, zero);
            if (errp) {
                char msg[256] = { 0 };
                rd_mem(errp, msg, sizeof(msg) - 1);
                LOG("dlerror: %s", msg);
            }
        }
    }

    set_regs(pid, &g_saved);
    ptrace(PTRACE_DETACH, pid, 0, 0);

    if (handle == 0) {
        LOG("INJECT FAILED (dlopen returned NULL)");
        return 1;
    }
    LOG("INJECT OK");
    return 0;
}
