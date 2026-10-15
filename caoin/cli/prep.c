/*
 * caoin_prep — caoin KPM 流程自动化准备（符号解析 + 远程页准备）
 *
 * 用法: caoin_prep <pid> <module_pat|@> <symbol>
 *   → 打印可直接喂给 caoin-shadow 的 args:
 *       pid=0x... tva=0x... shva=0x... sva=0x...
 *
 * 解决的问题：当前 KPM 流程要求目标进程自备影子页/status 页并输出 CFG
 * （tdyn4 专用）。实战目标不会配合。本工具在**准备阶段**用 ptrace 完成：
 *   1. /proc/pid/maps 找模块基址 → 远程 ELF dynsym 解析符号 → tva
 *      （tva 为函数真实地址，页内偏移由 KPM 自动推导 shva_off）
 *   2. 远程 mmap 影子页(RW) → shva
 *   3. 拷贝受管页 [tva & ~0xFFF, +4K) → shva（影子页 = 原页快照）
 *   4. 远程 mmap status 页 → sva
 *   5. detach —— 运行期无 ptrace 痕迹（准备期痕迹可接受）
 *
 * 与 cli/injector.c 同源：静态 glibc，rd/wr_mem 走 /proc/pid/mem，
 * call_remote 走 ptrace 远程调用（aarch64 x0-x5，LR=0 捕获返回）。
 *
 * 限制：只能解析**动态符号**（DT_SYMTAB）。主程序 local 符号需 -rdynamic
 * 或目标为共享库（实战主场景：libc/libxxx.so 的导出符号）。
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
#include <asm/ptrace.h>

#define LOG(...) do { fprintf(stderr, "[prep] " __VA_ARGS__); fprintf(stderr, "\n"); } while (0)
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

/* name == "@" 时返回第一个文件映射（主程序，PIE 主程序总在最低地址） */
static uintptr_t find_module(pid_t pid, const char *name)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f) DIE("open maps: %s", strerror(errno));

    int main_prog = (name[0] == '@');
    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        uintptr_t start, end, off;
        char perms[8], dev[8], fpath[256] = "";
        int n = sscanf(line, "%lx-%lx %7s %lx %7s %*d %255s",
                       &start, &end, perms, &off, dev, fpath);
        if (n < 5 || off != 0 || fpath[0] != '/') continue;
        if (main_prog || strstr(fpath, name)) { base = start; break; }
    }
    fclose(f);
    return base;
}

/* ---------- 远程 ELF dynsym 解析（同 injector.c） ---------- */

static uint32_t gnu_hash_nsyms(uintptr_t gh_addr)
{
    uint32_t hdr[4];
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

    uintptr_t chain_addr = gh_addr + 16 + (uintptr_t)bloom_n * 8 + (uintptr_t)nbuckets * 4;
    uint32_t c;
    uintptr_t ca = chain_addr + (uintptr_t)(max - symoffset) * 4;
    do {
        rd_mem(ca, &c, 4);
        ca += 4;
    } while (!(c & 1));
    return max + 2;
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
    if (!symtab || !strtab) DIE("no dynsym in remote ELF (local 符号需 -rdynamic)");

    uint32_t nsyms = gnuh ? gnu_hash_nsyms(gnuh)
                          : (uint32_t)((strtab - symtab) / sizeof(Elf64_Sym));
    nsyms += 8;   /* 余量：GNU hash 边界算法可能少算最后一个符号（真机踩坑：
                   * 目标符号恰为 dynsym 末项时被漏掉 → "symbol not found"） */
    LOG("dynsym: ~%u symbols", nsyms);

    char strs[256];
    Elf64_Sym sym;
    for (uint32_t i = 0; i < nsyms; i++) {
        uintptr_t rec = symtab + (uintptr_t)i * sizeof(sym);
        if (rec + sizeof(sym) > strtab)   /* 越过 dynsym 区（通常紧邻 dynstr）*/
            break;
        rd_mem(rec, &sym, sizeof(sym));
        if (!sym.st_name || sym.st_shndx == SHN_UNDEF) continue;
        if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC) continue;
        if (sym.st_name > 0x100000) continue;   /* 名字偏移不合理（余量读到的垃圾项）*/
        rd_mem(strtab + sym.st_name, strs, sizeof(strs));
        strs[sizeof(strs) - 1] = 0;
        if (strcmp(strs, name) == 0)
            return base + sym.st_value;
    }
    return 0;
}

/* ---------- 远程调用（aarch64: x0-5 参数，x0 返回，LR=0 触发 SIGSEGV） ---------- */

static struct user_pt_regs g_saved;

static void get_regs(pid_t pid, struct user_pt_regs *r)
{
    struct iovec iov = { r, sizeof(*r) };
    if (ptrace(PTRACE_GETREGSET, pid, (void *)1, &iov) != 0)
        DIE("GETREGSET: %s", strerror(errno));
}

static void set_regs(pid_t pid, struct user_pt_regs *r)
{
    struct iovec iov = { r, sizeof(*r) };
    if (ptrace(PTRACE_SETREGSET, pid, (void *)1, &iov) != 0)
        DIE("SETREGSET: %s", strerror(errno));
}

static uintptr_t call_remote(pid_t pid, uintptr_t func, const uintptr_t args[6])
{
    struct user_pt_regs r = g_saved;
    for (int i = 0; i < 6; i++) r.regs[i] = args[i];
    r.regs[30] = 0;             /* LR = 0：返回后跳 0 */
    r.pc = func;
    set_regs(pid, &r);
    if (ptrace(PTRACE_CONT, pid, 0, 0) != 0) DIE("CONT: %s", strerror(errno));

    int st;
    if (waitpid(pid, &st, 0) != pid) DIE("waitpid");
    if (!WIFSTOPPED(st)) DIE("target died during remote call (status=%x)", st);

    struct user_pt_regs r2;
    get_regs(pid, &r2);
    set_regs(pid, &g_saved);
    return (uintptr_t)r2.regs[0];
}

static void usage(void)
{
    fprintf(stderr, "usage: caoin_prep <pid> <module_pat|@> <symbol>\n");
    exit(1);
}

int main(int argc, char **argv)
{
    if (argc != 4) usage();
    pid_t pid = (pid_t)atoi(argv[1]);
    const char *module = argv[2];
    const char *symbol = argv[3];

    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/mem", pid);
    g_memfd = open(p, O_RDWR);
    if (g_memfd < 0) DIE("open mem: %s", strerror(errno));

    uintptr_t base = find_module(pid, module);
    if (!base) DIE("module not found in maps: %s", module);
    LOG("module base = %llx", (unsigned long long)base);

    uintptr_t tva = remote_symbol(base, symbol);
    if (!tva) DIE("symbol not found: %s", symbol);
    LOG("symbol %s = %llx (page off %llx)", symbol,
        (unsigned long long)tva, (unsigned long long)(tva & 0xFFF));

    uintptr_t libc = find_module(pid, "libc.so");
    if (!libc) DIE("libc.so not found");
    uintptr_t f_mmap = remote_symbol(libc, "mmap");
    if (!f_mmap) DIE("mmap not resolvable in libc");

    if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0)
        DIE("attach: %s", strerror(errno));
    int st;
    waitpid(pid, &st, 0);
    get_regs(pid, &g_saved);

    /* 远程 mmap 影子页 + status 页（RW 匿名） */
    uintptr_t a_sh[6] = { 0, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, (uintptr_t)-1, 0 };
    uintptr_t shva = call_remote(pid, f_mmap, a_sh);
    uintptr_t a_sv[6] = { 0, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, (uintptr_t)-1, 0 };
    uintptr_t sva = call_remote(pid, f_mmap, a_sv);
    if (shva == (uintptr_t)-1 || sva == (uintptr_t)-1)
        DIE("remote mmap failed (shva=%llx sva=%llx)",
            (unsigned long long)shva, (unsigned long long)sva);

    /* 影子页 = 受管页原样快照（KPM 只在其上写桩） */
    uintptr_t page = tva & ~0xFFFUL;
    static unsigned char buf[4096];
    rd_mem(page, buf, 4096);
    wr_mem(shva, buf, 4096);

    /* status 页 fault-in：KPM 经内核线性映射读它，未分配页（PTE 未 present）
     * 会让 KPM 的 PFN 推导失败（真机实证 "wstat slot unreadable"） */
    {
        unsigned long z = 0;
        wr_mem(sva, &z, 8);
    }

    set_regs(pid, &g_saved);
    ptrace(PTRACE_DETACH, pid, 0, 0);
    LOG("prepared: tva=%llx shva=%llx sva=%llx (detached)",
        (unsigned long long)tva, (unsigned long long)shva, (unsigned long long)sva);

    /* 输出可直接喂给 caoin-shadow 的 args */
    printf("pid=0x%x tva=0x%llx shva=0x%llx sva=0x%llx\n",
           (unsigned)pid, (unsigned long long)tva,
           (unsigned long long)shva, (unsigned long long)sva);
    return 0;
}
