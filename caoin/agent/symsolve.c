#include "symsolve.h"
#include "../hook/platform.h"

#include <elf.h>

/* 诊断出口：最后一次 resolve 的中间量（agent ERR 日志用） */
unsigned long caoin_dbg_base, caoin_dbg_nsyms, caoin_dbg_symtab, caoin_dbg_strtab;

static int st_eq(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return *a == *b;
}

static int st_contains(const char *h, const char *n)
{
    for (; *h; h++) {
        const char *a = h, *b = n;
        while (*b && *a == *b) { a++; b++; }
        if (!*b) return 1;
    }
    return 0;
}

static int rd_line_hex(const char *s, int *pos, uintptr_t *out)
{
    uintptr_t v = 0;
    int any = 0;
    for (; s[*pos]; (*pos)++) {
        char c = s[*pos];
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else break;
        v = (v << 4) | (uintptr_t)d;
        any = 1;
    }
    *out = v;
    return any;
}

/* maps 行: "start-end perms off dev inode path"
   pat == NULL 时返回第一个文件映射（主程序基址，PIE 主程序总在最低地址） */
static uintptr_t find_module_base(const char *pat)
{
    /* app 进程 maps 可达数百 KB（2730 行实测），static 缓冲避免栈溢出；未触碰页不占 RSS */
    static char maps[512 * 1024];
    long fd = caoin_sys6(CAOIN_SYS_openat, -100, (long)"/proc/self/maps", 0 /*O_RDONLY*/, 0, 0, 0);
    if (fd < 0)
        return 0;
    long total = 0;
    for (;;) {
        long r = caoin_sys6(CAOIN_SYS_read, fd, (long)(maps + total),
                            (long)sizeof(maps) - 1 - total, 0, 0, 0);
        if (r <= 0 || total >= (long)sizeof(maps) - 1) break;
        total += r;
    }
    caoin_sys6(CAOIN_SYS_close, fd, 0, 0, 0, 0, 0);
    if (total <= 0)
        return 0;
    maps[total] = 0;

    char *line = maps;
    while (line && *line) {
        char *nl = line;
        while (*nl && *nl != '\n') nl++;
        char *eol = nl;
        int has_nl = *nl == '\n';
        if (has_nl) *nl = 0;

        int pos = 0;
        uintptr_t start = 0, end = 0, off = 0;
        if (rd_line_hex(line, &pos, &start) && line[pos] == '-') {
            pos++;
            rd_line_hex(line, &pos, &end);
            pos++;  /* space */
            pos += 4;  /* perms "r-xp" */
            pos++;
            rd_line_hex(line, &pos, &off);
            /* 行尾找路径 */
            char *p = eol;
            while (p > line && *(p - 1) != ' ') p--;
            if (off == 0 && *p == '/'
                && (pat == 0 || st_contains(p, pat))) {
                return start;
            }
        }
        line = has_nl ? nl + 1 : 0;
    }
    return 0;
}

static uint32_t gnu_nsyms(uintptr_t gh)
{
    uint32_t *h = (uint32_t *)gh;
    uint32_t nbuckets = h[0], symoffset = h[1], bloom_n = h[2];
    uint32_t *buckets = (uint32_t *)(gh + 16 + (uintptr_t)bloom_n * 8);
    uint32_t max = 0;
    for (uint32_t i = 0; i < nbuckets; i++)
        if (buckets[i] > max) max = buckets[i];
    if (max < symoffset)
        return symoffset;
    uint32_t *chain = buckets + nbuckets;
    uint32_t c = chain[max - symoffset];
    while (!(c & 1)) {
        max++;
        c = chain[max - symoffset];
    }
    return max + 1;
}

uintptr_t caoin_module_base(const char *pat)
{
    if (pat && pat[0] == '@')
        pat = 0;
    return find_module_base(pat);
}

uintptr_t caoin_resolve(const char *module_pat, const char *symbol)
{
    uintptr_t base = find_module_base(module_pat);
    caoin_dbg_base = base;
    if (!base)
        return 0;

    Elf64_Ehdr *eh = (Elf64_Ehdr *)base;
    if (eh->e_ident[0] != 0x7f || eh->e_ident[1] != 'E')
        return 0;

    Elf64_Phdr *ph = (Elf64_Phdr *)(base + eh->e_phoff);
    uintptr_t symtab = 0, strtab = 0, gnuh = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_DYNAMIC)
            continue;
        Elf64_Dyn *dyn = (Elf64_Dyn *)(base + ph[i].p_vaddr);
        for (; dyn->d_tag != DT_NULL; dyn++) {
            if (dyn->d_tag == DT_SYMTAB)  symtab = base + dyn->d_un.d_ptr;
            if (dyn->d_tag == DT_STRTAB)  strtab = base + dyn->d_un.d_ptr;
            if (dyn->d_tag == DT_GNU_HASH) gnuh = base + dyn->d_un.d_ptr;
        }
    }
    if (!symtab || !strtab)
        return 0;
    caoin_dbg_symtab = symtab;
    caoin_dbg_strtab = strtab;

    uint32_t nsyms = gnuh ? gnu_nsyms(gnuh) : (uint32_t)((strtab - symtab) / sizeof(Elf64_Sym));
    caoin_dbg_nsyms = nsyms;
    Elf64_Sym *syms = (Elf64_Sym *)symtab;
    for (uint32_t i = 0; i < nsyms; i++) {
        if (syms[i].st_name == 0 || syms[i].st_shndx == 0 /*SHN_UNDEF*/)
            continue;
        if (st_eq((const char *)(strtab + syms[i].st_name), symbol))
            return base + syms[i].st_value;
    }
    return 0;
}
