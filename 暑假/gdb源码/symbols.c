#include "symbols.h"

#include <errno.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void push_symbol(debugger_t *d, const char *name, uint64_t addr,
                        uint64_t size, unsigned char info) {
    symbol_t *s = calloc(1, sizeof(*s));
    if (!s) return;
    s->name    = strdup(name);
    s->addr    = addr;
    s->size    = size;
    s->st_info = info;
    s->next    = d->symbols;
    d->symbols = s;
}

static int load_from_section(debugger_t *d, Elf *e, Elf_Scn *scn, uint64_t base) {
    GElf_Shdr sh;
    if (!gelf_getshdr(scn, &sh)) return -1;

    Elf_Data *data = elf_getdata(scn, NULL);
    if (!data) return -1;
    Elf_Scn *strscn = elf_getscn(e, sh.sh_link);
    if (!strscn) return -1;
    Elf_Data *strdata = elf_getdata(strscn, NULL);
    if (!strdata) return -1;

    size_t nsyms = sh.sh_size / sh.sh_entsize;
    int added = 0;
    for (size_t i = 0; i < nsyms; i++) {
        GElf_Sym sym;
        if (!gelf_getsym(data, i, &sym)) continue;
        if (sym.st_name >= strdata->d_size) continue;
        const char *name = (const char *)strdata->d_buf + sym.st_name;
        if (!name || !*name) continue;
        unsigned char type = GELF_ST_TYPE(sym.st_info);
        if (type != STT_FUNC && type != STT_OBJECT && type != STT_NOTYPE) continue;
        if (sym.st_shndx == SHN_UNDEF) continue;
        push_symbol(d, name, base + sym.st_value, sym.st_size, sym.st_info);
        added++;
    }
    return added;
}

int symbols_load(debugger_t *d, const char *path) {
    /* Reload semantics: wipe any previous entries so we can be called twice
       (once at startup with base=0, once after we know the PIE base). */
    symbols_free(d);

    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "libelf init failed\n");
        return -1;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }
    Elf *e = elf_begin(fd, ELF_C_READ, NULL);
    if (!e) {
        fprintf(stderr, "elf_begin: %s\n", elf_errmsg(-1));
        close(fd);
        return -1;
    }

    GElf_Ehdr eh;
    if (!gelf_getehdr(e, &eh)) {
        fprintf(stderr, "gelf_getehdr: %s\n", elf_errmsg(-1));
        elf_end(e); close(fd);
        return -1;
    }
    d->is_pie = (eh.e_type == ET_DYN);
    uint64_t base = d->is_pie ? d->base_addr : 0;

    Elf_Scn *scn = NULL;
    int total = 0;
    /* Prefer .symtab (may be stripped), then .dynsym. */
    while ((scn = elf_nextscn(e, scn))) {
        GElf_Shdr sh;
        if (!gelf_getshdr(scn, &sh)) continue;
        if (sh.sh_type == SHT_SYMTAB) {
            total += load_from_section(d, e, scn, base);
        }
    }
    if (total == 0) {
        scn = NULL;
        while ((scn = elf_nextscn(e, scn))) {
            GElf_Shdr sh;
            if (!gelf_getshdr(scn, &sh)) continue;
            if (sh.sh_type == SHT_DYNSYM) {
                total += load_from_section(d, e, scn, base);
            }
        }
    }

    elf_end(e);
    close(fd);
    printf("[符号] 从 %s 加载了 %d 个 (基址 0x%lx, %s)\n",
           path, total, base, d->is_pie ? "PIE" : "非 PIE");
    return 0;
}

void symbols_free(debugger_t *d) {
    symbol_t *s = d->symbols;
    while (s) {
        symbol_t *n = s->next;
        free(s->name);
        free(s);
        s = n;
    }
    d->symbols = NULL;
}

const symbol_t *symbols_by_name(debugger_t *d, const char *name) {
    for (symbol_t *s = d->symbols; s; s = s->next)
        if (strcmp(s->name, name) == 0) return s;
    return NULL;
}

const symbol_t *symbols_by_addr(debugger_t *d, uint64_t addr) {
    const symbol_t *best = NULL;
    uint64_t best_off = (uint64_t)-1;
    for (symbol_t *s = d->symbols; s; s = s->next) {
        if (s->addr > addr) continue;
        uint64_t off = addr - s->addr;
        /* Prefer a symbol whose range covers addr; otherwise nearest below. */
        int in_range = s->size ? (off < s->size) : (off < 0x1000);
        if (in_range && off < best_off) { best = s; best_off = off; }
    }
    return best;
}

void symbols_print(debugger_t *d, const char *filter) {
    int shown = 0;
    for (symbol_t *s = d->symbols; s; s = s->next) {
        if (filter && !strstr(s->name, filter)) continue;
        const char *kind = "?";
        switch (GELF_ST_TYPE(s->st_info)) {
            case STT_FUNC:   kind = "FUNC";   break;
            case STT_OBJECT: kind = "OBJECT"; break;
            case STT_NOTYPE: kind = "NOTYPE"; break;
        }
        printf("  0x%016lx  %-6s  %6lu  %s\n", s->addr, kind, s->size, s->name);
        shown++;
    }
    if (filter)
        printf("(共 %d 个符号,过滤词: %s)\n", shown, filter);
    else
        printf("(共 %d 个符号)\n", shown);
}

int symbols_resolve(debugger_t *d, const char *expr, uint64_t *out) {
    if (!expr || !*expr) return -1;

    if (expr[0] == '0' && (expr[1] == 'x' || expr[1] == 'X')) {
        char *end;
        errno = 0;
        uint64_t v = strtoull(expr, &end, 16);
        if (errno || *end) return -1;
        *out = v;
        return 0;
    }
    if (expr[0] >= '0' && expr[0] <= '9') {
        char *end;
        errno = 0;
        uint64_t v = strtoull(expr, &end, 10);
        if (errno || *end) return -1;
        *out = v;
        return 0;
    }

    /* symbol or symbol+off */
    char buf[256];
    strncpy(buf, expr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    uint64_t off = 0;
    char *plus = strchr(buf, '+');
    if (plus) {
        *plus = '\0';
        char *end;
        errno = 0;
        off = strtoull(plus + 1, &end,
                       (plus[1] == '0' && (plus[2] == 'x' || plus[2] == 'X')) ? 16 : 0);
        if (errno) return -1;
    }
    const symbol_t *s = symbols_by_name(d, buf);
    if (!s) {
        fprintf(stderr, "未知符号: %s\n", buf);
        return -1;
    }
    *out = s->addr + off;
    return 0;
}
