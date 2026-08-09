#include "libc.h"
#include "memory.h"
#include "symbols.h"

#include <errno.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* 一个私有的符号追加接口(和 symbols.c 里那个 push_symbol 结构一致)。
   放在这里是为了不改 symbols.c 的对外 API。 */
static void push(debugger_t *d, const char *name, uint64_t addr,
                 uint64_t size, unsigned char info) {
    symbol_t *s = calloc(1, sizeof(*s));
    if (!s) return;
    s->name = strdup(name);
    s->addr = addr;
    s->size = size;
    s->st_info = info;
    s->next = d->symbols;
    d->symbols = s;
}

/* 在 /proc/pid/maps 里找 libc.so.6 的 (load_base, 绝对路径)。
   load_base = 首个 r-xp 段的 start - offset —— 这是 st_value 的运行时基准。 */
static int find_libc(pid_t pid, uint64_t *out_base, char *out_path, size_t path_sz) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int)pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) return -1;
    int found = 0;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        uint64_t start, end, offset;
        char perms[8], dev[16], pth[1024] = {0};
        int n = sscanf(line, "%lx-%lx %7s %lx %15s %*d %1023[^\n]",
                       &start, &end, perms, &offset, dev, pth);
        if (n < 5) continue;
        if (perms[2] != 'x') continue;
        char *p = pth; while (*p == ' ') p++;
        if (strstr(p, "/libc.so.6") || strstr(p, "/libc-2.")) {
            *out_base = start - offset;
            strncpy(out_path, p, path_sz - 1);
            out_path[path_sz - 1] = '\0';
            found = 1;
            break;
        }
    }
    fclose(f);
    return found ? 0 : -1;
}

/* 从任意一个 ELF 文件的 .symtab 或 .dynsym 里,按加载基址补偿后 push 到 d。
   which: SHT_SYMTAB 或 SHT_DYNSYM。返回加载条数。 */
static int load_sym_section(debugger_t *d, Elf *e, uint64_t base, int which,
                            const char *tag) {
    Elf_Scn *scn = NULL;
    int added = 0;
    while ((scn = elf_nextscn(e, scn))) {
        GElf_Shdr sh;
        if (!gelf_getshdr(scn, &sh)) continue;
        if ((int)sh.sh_type != which) continue;
        Elf_Data *data = elf_getdata(scn, NULL);
        Elf_Scn *strscn = elf_getscn(e, sh.sh_link);
        if (!data || !strscn) continue;
        Elf_Data *strdata = elf_getdata(strscn, NULL);
        if (!strdata) continue;
        size_t nsyms = sh.sh_size / sh.sh_entsize;
        for (size_t i = 0; i < nsyms; i++) {
            GElf_Sym sym;
            if (!gelf_getsym(data, i, &sym)) continue;
            if (sym.st_name >= strdata->d_size) continue;
            const char *name = (char *)strdata->d_buf + sym.st_name;
            if (!name || !*name) continue;
            unsigned char type = GELF_ST_TYPE(sym.st_info);
            if (type != STT_FUNC && type != STT_OBJECT && type != STT_NOTYPE) continue;
            if (sym.st_shndx == SHN_UNDEF) continue;
            push(d, name, base + sym.st_value, sym.st_size, sym.st_info);
            added++;
        }
    }
    (void)tag;
    return added;
}

/* 从 .note.gnu.build-id 段读取 build-id 十六进制字符串,填到 out(至少 41 字节)。 */
static int read_build_id(Elf *e, char *out, size_t out_sz) {
    Elf_Scn *scn = NULL;
    size_t shstrndx;
    if (elf_getshdrstrndx(e, &shstrndx) != 0) return -1;
    while ((scn = elf_nextscn(e, scn))) {
        GElf_Shdr sh;
        if (!gelf_getshdr(scn, &sh)) continue;
        const char *nm = elf_strptr(e, shstrndx, sh.sh_name);
        if (!nm || strcmp(nm, ".note.gnu.build-id") != 0) continue;
        Elf_Data *d = elf_getdata(scn, NULL);
        if (!d || d->d_size < 16) continue;
        /* note header: namesz(4) + descsz(4) + type(4) + name("GNU\0" 4B) + desc(descsz) */
        uint32_t namesz  = *(uint32_t *)((char *)d->d_buf + 0);
        uint32_t descsz  = *(uint32_t *)((char *)d->d_buf + 4);
        (void)namesz;
        unsigned char *desc = (unsigned char *)d->d_buf + 16;
        if (descsz > 20) descsz = 20;
        size_t need = (size_t)descsz * 2 + 1;
        if (out_sz < need) return -1;
        for (uint32_t i = 0; i < descsz; i++)
            snprintf(out + i * 2, 3, "%02x", desc[i]);
        return (int)descsz;
    }
    return -1;
}

/* 从 libc 二进制的 .rodata 里搜索版本字符串,取出 "2.XX"。 */
static void guess_glibc_version(pid_t pid, uint64_t libc_base, int *maj, int *min) {
    *maj = 2; *min = 34;   /* 保守默认;开启 safe-linking */
    /* 直接读 libc 前 2MB 里搜 "GNU C Library"。粗暴但够用。 */
    size_t scan = 2 * 1024 * 1024;
    uint8_t *buf = malloc(scan);
    if (!buf) return;
    if (mem_read(pid, libc_base, buf, scan) != 0) { free(buf); return; }
    const char *needle = "GNU C Library";
    for (size_t i = 0; i + 64 < scan; i++) {
        if (memcmp(buf + i, needle, strlen(needle)) != 0) continue;
        /* 之后某处出现 "version 2.XX" 或 "release version 2.XX" */
        for (size_t j = i; j + 8 < i + 200 && j + 8 < scan; j++) {
            if (buf[j] == '2' && buf[j+1] == '.') {
                int a = 0, b = 0;
                if (sscanf((char *)buf + j, "%d.%d", &a, &b) == 2 && a == 2 && b >= 10) {
                    *maj = a; *min = b;
                    free(buf);
                    return;
                }
            }
        }
    }
    free(buf);
}

int libc_load(debugger_t *d, uint64_t *out_base) {
    uint64_t base = 0;
    char path[512] = {0};
    if (find_libc(d->pid, &base, path, sizeof(path)) != 0) {
        return -1;
    }
    if (out_base) *out_base = base;

    if (elf_version(EV_CURRENT) == EV_NONE) return -1;

    /* 主 libc 文件:通常已被 strip,只有 .dynsym。 */
    int fd = open(path, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "无法打开 %s: %s\n", path, strerror(errno)); return -1; }
    Elf *e = elf_begin(fd, ELF_C_READ, NULL);
    if (!e) { close(fd); return -1; }

    int total = 0;
    total += load_sym_section(d, e, base, SHT_DYNSYM, "libc.dynsym");
    total += load_sym_section(d, e, base, SHT_SYMTAB, "libc.symtab");

    /* 读 build-id 尝试加载分离的调试文件(libc6-dbg 装的话在这里)。
       路径:/usr/lib/debug/.build-id/XX/YYYY....debug */
    char bid[64] = {0};
    if (read_build_id(e, bid, sizeof(bid)) > 0 && strlen(bid) >= 4) {
        char dbg_path[512];
        snprintf(dbg_path, sizeof(dbg_path),
                 "/usr/lib/debug/.build-id/%c%c/%s.debug", bid[0], bid[1], bid + 2);
        int dfd = open(dbg_path, O_RDONLY);
        if (dfd >= 0) {
            Elf *de = elf_begin(dfd, ELF_C_READ, NULL);
            if (de) {
                int n = load_sym_section(d, de, base, SHT_SYMTAB, "libc.dbg.symtab");
                if (n > 0)
                    printf("[libc] 加载 %d 个调试符号 (%s)\n", n, dbg_path);
                total += n;
                elf_end(de);
            }
            close(dfd);
        }
    }

    elf_end(e);
    close(fd);

    printf("[libc] %s 基址 0x%lx,加载 %d 个符号\n", path, base, total);
    return total;
}

const libc_ctx_t *libc_ctx(debugger_t *d) {
    if (d->libc) return (const libc_ctx_t *)d->libc;
    if (d->pid <= 0 || d->state != ST_STOPPED) return NULL;

    libc_ctx_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    if (find_libc(d->pid, &c->base, c->path, sizeof(c->path)) != 0) {
        free(c);
        return NULL;
    }
    guess_glibc_version(d->pid, c->base, &c->version_major, &c->version_minor);
    c->safe_linking = (c->version_major > 2) ||
                      (c->version_major == 2 && c->version_minor >= 32);

    /* 在 d->symbols 里找 main_arena。 */
    const symbol_t *ma = symbols_by_name(d, "main_arena");
    c->main_arena_addr = ma ? ma->addr : 0;

    d->libc = (struct libc_ctx *)c;
    return c;
}
