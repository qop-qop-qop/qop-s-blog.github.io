#include "heap.h"
#include "libc.h"
#include "memory.h"
#include "registers.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* glibc malloc_chunk (x86_64):
     +0   prev_size    (8 bytes, 仅当上一个 chunk free 时有效)
     +8   size         (8 bytes,低 3 位 = A|M|P 标志)
     +16  fd / user data
   size & 0x1 (P) = PREV_INUSE — 上一个 chunk 正在使用
   size & 0x2 (M) = IS_MMAPPED — 通过 mmap 分配(通常非常大的块)
   size & 0x4 (A) = NON_MAIN_ARENA
   实际 chunk 大小 = size & ~0x7 */
#define PREV_INUSE      0x1
#define IS_MMAPPED      0x2
#define NON_MAIN_ARENA  0x4
#define SIZE_MASK       (~0x7UL)
#define MIN_CHUNK_SIZE  32   /* 0x20 on x86_64 */

static int find_heap_range(pid_t pid, uint64_t *start, uint64_t *end) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[1024];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "[heap]")) {
            if (sscanf(line, "%lx-%lx", start, end) == 2) found = 1;
            break;
        }
    }
    fclose(f);
    return found ? 0 : -1;
}

int heap_dump(debugger_t *d, int max_chunks) {
    if (d->pid <= 0) {
        fprintf(stderr, "当前没有被调试进程\n");
        return -1;
    }

    uint64_t hstart = 0, hend = 0;
    if (find_heap_range(d->pid, &hstart, &hend) != 0) {
        fprintf(stderr, "在 /proc/%d/maps 里没找到 [heap] 段\n", d->pid);
        fprintf(stderr, "  (程序可能还没调用过 malloc,或者分配全走 mmap)\n");
        return -1;
    }
    printf("[heap]  0x%lx - 0x%lx  (共 %lu 字节)\n",
           hstart, hend, hend - hstart);
    printf("  %-4s %-18s %-10s %-6s %-6s\n",
           "编号", "地址", "大小", "标志", "备注");

    if (max_chunks <= 0) max_chunks = 256;

    /* 第一遍:收集所有 chunk 的地址和 raw size。 */
    uint64_t *addrs = calloc(max_chunks, sizeof(uint64_t));
    uint64_t *sizes = calloc(max_chunks, sizeof(uint64_t));
    if (!addrs || !sizes) { free(addrs); free(sizes); return -1; }

    int n = 0;
    uint64_t cur = hstart;
    while (cur < hend && n < max_chunks) {
        uint64_t hdr[2];
        if (mem_read(d->pid, cur, hdr, sizeof(hdr)) != 0) break;
        uint64_t raw_size = hdr[1];
        uint64_t chunk_size = raw_size & SIZE_MASK;
        if (chunk_size < MIN_CHUNK_SIZE) {
            /* 到 top chunk 或者结构损坏,停止 */
            addrs[n] = cur; sizes[n] = raw_size; n++;
            break;
        }
        addrs[n] = cur; sizes[n] = raw_size; n++;
        cur += chunk_size;
    }

    /* 第二遍:根据下一个 chunk 的 PREV_INUSE 判断当前 chunk 是否 in-use。
       最后一个 chunk 是 top chunk,总是"in-use"直到被回收进 unsorted。 */
    for (int i = 0; i < n; i++) {
        uint64_t raw = sizes[i];
        uint64_t sz  = raw & SIZE_MASK;
        int P = raw & PREV_INUSE;
        int M = (raw & IS_MMAPPED) ? 1 : 0;
        int A = (raw & NON_MAIN_ARENA) ? 1 : 0;

        int in_use;
        const char *note;
        if (i == n - 1) {
            in_use = 1;
            note = "top";
        } else {
            /* 下一个 chunk 的 PREV_INUSE 表示"我"是否在用 */
            in_use = (sizes[i + 1] & PREV_INUSE) ? 1 : 0;
            note = in_use ? "in-use" : "free";
        }

        char flags[8];
        snprintf(flags, sizeof(flags), "%c%c%c",
                 A ? 'A' : '-',
                 M ? 'M' : '-',
                 P ? 'P' : '-');

        const char *color = in_use ? ANSI_GREEN : ANSI_YELLOW;
        printf("  %-4d 0x%016lx 0x%-8lx %-6s %s%s" ANSI_RESET "\n",
               i, addrs[i], sz, flags, color, note);
    }

    if (n == max_chunks)
        printf("  (最多显示 %d 个,加参数 `heap N` 提高上限)\n", max_chunks);
    printf("标志位:A=NON_MAIN_ARENA  M=IS_MMAPPED  P=PREV_INUSE\n");

    free(addrs); free(sizes);
    return 0;
}

/* ================= tcache ================= */

/* glibc 版本差异:
   - 2.26 - 2.34:  TCACHE_MAX_BINS=64, counts=当前个数, entries[] 紧跟在 128B counts 后
   - 2.35+:        TCACHE_MAX_BINS=76, counts=剩余槽位(max=16),entries[] 在 152B 后
   自动探测:扫描前面几个 uint16,如果最大值是 16 说明是新 layout。 */
#define TCACHE_MAX_BINS 76
#define TCACHE_MAX_SLOTS 16

/* safe-linking (glibc >= 2.32):
     stored_next = real_next ^ (chunk_addr >> 12)
   逆推真实指针。 */
static uint64_t decode_safe(uint64_t stored, uint64_t chunk_addr, int safe_linking) {
    if (!safe_linking) return stored;
    return stored ^ (chunk_addr >> 12);
}

/* 通过扫 fs_base 附近内存找 tcache_perthread_struct 地址(TLS 变量存的
   是它的 user-data 指针,即 chunk+0x10)。找不到就退回到"[heap] 起始
   处第一个 chunk"这个旧启发式。 */
static uint64_t locate_tcache_user(debugger_t *d, uint64_t hstart, uint64_t hend) {
    uint64_t fs_base = 0;
    if (regs_read_by_name(d->pid, "fs_base", &fs_base) == 0 && fs_base) {
        /* TLS 变量在 x86_64 上位于 fs_base 之前(负偏移)。libc 的
           `tcache` 变量偏移小,-256..256 覆盖足够。 */
        for (int64_t off = -512; off <= 512; off += 8) {
            uint64_t v = 0;
            if (mem_read(d->pid, fs_base + off, &v, 8) != 0) continue;
            if (v >= hstart + 0x10 && v < hend) return v;
        }
    }
    /* 兜底 */
    return hstart + 0x10;
}

int heap_tcache(debugger_t *d) {
    if (d->pid <= 0) { fprintf(stderr, "当前没有被调试进程\n"); return -1; }
    const libc_ctx_t *lc = libc_ctx(d);
    int safe_linking = lc ? lc->safe_linking : 1;

    uint64_t hstart = 0, hend = 0;
    if (find_heap_range(d->pid, &hstart, &hend) != 0) {
        fprintf(stderr, "没找到 [heap] 段(可能还没 malloc 过)\n");
        return -1;
    }

    uint64_t user = locate_tcache_user(d, hstart, hend);

    /* 先读一段 counts 区域用来探测 layout。 */
    uint16_t counts[TCACHE_MAX_BINS];
    size_t counts_bytes = sizeof(counts);
    if (mem_read(d->pid, user, counts, counts_bytes) != 0) {
        fprintf(stderr, "读取 tcache counts 失败\n"); return -1;
    }
    /* 新 layout 探测:如果 counts 里存在 == 0x10 的值,说明是"剩余槽位"语义。 */
    int new_layout = 0;
    for (int i = 0; i < TCACHE_MAX_BINS; i++) {
        if (counts[i] == TCACHE_MAX_SLOTS) { new_layout = 1; break; }
    }
    size_t entries_offset = counts_bytes;

    uint64_t entries[TCACHE_MAX_BINS];
    if (mem_read(d->pid, user + entries_offset, entries, sizeof(entries)) != 0) {
        fprintf(stderr, "读取 tcache entries 失败\n"); return -1;
    }

    printf("tcache_perthread_struct @ 0x%lx  "
           "(safe-linking %s, 计数语义: %s)\n",
           user, safe_linking ? "开" : "关",
           new_layout ? "剩余槽位 (glibc 2.35+)" : "当前个数");

    int shown = 0;
    for (int i = 0; i < TCACHE_MAX_BINS; i++) {
        int actual_count = new_layout ? (TCACHE_MAX_SLOTS - counts[i]) : counts[i];
        if (actual_count == 0 && entries[i] == 0) continue;
        uint64_t chunk_size = 0x20 + (uint64_t)i * 0x10;
        printf("  bin[%2d]  size=0x%-4lx  count=%d  chain:",
               i, chunk_size, actual_count);
        uint64_t p = entries[i];
        int hops = 0;
        while (p && hops < 32) {
            uint64_t chunk_hdr = p - 0x10;
            printf(" 0x%lx", chunk_hdr);
            uint64_t next_stored = 0;
            if (mem_read(d->pid, p, &next_stored, 8) != 0) break;
            uint64_t real = decode_safe(next_stored, p, safe_linking);
            if (real == p) break;
            p = real;
            hops++;
        }
        if (hops == 32) printf(" ...");
        printf("\n");
        shown++;
    }
    if (shown == 0) printf("  (所有桶都为空)\n");
    return 0;
}

/* ================= main_arena bins ================= */

/* glibc x86_64 malloc_state 关键字段偏移(相对 main_arena 起始):
   glibc 2.35+ 精简了 malloc_state,去掉了独立的 fastbinsY/have_fastchunks
   (整合进 flags),整体从 2200 字节收缩到 2112:
     0x00  mutex(4) + flags(4) 8 字节
     0x08  top                 8
     0x10  last_remainder      8
     0x18  bins[254]           2032 → 到 0x808
     0x808 binmap[4]           16
     0x818 next / next_free / attached / system_mem / max_system_mem 40
     0x840 = 2112 ✓
   老版本 glibc(2.34-)偏移不同,当前实现只针对 2.35+。 */
#define MA_TOP              0x08
#define MA_LAST_REMAINDER   0x10
#define MA_BINS             0x18
#define MA_SYSTEM_MEM       0x830
#define NBINS               128
#define NFASTBINS           10       /* 仅用于 fastbin 兜底(通常不适用于 2.35+) */

/* bins[] 里第 i 个 bin(逻辑意义)在数组中的索引是 (i-1)*2 = fd,(i-1)*2+1 = bk。
   fd/bk 都指向 chunk 的 user data(即 chunk+0x10)。 */
static uint64_t bin_at(uint64_t main_arena, int i) {
    /* 返回逻辑 bin i 的"假头"地址(可写但结构上像 chunk 的 fd 位置) */
    return main_arena + MA_BINS + ((uint64_t)(i - 1) * 2) * 8 - 0x10;
}

static int walk_bin(pid_t pid, uint64_t head_chunk_faux, int label_no,
                    const char *label) {
    /* head_chunk_faux 是"假 chunk 头",fd 在 +0x10 处。
       第一个真 chunk 由 head_chunk_faux->fd 指向。链表以 head 自身为终止条件。 */
    uint64_t fd = 0;
    if (mem_read(pid, head_chunk_faux + 0x10, &fd, 8) != 0) return -1;
    if (fd == 0 || fd == head_chunk_faux) return 0;   /* 空 bin */

    printf("  %s[%d]:", label, label_no);
    int hops = 0;
    uint64_t cur = fd;
    while (cur && cur != head_chunk_faux && hops < 64) {
        printf(" 0x%lx", cur);
        uint64_t next = 0;
        if (mem_read(pid, cur + 0x10, &next, 8) != 0) break;   /* 读 fd */
        cur = next;
        hops++;
    }
    if (hops == 64) printf(" ...");
    printf("\n");
    return hops;
}

int heap_bins(debugger_t *d) {
    if (d->pid <= 0) { fprintf(stderr, "当前没有被调试进程\n"); return -1; }
    const libc_ctx_t *lc = libc_ctx(d);
    if (!lc) { fprintf(stderr, "找不到 libc 上下文\n"); return -1; }
    if (!lc->main_arena_addr) {
        fprintf(stderr, "找不到 main_arena 符号\n"
                        "  安装 libc6-dbg 可自动加载调试符号:\n"
                        "  sudo apt install libc6-dbg\n"
                        "  然后重新 run/attach\n");
        return -1;
    }

    uint64_t ma = lc->main_arena_addr;
    int safe_linking = lc->safe_linking;

    /* 读 system_mem 判定 arena 是否活跃(值 == 0 说明 arena 从未初始化)。 */
    uint64_t system_mem = 0;
    mem_read(d->pid, ma + MA_SYSTEM_MEM, &system_mem, 8);
    printf("main_arena @ 0x%lx  glibc %d.%d  system_mem=0x%lx  "
           "(safe-linking %s)\n",
           ma, lc->version_major, lc->version_minor, system_mem,
           safe_linking ? "开" : "关");

    /* fastbinsY 在 glibc 2.35+ 已从 malloc_state 移除,这里不再解析。
       如果有内容,通常会通过 tcache 或 unsorted 呈现。 */

    /* --- unsorted (bin 1) --- */
    printf(ANSI_CYAN "unsorted bin:" ANSI_RESET "\n");
    if (walk_bin(d->pid, bin_at(ma, 1), 1, "unsorted") == 0)
        printf("  (空)\n");

    /* --- small bins (bin 2..63) --- */
    printf(ANSI_CYAN "small bins:" ANSI_RESET "\n");
    int sb_shown = 0;
    for (int i = 2; i <= 63; i++) {
        if (walk_bin(d->pid, bin_at(ma, i), i,
                     "small") > 0) sb_shown++;
    }
    if (!sb_shown) printf("  (全部为空)\n");

    /* --- large bins (bin 64..126) --- */
    printf(ANSI_CYAN "large bins:" ANSI_RESET "\n");
    int lb_shown = 0;
    for (int i = 64; i <= 126; i++) {
        if (walk_bin(d->pid, bin_at(ma, i), i,
                     "large") > 0) lb_shown++;
    }
    if (!lb_shown) printf("  (全部为空)\n");

    /* --- top chunk --- */
    uint64_t top = 0;
    if (mem_read(d->pid, ma + MA_TOP, &top, 8) == 0 && top) {
        uint64_t top_hdr[2];
        if (mem_read(d->pid, top, top_hdr, sizeof(top_hdr)) == 0) {
            printf(ANSI_CYAN "top chunk:" ANSI_RESET
                   " 0x%lx  size=0x%lx\n", top, top_hdr[1] & ~0x7UL);
        }
    }
    return 0;
}
