/*
 * trampoline 运行时（plain writer 后端）
 * 写入 = mprotect 暂时可写 + memcpy + icache flush。
 * shadow-PTE 后端（wxshadow .ko 路线）后续通过替换 write_code 接入。
 * 平台依赖见 platform.h（glibc / 裸 syscall 双实现）。
 */
#include "tramp.h"
#include "reloc.h"
#include "platform.h"

static int write_code(void *addr, const void *buf, size_t len)
{
    uintptr_t a = (uintptr_t)addr;
    uintptr_t start = a & ~(CAOIN_PAGE - 1);
    uintptr_t end = (a + len + CAOIN_PAGE - 1) & ~(CAOIN_PAGE - 1);

    if (caoin_mprotect((void *)start, end - start, CAOIN_PROT_RWX) != 0)
        return -1;
    caoin_memcpy(addr, buf, len);
    caoin_flush_icache(addr, (char *)addr + len);
    caoin_mprotect((void *)start, end - start, CAOIN_PROT_RX);
    return 0;
}

/*
 * trampoline 分配（W^X 合规）：
 *  memfd 双映射优先——RW 写入 + RX 执行（部分域拒绝匿名 RWX，ART JIT 同款方案），
 *  失败回退匿名 RWX（shell 等宽松域）。
 *
 *  距离：need_near（窗口含 PC 相对指令，ADRP ±4GB / B ±128MB 约束）时步进 hint
 *  就近分配；否则任何地址可用，机会主义试几次 hint 后直接接受内核自选地址。
 *  大 so 附近 hint 会被自身映射挡住（内核自选地址可达 10GB 外），非 PC 相对
 *  窗口无距离需求，不应因距离检查失败。
 */
static int alloc_tramp(void *target, int need_near,
                       void **rx_out, void **rw_out, long *fd_out)
{
    long page = (long)CAOIN_PAGE;

    long fd = caoin_memfd_create();
    if (fd >= 0) {
        caoin_ftruncate(fd, page);
        void *rw = caoin_mmap(0, (size_t)page, CAOIN_PROT_RW,
                              0x1 /*MAP_SHARED*/, (int)fd, 0);
        if (rw != (void *)-1) {
            for (uint64_t off = 0x200000; off < 0x60000000ULL; off += 0x200000) {
                for (int dir = 0; dir < 2; dir++) {
                    uintptr_t hint = (dir ? (uintptr_t)target + off : (uintptr_t)target - off)
                                     & ~(uintptr_t)(CAOIN_PAGE - 1);
                    void *rx = caoin_mmap((void *)hint, (size_t)page, CAOIN_PROT_RX,
                                          0x1 /*MAP_SHARED*/, (int)fd, 0);
                    if (rx != (void *)-1) {
                        uint64_t d = (uint64_t)((intptr_t)rx - (intptr_t)target);
                        if (d < 0x60000000ULL || !need_near) {
                            *rx_out = rx; *rw_out = rw; *fd_out = fd;
                            return 0;
                        }
                        caoin_munmap(rx, (size_t)page);
                    }
                }
                if (!need_near) break;   /* 远近皆可：一轮（4 个 hint）足矣 */
            }
            caoin_munmap(rw, (size_t)page);
        } else {
            caoin_close_fd(fd);
        }
    }

    /* 回退：匿名 RWX */
    for (uint64_t off = 0x200000; off < 0x60000000ULL; off += 0x200000) {
        for (int dir = 0; dir < 2; dir++) {
            uintptr_t hint = (dir ? (uintptr_t)target + off : (uintptr_t)target - off)
                             & ~(uintptr_t)(CAOIN_PAGE - 1);
            void *p = caoin_mmap((void *)hint, (size_t)page, CAOIN_PROT_RWX,
                                 CAOIN_MAP_PRIVATE_ANON, -1, 0);
            if (p != (void *)-1) {
                uint64_t d = (uint64_t)((intptr_t)p - (intptr_t)target);
                if (d < 0x60000000ULL || !need_near) {
                    *rx_out = p; *rw_out = p; *fd_out = -1;
                    return 0;
                }
                caoin_munmap(p, (size_t)page);
            }
        }
        if (!need_near) break;
    }
    return -1;
}

static void free_tramp(caoin_hook_t *h)
{
    if (h->tramp_fd >= 0) {
        caoin_close_fd(h->tramp_fd);
        h->tramp_fd = -1;
    }
    caoin_munmap(h->tramp, CAOIN_PAGE);
    if (h->tramp_rw != h->tramp)
        caoin_munmap(h->tramp_rw, CAOIN_PAGE);
    h->tramp = NULL;
    h->tramp_rw = NULL;
}

int caoin_hook_attach(void *target, void *handler, caoin_hook_t *h)
{
    int st[CAOIN_TRAMP_INSN];

    h->target = target;
    int need_near = caoin_window_pc_relative((const uint32_t *)target);
    if (alloc_tramp(target, need_near, &h->tramp, &h->tramp_rw, &h->tramp_fd) != 0)
        return -1;

    /* 写 RW 视图，PC 相对按 RX 视图地址计算 */
    size_t n = caoin_reloc_block((uint32_t *)h->tramp_rw, (uintptr_t)h->tramp,
                                 (const uint32_t *)target, (uintptr_t)target, st);
    if (n == 0) {
        free_tramp(h);
        return -2;     /* relocator 拒绝（窗口内分支/超范围），详见 st */
    }
    caoin_flush_icache(h->tramp, (char *)h->tramp + n * 4);

    caoin_memcpy(h->orig, target, sizeof(h->orig));

    uint32_t stub[CAOIN_TRAMP_INSN];
    caoin_make_entry_stub(stub, (uintptr_t)handler);
    if (write_code(target, stub, sizeof(stub)) != 0) {
        free_tramp(h);
        return -3;
    }
    h->attached = 1;
    return 0;
}

int caoin_hook_detach(caoin_hook_t *h)
{
    if (!h->attached)
        return -1;
    int rc = write_code(h->target, h->orig, sizeof(h->orig));
    free_tramp(h);
    h->attached = 0;
    return rc;
}
