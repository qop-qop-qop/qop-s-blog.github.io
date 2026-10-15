/*
 * caoin 平台抽象：libc（测试/CLI）与裸 syscall（agent, CAOIN_NOLIBC）双实现。
 * MI 8 内核 4K 页；如目标设备 16K 页需改 CAOIN_PAGE 为运行时探测。
 */
#ifndef CAOIN_PLATFORM_H
#define CAOIN_PLATFORM_H

#include <stdint.h>
#include <stddef.h>

#ifdef CAOIN_NOLIBC

/* ---- 裸 syscall（aarch64） ---- */

#define CAOIN_SYS_openat    56
#define CAOIN_SYS_close     57
#define CAOIN_SYS_read      63
#define CAOIN_SYS_write     64
#define CAOIN_SYS_mmap      222
#define CAOIN_SYS_munmap    215
#define CAOIN_SYS_mprotect  226
#define CAOIN_SYS_memfd_create 279
#define CAOIN_SYS_ftruncate 46

static __attribute__((unused)) long caoin_sys6(long n, long a, long b, long c, long d, long e, long f)
{
    register long x8 asm("x8") = n;
    register long x0 asm("x0") = a;
    register long x1 asm("x1") = b;
    register long x2 asm("x2") = c;
    register long x3 asm("x3") = d;
    register long x4 asm("x4") = e;
    register long x5 asm("x5") = f;
    asm volatile("svc #0" : "+r"(x0)
                 : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                 : "memory", "cc");
    return x0;
}

#define CAOIN_PROT_RW  0x3
#define CAOIN_PROT_RWX 0x7
#define CAOIN_PROT_RX  0x5
#define CAOIN_MAP_PRIVATE_ANON 0x22

#define CAOIN_PAGE 4096UL

static __attribute__((unused)) long caoin_memfd_create(void)
{
    /* memfd 名伪装成 ART 的 jit-cache：app maps 里本来就有同名映射，
     * 用 "caoin" 这类工具名会直接把身份写进 /proc/pid/maps（真机实测） */
    return caoin_sys6(CAOIN_SYS_memfd_create, (long)"jit-cache", 0, 0, 0, 0, 0);
}

static __attribute__((unused)) long caoin_ftruncate(long fd, long len)
{
    return caoin_sys6(CAOIN_SYS_ftruncate, fd, len, 0, 0, 0, 0);
}

static __attribute__((unused)) long caoin_close_fd(long fd)
{
    return caoin_sys6(CAOIN_SYS_close, fd, 0, 0, 0, 0, 0);
}

static __attribute__((unused)) void * caoin_mmap(void *addr, size_t len, int prot, int flags, int fd, long off)
{
    return (void *)caoin_sys6(CAOIN_SYS_mmap, (long)addr, (long)len, prot, flags, fd, off);
}

static __attribute__((unused)) int caoin_mprotect(void *addr, size_t len, int prot)
{
    return (int)caoin_sys6(CAOIN_SYS_mprotect, (long)addr, (long)len, prot, 0, 0, 0);
}

static __attribute__((unused)) int caoin_munmap(void *addr, size_t len)
{
    return (int)caoin_sys6(CAOIN_SYS_munmap, (long)addr, (long)len, 0, 0, 0, 0);
}

static __attribute__((unused)) void * caoin_memcpy(void *dst, const void *src, size_t n)
{
    unsigned char *d = dst;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dst;
}

static __attribute__((unused)) void caoin_flush_icache(void *beg, void *end)
{
    uintptr_t p = (uintptr_t)beg & ~(uintptr_t)31;
    for (; p < (uintptr_t)end; p += 32)
        asm volatile("ic ivau, %0" :: "r"(p) : "memory");
    asm volatile("dsb ish" ::: "memory");
}

#else /* !CAOIN_NOLIBC —— glibc 路径（主机/真机测试程序、CLI） */

#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

static __attribute__((unused)) long caoin_memfd_create(void)
{
    /* 同上：memfd 名伪装成 jit-cache，避免工具名进 maps */
    return syscall(SYS_memfd_create, "jit-cache", 0);
}

static __attribute__((unused)) long caoin_ftruncate(long fd, long len)
{
    return syscall(SYS_ftruncate, fd, len);
}

static __attribute__((unused)) long caoin_close_fd(long fd)
{
    return close((int)fd);
}

#define CAOIN_PROT_RW  (PROT_READ | PROT_WRITE)
#define CAOIN_PROT_RWX (PROT_READ | PROT_WRITE | PROT_EXEC)
#define CAOIN_PROT_RX  (PROT_READ | PROT_EXEC)
#define CAOIN_MAP_PRIVATE_ANON (MAP_PRIVATE | MAP_ANONYMOUS)
#define CAOIN_PAGE ((size_t)sysconf(_SC_PAGESIZE))

static __attribute__((unused)) void * caoin_mmap(void *addr, size_t len, int prot, int flags, int fd, long off)
{
    return mmap(addr, len, prot, flags, fd, off);
}

static __attribute__((unused)) int caoin_mprotect(void *addr, size_t len, int prot)
{
    return mprotect(addr, len, prot);
}

static __attribute__((unused)) int caoin_munmap(void *addr, size_t len)
{
    return munmap(addr, len);
}

#define caoin_memcpy memcpy
#define caoin_flush_icache(beg, end) __builtin___clear_cache((char *)(beg), (char *)(end))

#endif

#endif
