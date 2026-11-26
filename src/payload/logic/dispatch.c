/* SPDX-License-Identifier: MIT */
/* Guest syscalls after the integrity checks: PRoot path semantics (the
 * bridge), fake credentials, hooking of newly executable memory, the calls
 * this platform cannot serve, and native passthrough for everything else. */
#include "syscall_nums.h"
#include <errno.h>
#include <stddef.h>
#include "config.h"
#include "container_state.h"
#include "dispatch.h"
#include "elf_abi.h"
#include "fake_ids.h"
#include "async_io.h"
#include "bpf_emu.h"
#include "hook_runtime.h"
#include "host_syscall.h"
#include "platform.h"
#include "vfs_bridge.h"

#define PROT_READ     0x1
#define PROT_WRITE    0x2
#define PROT_EXEC     0x4
#define MAP_FIXED     0x10
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED_NOREPLACE 0x100000
#define MAP_TYPE      0x0f
#define MAP_PRIVATE   0x02

extern long raw_syscall(long number, long a1, long a2, long a3, long a4, long a5, long a6);
extern void _start(void);
extern void fast_passthrough_svc(void);
extern void fast_passthrough_after(void);

/* Tracks whether the guest installed a seccomp filter and whether its BPF
 * returns SECCOMP_RET_TRAP with zero (bit 0) or nonzero (bit 1) trap data. */
static volatile uint32_t g_guest_seccomp_trap_flags = 0;
static volatile int g_guest_seccomp_installed = 0;

static long passthrough(long number, const long a[6])
{
    return raw_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
}

/* Reads [off, off+len) of fd into dst; the tail past end of file is zero. */
static long read_region(int fd, unsigned char *dst, unsigned long len, long off)
{
    /* Fresh MAP_ANONYMOUS pages are already zero-initialized by the kernel,
     * so we can read in large 1 MiB chunks and stop immediately on EOF. */
    while (len) {
        unsigned long chunk = len > (1024ul * 1024ul) ? (1024ul * 1024ul) : len;
        long n = raw_syscall(__NR_pread64, fd, (long)dst, (long)chunk, off, 0, 0);
        if (n < 0)
            return n;
        if (n == 0)
            break;
        dst += n;
        off += n;
        len -= (unsigned long)n;
    }
    return 0;
}

static int guest_path_has_prefix(const char *path, const char *prefix)
{
    size_t n = 0;
    while (prefix[n]) {
        if (path[n] != prefix[n])
            return 0;
        n++;
    }
    if (n == 1 && prefix[0] == '/')
        return path[0] == '/';
    return path[n] == '\0' || path[n] == '/';
}

static int should_skip_inline_patch_fd(int fd)
{
    if (!g_payload_config.seccomp_backstop)
        return 0;
    if (g_payload_config.no_inline_patch_all)
        return 1;
    uint32_t cnt = g_payload_config.no_inline_patch_count;
    if (!cnt || fd < 0)
        return 0;
    if (cnt > 8) cnt = 8;
    char gpath[CONFIG_MAX_PATH];
    if (proot_fd_guest_path(fd, gpath, sizeof(gpath)) < 0)
        return 0;
    for (uint32_t i = 0; i < cnt; i++) {
        if (guest_path_has_prefix(gpath, g_payload_config.no_inline_patch_prefixes[i]))
            return 1;
    }
    return 0;
}

/* An executable file mapping becomes an anonymous copy (code signing
 * refuses executable file pages on HarmonyOS), patched while writable and
 * made executable once. Fail closed: no unhooked syscall is left runnable. */
static long map_exec_copy(const long a[6])
{
    unsigned long len = (unsigned long)a[1];
    int prot = (int)a[2], fd = (int)a[4];
    long mapped = raw_syscall(__NR_mmap, a[0], (long)len, PROT_READ | PROT_WRITE,
                              a[3] | MAP_ANONYMOUS, -1, 0);
    if (mapped < 0)
        return mapped;
    long rc = read_region(fd, (unsigned char *)mapped, len, a[5]);
    int skip_patch = should_skip_inline_patch_fd(fd);
    if (rc >= 0 && !skip_patch &&
        install_hook_file((void *)mapped, len, (void *)&_start,
                          PROT_READ | PROT_WRITE, fd, (unsigned long)a[5]) < 0) {
        /* With --seccomp-backstop active, unpatched svc #0 traps cleanly into
         * payload via SIGSYS so even >256 MiB or packed VA segments succeed. */
        if (!g_payload_config.seccomp_backstop)
            rc = -ENOMEM;
    }
    if (rc >= 0)
        rc = platform_mprotect_exec(mapped, len, prot);
    if (rc < 0) {
        raw_syscall(__NR_munmap, mapped, (long)len, 0, 0, 0, 0);
        return rc;
    }
    vma_track_add((uintptr_t)mapped, (size_t)len, (uint64_t)a[5], fd);
    return mapped;
}

/* HarmonyOS refuses mprotect(..., PROT_EXEC) on non-anonymous VMAs (e.g.
 * MAP_PRIVATE file/memfd mappings or mremap()ed read-only segments) with
 * -EACCES even inside PR_HM_JIT. On Linux, upgrading a MAP_PRIVATE mapping
 * to executable is valid; materialize the private pages as an anonymous copy
 * preserving their exact bytes, then apply platform_mprotect_exec(). Never
 * convert MAP_SHARED mappings. */
static int parse_maps_hex(const char **pp, const char *end, uintptr_t *out)
{
    const char *p = *pp;
    uintptr_t v = 0;
    int digits = 0;
    while (p < end) {
        char c = *p;
        unsigned d;
        if (c >= '0' && c <= '9') d = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') d = (unsigned)(c - 'A' + 10);
        else break;
        v = (v << 4) | d;
        digits++;
        p++;
    }
    if (!digits) return 0;
    *pp = p;
    *out = v;
    return 1;
}

static long mprotect_private_exec_copy(unsigned long addr, size_t len, int prot)
{
    if (!len)
        return 0;
    uintptr_t lo = (uintptr_t)addr & ~(uintptr_t)4095ul;
    uintptr_t raw_end = (uintptr_t)addr + len;
    if (raw_end < (uintptr_t)addr)
        return -EACCES;
    uintptr_t hi = (raw_end + 4095ul) & ~(uintptr_t)4095ul;
    if (hi <= lo || (hi - lo) > (256ul << 20))
        return -EACCES;
    size_t plen = (size_t)(hi - lo);

    long mfd = raw_syscall(__NR_openat, -100 /* AT_FDCWD */, (long)"/proc/self/maps",
                           0x80000 /* O_RDONLY | O_CLOEXEC */, 0, 0, 0);
    if (mfd < 0)
        return -EACCES;

    struct { uintptr_t lo, hi; int readable; } subs[16];
    int nsubs = 0;
    uintptr_t covered = lo;
    int ok = 1;
    char rbuf[4096], line[512];
    size_t line_len = 0;
    int eof = 0;

    while (!eof && ok && covered < hi) {
        long nr = raw_syscall(__NR_read, mfd, (long)rbuf, sizeof(rbuf), 0, 0, 0);
        if (nr <= 0) {
            eof = 1;
            if (!line_len) break;
        }
        size_t ri = 0;
        while (ok && covered < hi && (ri < (size_t)(nr > 0 ? nr : 0) || (eof && line_len > 0))) {
            int got = 0;
            if (!eof) {
                while (ri < (size_t)nr) {
                    char ch = rbuf[ri++];
                    if (line_len + 1 < sizeof(line))
                        line[line_len++] = ch;
                    if (ch == '\n') { got = 1; break; }
                }
            } else {
                got = 1;
            }
            if (!got) break;
            const char *p = line, *lend = line + line_len;
            uintptr_t vlo = 0, vhi = 0;
            if (parse_maps_hex(&p, lend, &vlo) && p < lend && *p == '-' &&
                (++p, parse_maps_hex(&p, lend, &vhi)) && p + 5 <= lend && *p == ' ') {
                const char *perms = p + 1;
                if (vhi > covered && vlo < hi) {
                    if (vlo > covered || perms[3] != 'p' || nsubs >= 16) {
                        ok = 0;
                    } else {
                        uintptr_t ov_lo = vlo > lo ? vlo : lo;
                        uintptr_t ov_hi = vhi < hi ? vhi : hi;
                        subs[nsubs].lo = ov_lo;
                        subs[nsubs].hi = ov_hi;
                        subs[nsubs].readable = (perms[0] == 'r');
                        nsubs++;
                        covered = ov_hi;
                    }
                } else if (vlo >= hi) {
                    ok = (covered >= hi);
                    eof = 1;
                }
            }
            line_len = 0;
            if (eof) break;
        }
    }
    raw_syscall(__NR_close, mfd, 0, 0, 0, 0, 0);
    if (!ok || covered < hi)
        return -EACCES;

    long tmp = raw_syscall(__NR_mmap, 0, (long)plen, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tmp < 0)
        return tmp;
    for (int i = 0; i < nsubs; i++) {
        if (!subs[i].readable) {
            long mrc = raw_syscall(__NR_mprotect, (long)subs[i].lo,
                                   (long)(subs[i].hi - subs[i].lo), PROT_READ, 0, 0, 0);
            if (mrc < 0) {
                raw_syscall(__NR_munmap, tmp, (long)plen, 0, 0, 0, 0);
                return -EACCES;
            }
        }
    }
    memcpy((void *)tmp, (const void *)lo, plen);
    long mapped = raw_syscall(__NR_mmap, (long)lo, (long)plen, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (mapped != (long)lo) {
        raw_syscall(__NR_munmap, tmp, (long)plen, 0, 0, 0, 0);
        return mapped < 0 ? mapped : -EACCES;
    }
    memcpy((void *)lo, (const void *)tmp, plen);
    raw_syscall(__NR_munmap, tmp, (long)plen, 0, 0, 0, 0);
    long rc = platform_mprotect_exec(lo, plen, prot);
    if (rc == 0)
        vma_track_remove(lo, plen);
    return rc;
}

/* Executable memory is readable (the hook scanner reads it) and hooked
 * before any of it can run. */
static long map_exec(long number, long a[6])
{
    a[2] |= PROT_READ;
    /* A file's executable mapping becomes a hooked private copy, frozen at
     * this point: for a shared mapping, code written later through another
     * mapping of the same object (a JIT's dual mapping of a memfd) would
     * never show, and the copy would run stale bytes. Refused, as HarmonyOS
     * refuses it natively, so the program falls back to anonymous memory. */
    if (number == __NR_mmap && !(a[3] & MAP_ANONYMOUS) && (int)a[4] >= 0 &&
        (a[3] & MAP_TYPE) != MAP_PRIVATE)
        return -EACCES;
    if (number == __NR_mmap && !(a[3] & MAP_ANONYMOUS) && (int)a[4] >= 0)
        return map_exec_copy(a);
    long ret;
    if (number == __NR_mmap) {
        if ((a[3] & MAP_ANONYMOUS) && (a[2] & PROT_EXEC) && platform_is_harmonyos()) {
            long rw_a[6] = { a[0], a[1], (a[2] & ~PROT_EXEC) | PROT_READ | PROT_WRITE, a[3], a[4], a[5] };
            ret = passthrough(number, rw_a);
            if (ret >= 0) {
                long prc = platform_mprotect_exec((unsigned long)ret, (unsigned long)a[1], (int)a[2]);
                if (prc < 0) {
                    raw_syscall(__NR_munmap, ret, a[1], 0, 0, 0, 0);
                    return prc;
                }
            }
        } else {
            ret = passthrough(number, a);
        }
        /* Fresh MAP_ANONYMOUS pages are kernel-zeroed (0 svc #0 instructions);
         * skipping the scan avoids faulting in multi-MiB JIT arenas prematurely. */
        if (ret >= 0 && (a[3] & MAP_ANONYMOUS))
            return ret;
    } else {
        ret = platform_mprotect_exec(a[0], (unsigned long)a[1], (int)a[2]);
        if (ret == -EACCES && platform_is_harmonyos())
            ret = mprotect_private_exec_copy((unsigned long)a[0], (size_t)a[1], (int)a[2]);
    }
    if (ret < 0)
        return ret;
    unsigned long base = number == __NR_mmap ? (unsigned long)ret : (unsigned long)a[0];
    /* When --seccomp-backstop is combined with --no-inline-patch*, leave
     * runtime mprotect(..., PROT_EXEC) regions unmodified so self-decrypting
     * or integrity-checked code stays intact while svc #0 traps cleanly. */
    int skip_mprot_patch = (g_payload_config.seccomp_backstop &&
                            (g_payload_config.no_inline_patch_all ||
                             g_payload_config.no_inline_patch_count > 0));
    if (!skip_mprot_patch &&
        install_hook_prot((void *)base, (size_t)a[1], (void *)&_start, (int)a[2]) < 0) {
        /* When --seccomp-backstop is active, leave unpatched svc #0 to the
         * seccomp SIGSYS backstop instead of failing the mapping. */
        if (!g_payload_config.seccomp_backstop) {
            /* Fail closed: drop the mapping (or its execute right). */
            if (number == __NR_mmap)
                raw_syscall(__NR_munmap, (long)base, a[1], 0, 0, 0, 0);
            else
                raw_syscall(__NR_mprotect, (long)base, a[1], a[2] & ~PROT_EXEC, 0, 0, 0);
            return -ENOMEM;
        }
    }
    return number == __NR_mmap ? ret : 0;
}

/* Wrap a guest SECCOMP_SET_MODE_FILTER program with a 7-instruction prefix
 * that returns SECCOMP_RET_ALLOW for syscalls issued by svbox's own loader
 * and payload images ([LOADER_FIXED_BASE, +16 MiB) and [PAYLOAD_FIXED_BASE,
 * +16 MiB)), so guest seccomp-BPF filters work natively without blocking
 * svbox's internal VFS, broker, or PR_HM_JIT syscalls. */
struct svbox_sock_filter {
    uint16_t code;
    uint8_t jt;
    uint8_t jf;
    uint32_t k;
};
struct svbox_sock_fprog {
    uint16_t len;
    struct svbox_sock_filter *filter;
};

static long install_wrapped_seccomp(long number, const long a[6], unsigned long fprog_addr)
{
    if (!fprog_addr)
        return passthrough(number, a);
    const struct svbox_sock_fprog *up = (const struct svbox_sock_fprog *)fprog_addr;
    uint16_t ulen = up->len;
    const struct svbox_sock_filter *ufilt = up->filter;
    if (!ufilt || ulen == 0 || ulen > 4087u)
        return passthrough(number, a);

    uint32_t tflags = 0;
    for (uint16_t i = 0; i < ulen; i++) {
        if (ufilt[i].code == 0x06u /* BPF_RET | BPF_K */ &&
            (ufilt[i].k & 0xffff0000u) == 0x00030000u /* SECCOMP_RET_TRAP */) {
            tflags |= ((ufilt[i].k & 0xffffu) == 0u) ? 1u : 2u;
        } else if (ufilt[i].code == 0x16u /* BPF_RET | BPF_A */) {
            tflags |= 3u;
        }
    }

    uintptr_t pay_base = (uintptr_t)&_start;
    uint32_t ldr_hi = (uint32_t)(LOADER_FIXED_BASE >> 32);
    uint32_t pay_hi = (uint32_t)(pay_base >> 32);
    uint32_t pay_lo = (uint32_t)(pay_base & 0xffffffffu);
    uint32_t pay_end = pay_lo + 0x01000000u;
    uint32_t fp_after_lo = (uint32_t)((uintptr_t)&fast_passthrough_after & 0xffffffffu);
    uint32_t fp_svc_lo = (uint32_t)((uintptr_t)&fast_passthrough_svc & 0xffffffffu);

    enum { PREFIX_LEN = 9 };
    size_t total = (size_t)ulen + PREFIX_LEN;
    size_t bytes = total * sizeof(struct svbox_sock_filter);
    struct svbox_sock_filter stack_buf[512];
    struct svbox_sock_filter *buf = stack_buf;
    int used_mmap = 0;
    if (total > 512) {
        long m = raw_syscall(__NR_mmap, 0, (long)bytes, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (m < 0)
            return -ENOMEM;
        buf = (struct svbox_sock_filter *)m;
        used_mmap = 1;
    }
    /* Allow internal syscalls from loader and payload ranges while still
     * routing fast_passthrough's guest svc #0 through the guest filter. */
    struct svbox_sock_filter prefix[PREFIX_LEN] = {
        { 0x20, 0, 0, 12u },                  /* 0: ld ip_hi */
        { 0x15, 0, 7, pay_hi == ldr_hi ? ldr_hi : pay_hi }, /* 1: != hi -> guest[0] */
        { 0x20, 0, 0, 8u },                   /* 2: ld ip_lo */
        { 0x35, 0, 4, pay_hi == ldr_hi ? 0x01000000u : 0u }, /* 3: < 16 MiB (loader) -> ALLOW */
        { 0x35, 0, 4, pay_lo },               /* 4: < pay_lo -> guest[0] */
        { 0x35, 3, 0, pay_end },              /* 5: >= pay_end -> guest[0] */
        { 0x15, 2, 0, fp_after_lo },          /* 6: == fast_passthrough_after -> guest[0] */
        { 0x15, 1, 0, fp_svc_lo },            /* 7: == fast_passthrough_svc -> guest[0] */
        { 0x06, 0, 0, 0x7fff0000u },          /* 8: ret SECCOMP_RET_ALLOW */
    };
    memcpy(buf, prefix, sizeof(prefix));
    memcpy(buf + PREFIX_LEN, ufilt, (size_t)ulen * sizeof(struct svbox_sock_filter));
    struct svbox_sock_fprog wp = { (uint16_t)total, buf };
    long wa[6] = { a[0], a[1], a[2], a[3], a[4], a[5] };
    wa[2] = (long)&wp;
    long rc = passthrough(number, wa);
    if (used_mmap)
        raw_syscall(__NR_munmap, (long)buf, (long)bytes, 0, 0, 0, 0);
    if (rc == 0) {
        if (tflags)
            __atomic_fetch_or(&g_guest_seccomp_trap_flags, tflags, __ATOMIC_RELEASE);
        __atomic_store_n(&g_guest_seccomp_installed, 1, __ATOMIC_RELEASE);
    }
    return rc;
}

long dispatch_syscall(long number, long a[6])
{
    if (number == __NR_prctl && a[0] == PR_GET_AUXV)
        return proot_get_auxv(a);
    if (number == __NR_prctl && a[0] == SVBOX_PR_GET_GUEST_SECCOMP_TRAPS)
        return (long)__atomic_load_n(&g_guest_seccomp_trap_flags, __ATOMIC_ACQUIRE);
    if (number == __NR_execve || number == __NR_execveat)
        return proot_execve(number, a);
    if (proot_handles_syscall(number))
        return proot_syscall(number, a);
    long routed;
    if (broker_route(number, a, &routed))
        return routed;
    long faked;
    if (fake_ids_syscall(number, a, &faked))
        return faked;
    if (async_io_syscall(number, a, &faked))
        return faked;
    if (bpf_emu_syscall(number, a, &faked))
        return faked;
    switch (number) {
    case __NR_sched_setaffinity:
        if (g_payload_config.cpu_mask != 0) {
            if (!a[2] || (unsigned long)a[1] < sizeof(uint32_t))
                return -EINVAL;
            size_t cpy = (unsigned long)a[1] < sizeof(uint64_t) ? (size_t)a[1] : sizeof(uint64_t);
            uint64_t req = 0;
            memcpy(&req, (const void *)a[2], cpy);
            uint64_t clamped = req & g_payload_config.cpu_mask;
            if (!clamped)
                clamped = g_payload_config.cpu_mask;
            unsigned long kmask[2] = { (unsigned long)clamped, 0ul };
            return raw_syscall(__NR_sched_setaffinity, a[0], sizeof(kmask), (long)kmask, 0, 0, 0);
        }
        return passthrough(number, a);
    case __NR_sched_getaffinity:
        if (g_payload_config.cpu_mask != 0) {
            long rc = passthrough(number, a);
            if (rc > 0 && a[2] && (unsigned long)a[1] >= sizeof(uint32_t)) {
                size_t cpy = (unsigned long)a[1] < sizeof(uint64_t) ? (size_t)a[1] : sizeof(uint64_t);
                uint64_t cur = 0;
                memcpy(&cur, (const void *)a[2], cpy);
                cur &= g_payload_config.cpu_mask;
                if (!cur)
                    cur = g_payload_config.cpu_mask;
                memcpy((void *)a[2], &cur, cpy);
                if ((unsigned long)rc > cpy)
                    memset((unsigned char *)a[2] + cpy, 0, (size_t)rc - cpy);
            }
            return rc;
        }
        return passthrough(number, a);
#ifdef __NR_sched_setscheduler
    case __NR_sched_setscheduler:
#endif
#ifdef __NR_sched_setparam
    case __NR_sched_setparam:
#endif
#ifdef __NR_sched_setattr
    case __NR_sched_setattr:
#endif
    {
        long rc = passthrough(number, a);
        /* In an unprivileged container holding virtual CAP_SYS_NICE (23),
         * emulate real-time scheduling elevation success when host rejects -EPERM. */
        if (rc == -EPERM && fake_ids_capable(23 /* CAP_SYS_NICE */))
            return 0;
        return rc;
    }
#ifdef __NR_memfd_create
    case __NR_memfd_create:
        if (g_payload_config.deny_memfd_prefix[0] && a[0]) {
            const char *name = (const char *)a[0];
            const char *pfx = g_payload_config.deny_memfd_prefix;
            size_t i = 0;
            while (pfx[i] && name[i] == pfx[i]) i++;
            if (!pfx[i])
                return -ENOSYS;
        }
        return passthrough(number, a);
#endif
    case __NR_sysinfo: {
        long rc = passthrough(number, a);
        if (rc == 0 && g_payload_config.mem_limit_mb > 0 && a[0]) {
            /* Linux AArch64 struct sysinfo layout:
             * 0: uptime(8), 8: loads[3](24), 32: totalram(8), 40: freeram(8),
             * 48: sharedram(8), 56: bufferram(8), 64: totalswap(8), 72: freeswap(8),
             * 80: procs(2), pad(6), 88: totalhigh(8), 96: freehigh(8), 104: mem_unit(4) */
            unsigned char *si = (unsigned char *)a[0];
            uint32_t unit = 1;
            uint64_t totalram = 0, freeram = 0;
            memcpy(&unit, si + 104, sizeof(unit));
            if (unit == 0) unit = 1;
            memcpy(&totalram, si + 32, sizeof(totalram));
            memcpy(&freeram, si + 40, sizeof(freeram));
            uint64_t cap_units = ((uint64_t)g_payload_config.mem_limit_mb * 1024ull * 1024ull) / (uint64_t)unit;
            if (totalram > cap_units) {
                totalram = cap_units;
                if (freeram > cap_units)
                    freeram = (cap_units * 3ull) / 4ull;
                memcpy(si + 32, &totalram, sizeof(totalram));
                memcpy(si + 40, &freeram, sizeof(freeram));
            }
        }
        return rc;
    }
    case __NR_mmap:
        /* On HarmonyOS, a large unhinted mmap(NULL, ...) (e.g. Android Bionic
         * Scudo's 8 GiB primary arena) is placed bottom-up from 0x10000,
         * exhausting the low 4 GiB space required by Android ART's 32-bit
         * compressed heap and boot image. Hint it above 4 GiB when unfixed. */
        if (platform_is_harmonyos() && a[0] == 0 && (unsigned long)a[1] >= (1UL << 28) &&
            !(a[3] & (MAP_FIXED | MAP_FIXED_NOREPLACE)))
            a[0] = 0x1000000000L;
        if (a[2] & PROT_EXEC)
            return map_exec(number, a);
        {
            long rc = passthrough(number, a);
            if (rc >= 0 && (a[3] & MAP_FIXED))
                vma_track_remove((uintptr_t)rc, (size_t)a[1]);
            return rc;
        }
    case __NR_mprotect:
        if (a[2] & PROT_EXEC)
            return map_exec(number, a);
        return passthrough(number, a);
#ifdef __NR_mremap
    case __NR_mremap: {
        /* On Linux, mremap(..., MREMAP_DONTUNMAP) on a file-backed MAP_PRIVATE
         * mapping keeps the source pages intact (clean pages re-fault from the
         * backing file). Because map_exec_copy materializes executable file
         * segments as MAP_ANONYMOUS copies, forwarding MREMAP_DONTUNMAP to the
         * host kernel would move the anonymous pages and zero-fill the live
         * source segment. Duplicate via anonymous copy so both ranges retain
         * the exact bytes. */
        unsigned long flags = (unsigned long)a[3];
        if ((flags & 4ul /* MREMAP_DONTUNMAP */) && a[1] > 0 && a[2] > 0) {
            uintptr_t old_addr = (uintptr_t)a[0];
            size_t old_len = (size_t)a[1];
            size_t new_len = (size_t)a[2];
            uintptr_t ov_lo = 0, ov_hi = 0;
            if ((old_addr & 4095ul) == 0 && old_addr + old_len > old_addr &&
                vma_track_next_overlap(old_addr, old_addr + old_len, &ov_lo, &ov_hi)) {
                if ((flags & 1ul /* MREMAP_MAYMOVE */) == 0)
                    return -EINVAL;
                int fixed = (flags & 2ul /* MREMAP_FIXED */) != 0;
                long hint = fixed ? a[4] : 0;
                if (fixed) {
                    uintptr_t h = (uintptr_t)hint;
                    if ((h & 4095ul) != 0 || h + new_len <= h)
                        return -EINVAL;
                    if (h < old_addr + old_len && h + new_len > old_addr)
                        return -EINVAL;
                }
                int mflags = MAP_PRIVATE | MAP_ANONYMOUS | (fixed ? MAP_FIXED : 0);
                long dst = raw_syscall(__NR_mmap, hint, (long)new_len,
                                       PROT_READ | PROT_WRITE, mflags, -1, 0);
                if (dst < 0)
                    return dst;
                size_t copy_len = old_len < new_len ? old_len : new_len;
                memcpy((void *)dst, (const void *)old_addr, copy_len);
                long prc = platform_mprotect_exec((unsigned long)dst, new_len,
                                                  PROT_READ | PROT_EXEC);
                if (prc < 0) {
                    raw_syscall(__NR_munmap, dst, (long)new_len, 0, 0, 0, 0);
                    return prc;
                }
                if (fixed)
                    vma_track_remove((uintptr_t)dst, new_len);
                return dst;
            }
        }
        return passthrough(number, a);
    }
#endif
    case __NR_madvise: {
        int advice = (int)a[2];
        /* On Linux, MADV_DONTNEED / MADV_DONTNEED_LOCKED on a file-backed
         * MAP_PRIVATE mapping discards private dirty pages and re-faults clean
         * bytes from the backing file, whereas on MAP_ANONYMOUS it zero-fills
         * them. Because map_exec_copy materializes executable file segments as
         * MAP_ANONYMOUS copies, forwarding destructive advices on those ranges
         * would wipe live code to zeroes (SIGILL). Split around tracked exec
         * copies so only genuinely anonymous sub-ranges are advised. */
        if (advice == 4 /* MADV_DONTNEED */ ||
            advice == 8 /* MADV_FREE */ ||
            advice == 24 /* MADV_DONTNEED_LOCKED */) {
            uintptr_t addr = (uintptr_t)a[0];
            size_t len = (size_t)a[1];
            if ((addr & 4095ul) != 0)
                return -EINVAL;
            if (!len)
                return passthrough(number, a);
            uintptr_t end = addr + len;
            if (end < addr)
                return -EINVAL;
            uintptr_t align_end = (end + 4095ul) & ~4095ul;
            if (align_end < end)
                align_end = ~(uintptr_t)4095ul;
            uintptr_t ov_lo = 0, ov_hi = 0;
            if (!vma_track_next_overlap(addr, align_end, &ov_lo, &ov_hi))
                return passthrough(number, a);
            uintptr_t cur = addr;
            long rc = 0;
            while (cur < align_end) {
                if (!vma_track_next_overlap(cur, align_end, &ov_lo, &ov_hi)) {
                    long r = raw_syscall(__NR_madvise, (long)cur, (long)(align_end - cur),
                                         advice, 0, 0, 0);
                    if (r < 0 && rc == 0) rc = r;
                    break;
                }
                if (ov_lo > cur) {
                    long r = raw_syscall(__NR_madvise, (long)cur, (long)(ov_lo - cur),
                                         advice, 0, 0, 0);
                    if (r < 0 && rc == 0) rc = r;
                }
                if (ov_hi <= cur)
                    break;
                cur = ov_hi;
            }
            return rc;
        }
        return passthrough(number, a);
    }
    /* HarmonyOS AArch64 enables TBID0 (data-only TBI), so tagged pointers
     * trap infinitely on instruction fetch (e.g. JIT code in heap pages).
     * Also keep PR_GET_SECCOMP / PR_GET_NO_NEW_PRIVS consistent with
     * /proc/self/status when svbox's own seccomp backstop is active. */
    case __NR_prctl: {
        static int guest_nnp = 0;
        if (platform_is_harmonyos() && (a[0] == 55 /* PR_SET_TAGGED_ADDR_CTRL */ ||
                                        a[0] == 56 /* PR_GET_TAGGED_ADDR_CTRL */))
            return -EINVAL;
        if (a[0] == 22 /* PR_SET_SECCOMP */ && a[1] == 2 /* SECCOMP_MODE_FILTER */)
            return install_wrapped_seccomp(number, a, (unsigned long)a[2]);
        if (g_payload_config.seccomp_backstop || g_payload_config.trap_sigsys) {
            if (a[0] == 21 /* PR_GET_SECCOMP */)
                return __atomic_load_n(&g_guest_seccomp_installed, __ATOMIC_ACQUIRE) ? 2 : 0;
            if (a[0] == 38 /* PR_SET_NO_NEW_PRIVS */ && a[1] == 1 && !a[2] && !a[3] && !a[4]) {
                long rc = passthrough(number, a);
                if (rc == 0)
                    guest_nnp = 1;
                return rc;
            }
            if (a[0] == 39 /* PR_GET_NO_NEW_PRIVS */)
                return guest_nnp;
        }
        return passthrough(number, a);
    }
#ifdef __NR_seccomp
    case __NR_seccomp:
        if (a[0] == 1 /* SECCOMP_SET_MODE_FILTER */)
            return install_wrapped_seccomp(number, a, (unsigned long)a[2]);
        return passthrough(number, a);
#endif
    /* glibc falls back from both; the sandbox kills rseq with SIGSYS. */
    case __NR_rseq:
    case __NR_clone3:
        return -ENOSYS;
    /* R4: util-linux tries the new mount API first and falls back to
     * mount(2), which the bridge emulates, only on ENOSYS. */
    case __NR_fsopen: case __NR_fsconfig: case __NR_fsmount: case __NR_fspick:
    case __NR_open_tree: case __NR_move_mount: case __NR_mount_setattr:
        return mounts_enabled() ? -ENOSYS : passthrough(number, a);
    /* Emulated mount table: unshare(CLONE_NEWNS) clones the mount table into
     * a private memfd so subsequent mounts stay isolated from parent/siblings. */
    case __NR_unshare:
        if (mounts_enabled() && (a[0] & ~0x00020000L /* CLONE_NEWNS */) == 0)
            return (a[0] & 0x00020000L) ? mounts_unshare() : 0;
        return platform_is_harmonyos() ? -ENOSYS : passthrough(number, a);
    /* HarmonyOS app sandboxes refuse AF_NETLINK/NETLINK_KOBJECT_UEVENT with
     * EACCES; fall back to an idle AF_UNIX SOCK_DGRAM so uevent listeners
     * (udev/UEventObserver) block cleanly instead of aborting. */
    case __NR_socket:
        if (platform_is_harmonyos() && a[0] == 16 /* AF_NETLINK */ &&
            a[2] == 15 /* NETLINK_KOBJECT_UEVENT */) {
            long rc = passthrough(number, a);
            if (rc == -EACCES || rc == -EPERM)
                return raw_syscall(__NR_socket, 1 /* AF_UNIX */,
                                   (a[1] & ~0xffL) | 2 /* SOCK_DGRAM */, 0, 0, 0, 0);
            return rc;
        }
        return passthrough(number, a);
    /* The HarmonyOS sandbox kills these with SIGSYS: report them as not
     * implemented instead. Other kernels serve them natively. */
    case __NR_mount: case __NR_umount2: case __NR_pivot_root: case __NR_chroot:
    case __NR_setns: case __NR_kcmp: case __NR_fchmodat2:
    case __NR_close_range: case __NR_openat2: case __NR_open_by_handle_at:
    case __NR_io_uring_enter: case __NR_io_uring_register:
#ifdef __NR_bpf
    case __NR_bpf:
#endif
        return platform_is_harmonyos() ? -ENOSYS : passthrough(number, a);
    /* Privileged host-wide syscalls killed by HarmonyOS HAP seccomp: return EPERM. */
#ifdef __NR_settimeofday
    case __NR_settimeofday:
#endif
#ifdef __NR_clock_settime
    case __NR_clock_settime:
#endif
#ifdef __NR_adjtimex
    case __NR_adjtimex:
#endif
#ifdef __NR_clock_adjtime
    case __NR_clock_adjtime:
#endif
#ifdef __NR_sethostname
    case __NR_sethostname:
#endif
#ifdef __NR_setdomainname
    case __NR_setdomainname:
#endif
#ifdef __NR_acct
    case __NR_acct:
#endif
#ifdef __NR_reboot
    case __NR_reboot:
#endif
#ifdef __NR_syslog
    case __NR_syslog:
#endif
        return platform_is_harmonyos() ? -EPERM : passthrough(number, a);
    case __NR_close:
        proot_vfd_close((int)a[0]);
        return passthrough(number, a);
    case __NR_dup:
    case __NR_dup3: {
        long rc = passthrough(number, a);
        if (rc >= 0)
            proot_vfd_dup((int)a[0], (int)rc);
        return rc;
    }
    case __NR_fcntl: {
        long rc = passthrough(number, a);
        if (rc >= 0 && (a[1] == 0 /* F_DUPFD */ || a[1] == 1030 /* F_DUPFD_CLOEXEC */))
            proot_vfd_dup((int)a[0], (int)rc);
        return rc;
    }
    case __NR_fstat: {
        long rc = passthrough(number, a);
        if (rc == 0 && a[1])
            proot_vfd_fix_fstat((int)a[0], (void *)a[1]);
        return rc;
    }
    case __NR_ioctl: {
        long rc = passthrough(number, a);
        /* Virtualized procfs memfds: host LSMs can return -EACCES on ioctl
         * (e.g. FIONREAD from Java FileInputStream.available); real procfs
         * files return -ENOTTY. */
        if (rc == -EACCES && proot_vfd_is_procfs((int)a[0]))
            return -ENOTTY;
        return rc;
    }
#ifdef __NR_fgetxattr
    case __NR_fgetxattr:
        if (g_payload_config.mode == CONFIG_MODE_CONTAINER && a[1] &&
            !strcmp((const char *)a[1], "security.selinux"))
            return -ENODATA;
        return passthrough(number, a);
#endif
    default:
        return passthrough(number, a);
    }
}
