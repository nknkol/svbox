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

static long passthrough(long number, const long a[6])
{
    return raw_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
}

/* Reads [off, off+len) of fd into dst; the tail past end of file is zero. */
static long read_region(int fd, unsigned char *dst, unsigned long len, long off)
{
    while (len) {
        unsigned long chunk = len > 4096 ? 4096 : len;
        long n = raw_syscall(__NR_pread64, fd, (long)dst, (long)chunk, off, 0, 0);
        if (n < 0)
            return n;
        if (n == 0) {
            for (unsigned long i = 0; i < len; i++)
                dst[i] = 0;
            break;
        }
        dst += n;
        off += n;
        len -= (unsigned long)n;
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
    if (rc >= 0 && install_hook_file((void *)mapped, len, (void *)&_start,
                                     PROT_READ | PROT_WRITE, fd, (unsigned long)a[5]) < 0)
        rc = -ENOMEM;
    if (rc >= 0)
        rc = platform_mprotect_exec(mapped, len, prot);
    if (rc < 0) {
        raw_syscall(__NR_munmap, mapped, (long)len, 0, 0, 0, 0);
        return rc;
    }
    return mapped;
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
    long ret = number == __NR_mmap ? passthrough(number, a) :
        platform_mprotect_exec(a[0], (unsigned long)a[1], (int)a[2]);
    if (ret < 0)
        return ret;
    unsigned long base = number == __NR_mmap ? (unsigned long)ret : (unsigned long)a[0];
    if (install_hook_prot((void *)base, (size_t)a[1], (void *)&_start, (int)a[2]) < 0) {
        /* Fail closed: drop the mapping (or its execute right). */
        if (number == __NR_mmap)
            raw_syscall(__NR_munmap, (long)base, a[1], 0, 0, 0, 0);
        else
            raw_syscall(__NR_mprotect, (long)base, a[1], a[2] & ~PROT_EXEC, 0, 0, 0);
        return -ENOMEM;
    }
    return number == __NR_mmap ? ret : 0;
}

long dispatch_syscall(long number, long a[6])
{
    if (number == __NR_prctl && a[0] == PR_GET_AUXV)
        return proot_get_auxv(a);
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
    switch (number) {
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
        return passthrough(number, a);
    case __NR_mprotect:
        if (a[2] & PROT_EXEC)
            return map_exec(number, a);
        return passthrough(number, a);
    /* HarmonyOS AArch64 enables TBID0 (data-only TBI), so tagged pointers
     * trap infinitely on instruction fetch (e.g. JIT code in heap pages). */
    case __NR_prctl:
        if (platform_is_harmonyos() && (a[0] == 55 /* PR_SET_TAGGED_ADDR_CTRL */ ||
                                        a[0] == 56 /* PR_GET_TAGGED_ADDR_CTRL */))
            return -EINVAL;
        return passthrough(number, a);
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
    default:
        return passthrough(number, a);
    }
}
