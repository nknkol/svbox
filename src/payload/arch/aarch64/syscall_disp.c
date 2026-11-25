#include <asm/unistd.h>
#include <errno.h>
#include <string.h>
#include "syscall_nums.h"
#include "dispatch.h"
#include "integrity.h"
#include "config.h"
#include "vfs_bridge.h"
#include "container_state.h"
#include "union_view.h"
#include "net_view.h"
#include "net_stack.h"
#include "fake_ids.h"
#include "host_syscall.h"
#include "fd_runtime.h"
#include "hook_runtime.h"
#include "vdev.h"
static inline long dispatch_call(long n, long args[6])
{
    return g_payload_config.guard != GUARD_NONE
        ? fd_runtime_dispatch(n, args)
        : dispatch_syscall(n, args);
}
#define DISPATCH(n, args) dispatch_call(n, args)

typedef struct {
    unsigned long regs[30]; // x0 - x29
    unsigned long lr;       // x30
    unsigned long _pad;
} pt_regs;

long raw_syscall(long sys_no, long a1, long a2, long a3, long a4, long a5, long a6);

/* Runs on a payload stack (payload_stack.c), with regs (the saved general
 * registers) on the guest's. */
long syscall_dispatcher(long sys_no, pt_regs *regs)
{
    long *a = (long *)regs->regs;
    /* A thread unmapping the stack it entered on (musl's __unmapself: munmap
     * then exit, touching no stack): nothing can return to it, since the
     * entry saved the registers there. Its only next step is exit. */
    if (sys_no == __NR_munmap && (unsigned long)regs - (unsigned long)a[0] < (unsigned long)a[1]) {
        long rc = raw_syscall(__NR_munmap, a[0], a[1], 0, 0, 0, 0);
        if (!rc)
            raw_syscall(__NR_exit, 0, 0, 0, 0, 0, 0);
        return rc;
    }
    /* The backends may rewrite their copy; the saved registers stay. */
    long args[6] = {a[0], a[1], a[2], a[3], a[4], a[5]};
    long ret;

    if (sys_no >= __NR_setxattrat && sys_no <= __NR_file_setattr)
        return -ENOSYS; /* Untranslated newer path calls (syscall_nums.h). */
    if (integrity_check(sys_no, a, &ret))
        return ret;
    /* Destructive madvise on a thread's own stack (e.g. reclaiming unused
     * stack pages with a 1-page margin below guest SP) can overlap our active
     * pt_regs and SIGSYS rt_sigframe (~5 KiB on AArch64), zeroing the return
     * context. Preserve [page_down(regs), page_up(regs + 12 KiB)). */
    if (sys_no == __NR_madvise &&
        (a[2] == 4 /* MADV_DONTNEED */ || a[2] == 8 /* MADV_FREE */ ||
         a[2] == 9 /* MADV_REMOVE */ || a[2] == 24 /* MADV_DONTNEED_LOCKED */) &&
        a[1] > 0) {
        uintptr_t lo = (uintptr_t)a[0];
        uintptr_t hi = lo + (uintptr_t)a[1];
        uintptr_t guard_lo = (uintptr_t)regs & ~(uintptr_t)4095;
        uintptr_t guard_hi = ((uintptr_t)regs + 12288u + 4095u) & ~(uintptr_t)4095;
        if (hi > lo && lo < guard_hi && hi > guard_lo) {
            long rc = 0;
            if (lo < guard_lo) {
                long sub[6] = { (long)lo, (long)(guard_lo - lo), a[2], a[3], a[4], a[5] };
                rc = DISPATCH(__NR_madvise, sub);
            }
            if (rc == 0 && hi > guard_hi) {
                long sub[6] = { (long)guard_hi, (long)(hi - guard_hi), a[2], a[3], a[4], a[5] };
                rc = DISPATCH(__NR_madvise, sub);
            }
            return rc;
        }
    }
    int named = sys_no == __NR_accept || sys_no == __NR_accept4 ||
        sys_no == __NR_getsockname || sys_no == __NR_getpeername;
    unsigned capacity = named && a[1] && a[2] ? *(unsigned *)a[2] : 0;
    /* Generic userspace character-device proxies (--vdev GUEST:SOCK[:TYPE]). */
    if (vdev_enabled() && vdev_fd_call(sys_no, a, &ret))
        return ret;
    /* Generic userspace virtual network & TUN stack (--net-sock PATH). */
    if (net_stack_enabled() && net_stack_pre_syscall(sys_no, a, &ret))
        return ret;
    /* R6: loop devices are the payload's (before the guarded ioctl policy). */
    if (sys_no == __NR_ioctl && mounts_enabled() && proot_loop_ioctl(a[0], (unsigned long)a[1], a[2], &ret))
        return ret;
    ret = DISPATCH(sys_no, args);
    if (sys_no == __NR_munmap && ret == 0)
        hook_on_munmap((uintptr_t)a[0], (size_t)a[1]);
    /* R6: a directory of the merged view lists every layer. */
    if (sys_no == __NR_getdents64 && union_enabled())
        ret = union_getdents((int)a[0], (void *)a[1], (unsigned long)a[2], ret);
    /* A batch holding only filtered FDs or non-container /proc PIDs is read
     * again: zero means the end of the directory. */
    while (sys_no == __NR_getdents64 && ret > 0) {
        ret = broker_hide_fds((int)a[0], (void *)a[1], ret);
        if (ret > 0)
            ret = proot_proc_filter_pids((int)a[0], (void *)a[1], ret);
        if (ret != 0)
            break;
        long again[6] = {a[0], a[1], a[2], a[3], a[4], a[5]};
        ret = DISPATCH(sys_no, again);
    }
    if (sys_no == __NR_getdents64 && ret > 0)
        owners_fix_getdents((int)a[0], (void *)a[1], ret);
    /* R6: an openat2 lookup may be the kernel's own (RESOLVE_BENEATH, or
     * passed through): a layer image placeholder is filled all the same. */
    if (sys_no == __NR_openat2 && ret >= 0 && union_enabled()) {
        long fill = union_lazy_fd((int)ret);
        if (fill < 0) {
            long close_args[6] = {ret, 0, 0, 0, 0, 0};
            DISPATCH(__NR_close, close_args);
            ret = fill;
        }
    }
    /* Some SELinux-hardened hosts deny getattr/fstat on memfd inodes (-EACCES),
     * breaking virtual /proc files and guest memfds. Identify genuine memfds via
     * F_GET_SEALS and synthesize POSIX stat/statx using lseek(SEEK_END) size. */
    if (ret == -EACCES || (sys_no == __NR_statx && ret == -EFAULT)) {
        int mfd = -1;
        int is_stat = 0, is_statx = 0;
        void *out_buf = NULL;
        if (sys_no == __NR_fstat && a[1]) {
            mfd = (int)a[0];
            is_stat = 1;
            out_buf = (void *)a[1];
        } else if (sys_no == __NR_newfstatat && a[1] && !((const char *)a[1])[0] &&
                   (a[3] & 0x1000 /* AT_EMPTY_PATH */) && a[0] != -100 /* AT_FDCWD */ && a[2]) {
            mfd = (int)a[0];
            is_stat = 1;
            out_buf = (void *)a[2];
        } else if (sys_no == __NR_statx && a[1] && !((const char *)a[1])[0] &&
                   (a[2] & 0x1000 /* AT_EMPTY_PATH */) && a[0] != -100 /* AT_FDCWD */ && a[4]) {
            mfd = (int)a[0];
            is_statx = 1;
            out_buf = (void *)a[4];
        }
        if (mfd >= 0 && raw_syscall(__NR_fcntl, mfd, 1034 /* F_GET_SEALS */, 0, 0, 0, 0) >= 0) {
            long cur = raw_syscall(__NR_lseek, mfd, 0, 1 /* SEEK_CUR */, 0, 0, 0);
            long sz = 0;
            if (cur >= 0) {
                long end = raw_syscall(__NR_lseek, mfd, 0, 2 /* SEEK_END */, 0, 0, 0);
                if (end >= 0) sz = end;
                raw_syscall(__NR_lseek, mfd, cur, 0 /* SEEK_SET */, 0, 0, 0);
            }
            uint64_t ino = 0x4d46440000000000ULL | (uint32_t)mfd;
            uint64_t usz = sz > 0 ? (uint64_t)sz : 0ULL;
            uint64_t blocks = (usz + 511ULL) / 512ULL;
            if (is_stat) {
                unsigned char *sb = (unsigned char *)out_buf;
                memset(sb, 0, 128);
                uint64_t dev = 1;
                uint32_t mode = 0100644; /* S_IFREG | 0644 */
                uint32_t nlink = 1;
                uint32_t blksize = 4096;
                memcpy(sb + 0, &dev, 8);
                memcpy(sb + 8, &ino, 8);
                memcpy(sb + 16, &mode, 4);
                memcpy(sb + 20, &nlink, 4);
                memcpy(sb + 48, &usz, 8);
                memcpy(sb + 56, &blksize, 4);
                memcpy(sb + 64, &blocks, 8);
                ret = 0;
            } else if (is_statx) {
                unsigned char *sx = (unsigned char *)out_buf;
                memset(sx, 0, 256);
                uint32_t mask = 0x07ffu; /* STATX_BASIC_STATS */
                uint32_t blksize = 4096;
                uint32_t nlink = 1;
                uint16_t mode = 0100644;
                uint32_t dmin = 1;
                memcpy(sx + 0, &mask, 4);
                memcpy(sx + 4, &blksize, 4);
                memcpy(sx + 16, &nlink, 4);
                memcpy(sx + 28, &mode, 2);
                memcpy(sx + 32, &ino, 8);
                memcpy(sx + 40, &usz, 8);
                memcpy(sx + 48, &blocks, 8);
                memcpy(sx + 140, &dmin, 4);
                ret = 0;
            }
        }
    }
    if (!ret) {
        fake_ids_stat_owner(sys_no, a);
        if (sys_no == __NR_getsockopt)
            fake_ids_peercred(a);
        owners_stat(sys_no, a); /* R5: recorded owners and modes */
        union_lazy_stat(sys_no, a); /* R6: layer image placeholders */
        /* HarmonyOS hmdfs reports st_dev == 0, breaking POSIX (st_dev, st_ino)
         * deduplication in dynamic linkers and tools. */
        if ((sys_no == __NR_fstat && a[1]) || (sys_no == __NR_newfstatat && a[2])) {
            uint64_t *dev = (uint64_t *)(sys_no == __NR_fstat ? a[1] : a[2]);
            if (*dev == 0)
                *dev = 1;
        } else if (sys_no == __NR_statx && a[4]) {
            uint32_t *dmaj = (uint32_t *)((unsigned char *)a[4] + 136);
            uint32_t *dmin = (uint32_t *)((unsigned char *)a[4] + 140);
            if (*dmaj == 0 && *dmin == 0)
                *dmin = 1;
        }
        /* Virtual filesystem capacity cap (--disk-mb): clamp non-pseudo
         * statfs/fstatfs reports without over-reporting host free space. */
        if (g_payload_config.disk_limit_mb > 0 &&
            (sys_no == __NR_statfs || sys_no == __NR_fstatfs) && a[1]) {
            unsigned char *sf = (unsigned char *)a[1];
            uint64_t f_type = 0, f_bsize = 0, f_blocks = 0, f_bfree = 0, f_bavail = 0, f_frsize = 0;
            memcpy(&f_type, sf + 0, 8);
            if (f_type != 0x9fa0ULL && f_type != 0x62656572ULL && f_type != 0x1cd1ULL &&
                f_type != 0x27e0ebULL && f_type != 0x63677270ULL &&
                f_type != 0x50495045ULL && f_type != 0x534f434bULL) {
                memcpy(&f_bsize, sf + 8, 8);
                memcpy(&f_blocks, sf + 16, 8);
                memcpy(&f_bfree, sf + 24, 8);
                memcpy(&f_bavail, sf + 32, 8);
                memcpy(&f_frsize, sf + 72, 8);
                uint64_t unit = f_frsize ? f_frsize : (f_bsize ? f_bsize : 4096ULL);
                uint64_t cap_blocks = ((uint64_t)g_payload_config.disk_limit_mb * 1024ULL * 1024ULL) / unit;
                if (cap_blocks > 0 && f_blocks > cap_blocks) {
                    uint64_t new_bfree = f_bfree > cap_blocks ? cap_blocks : f_bfree;
                    uint64_t new_bavail = f_bavail > new_bfree ? new_bfree : f_bavail;
                    memcpy(sf + 16, &cap_blocks, 8);
                    memcpy(sf + 24, &new_bfree, 8);
                    memcpy(sf + 32, &new_bavail, 8);
                }
            }
        }
    }
    /* struct utsname: six 65-byte fields; sysname, nodename, release. */
    if (!ret && sys_no == __NR_uname && a[0]) {
        if (g_payload_config.kernel_sysname[0])
            memcpy((char *)a[0], g_payload_config.kernel_sysname, 65);
        if (g_payload_config.hostname[0])
            memcpy((char *)a[0] + 65, g_payload_config.hostname, 65);
        if (g_payload_config.kernel_release[0])
            memcpy((char *)a[0] + 130, g_payload_config.kernel_release, 65);
    }
    if (ret >= 0 && capacity)
        proot_socket_name(sys_no, sys_no == __NR_accept || sys_no == __NR_accept4 ? ret : a[0],
                          (void *)a[1], (unsigned *)a[2], capacity);
    /* Container networks: ports of the container's addresses as the guest
     * bound them (net_view.h). */
    if (ret >= 0 && net_enabled()) {
        if (named && a[1] && a[2])
            net_reverse((void *)a[1], *(unsigned *)a[2] < capacity ? *(unsigned *)a[2] : capacity);
        else if (sys_no == __NR_recvfrom && a[4] && a[5])
            net_reverse((void *)a[4], *(unsigned *)a[5]);
        else if (sys_no == __NR_recvmsg && a[1]) {
            void *msg_name = *(void **)a[1];
            int msg_length = *(int *)((char *)a[1] + 8);
            if (msg_name && msg_length > 0) net_reverse(msg_name, (unsigned)msg_length);
        }
    }
    if (ret >= 0 && net_stack_enabled())
        net_stack_post_syscall(sys_no, a, ret, capacity);
    return ret;
}
