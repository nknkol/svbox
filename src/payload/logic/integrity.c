/* SPDX-License-Identifier: MIT */
#include <asm/unistd.h>
#include <errno.h>
#include <string.h>
#include "config.h"
#include "hook_runtime.h"
#include "host_syscall.h"
#include "integrity.h"

#define MAP_FIXED              0x10
#define MAP_FIXED_NOREPLACE    0x100000
#define MREMAP_FIXED           2
#define SIGSYS                 31

/* madvise advice that discards or replaces contents. */
static int destructive_advice(int advice)
{
    switch (advice) {
    case 4:  /* MADV_DONTNEED */
    case 8:  /* MADV_FREE */
    case 9:  /* MADV_REMOVE */
    case 10: /* MADV_DONTFORK */
    case 18: /* MADV_WIPEONFORK */
        return 1;
    default:
        return 0;
    }
}

static int touches_protected(long number, const long a[6])
{
    switch (number) {
    case __NR_munmap: case __NR_mprotect: case __NR_pkey_mprotect:
        break;
    case __NR_mremap:
        if ((a[3] & MREMAP_FIXED) && hook_protected_overlap((uintptr_t)a[4], (size_t)a[2]))
            return 1;
        break;
    case __NR_mmap:
        if (!(a[3] & MAP_FIXED) || (a[3] & MAP_FIXED_NOREPLACE))
            return 0;
        break;
    case __NR_madvise:
        if (!destructive_advice((int)a[2]))
            return 0;
        break;
    default:
        return 0;
    }
    return hook_protected_overlap((uintptr_t)a[0], (size_t)a[1]);
}

/* A guest SIGSYS action is recorded and reported back, never installed in the
 * host kernel; backstop.c queries this slot to forward non-SYS_SECCOMP SIGSYS
 * (e.g. guest raise/kill/tgkill) with POSIX semantics. */
static unsigned char guest_sigsys[32];
int integrity_guest_sigsys_state(void)
{
    unsigned long h = 0;
    memcpy(&h, guest_sigsys, sizeof(h));
    if (h == 0) return 0;
    if (h == 1) return 1;
    return 2;
}

static long sigsys_action(const long a[6])
{
    if (a[3] != 8)
        return -EINVAL;
    unsigned char previous[32];
    memcpy(previous, guest_sigsys, sizeof(previous));
    if (a[1]) memcpy(guest_sigsys, (const void *)a[1], sizeof(guest_sigsys));
    if (a[2]) memcpy((void *)a[2], previous, sizeof(previous));
    return 0;
}

/* Wrap guest async signal handlers (installed without SA_ONSTACK) with
 * payload_sig_trampoline so that if a signal arrives while a thread is running
 * an intercepted syscall on svbox's payload_stack, the handler executes on the
 * thread's real guest stack (critical for conservative stack-scanning GCs such
 * as Boehm GC / Mono / Unity IL2CPP). */
#define SA_SIGINFO_   0x00000004ul
#define SA_ONSTACK_   0x08000000ul
#define SA_RESETHAND_ 0x80000000ul

struct k_sigaction_rec {
    unsigned long sa_handler;
    unsigned long sa_flags;
    unsigned long sa_restorer;
    unsigned long sa_mask;
};

extern void payload_sig_trampoline(int sig, void *info, void *uctx);

static struct k_sigaction_rec g_guest_sigact[65];
static unsigned char g_sig_wrapped[65];

static int is_sync_fault_sig(int sig)
{
    switch (sig) {
    case 4:  /* SIGILL */
    case 5:  /* SIGTRAP */
    case 6:  /* SIGABRT */
    case 7:  /* SIGBUS */
    case 8:  /* SIGFPE */
    case 9:  /* SIGKILL */
    case 11: /* SIGSEGV */
    case 19: /* SIGSTOP */
    case 31: /* SIGSYS */
        return 1;
    default:
        return 0;
    }
}

unsigned long integrity_get_sig_handler(int sig)
{
    if (sig < 1 || sig > 64)
        return 0;
    unsigned long fn = __atomic_load_n(&g_guest_sigact[sig].sa_handler, __ATOMIC_ACQUIRE);
    unsigned long fl = __atomic_load_n(&g_guest_sigact[sig].sa_flags, __ATOMIC_RELAXED);
    if (fl & SA_RESETHAND_)
        __atomic_store_n(&g_sig_wrapped[sig], 0, __ATOMIC_RELEASE);
    return fn;
}

static long wrapped_sigaction(const long a[6])
{
    int sig = (int)a[0];
    if (a[3] != 8 || sig < 1 || sig > 64)
        return raw_syscall(__NR_rt_sigaction, a[0], a[1], a[2], a[3], 0, 0);

    struct k_sigaction_rec prev_guest;
    unsigned char was_wrapped = __atomic_load_n(&g_sig_wrapped[sig], __ATOMIC_ACQUIRE);
    if (was_wrapped)
        memcpy(&prev_guest, &g_guest_sigact[sig], sizeof(prev_guest));

    struct k_sigaction_rec host_old;
    memset(&host_old, 0, sizeof(host_old));
    long rc;
    if (a[1]) {
        struct k_sigaction_rec new_act;
        memcpy(&new_act, (const void *)a[1], sizeof(new_act));
        if (g_payload_config.seccomp_backstop || g_payload_config.trap_sigsys)
            new_act.sa_mask &= ~(1ul << (SIGSYS - 1));
        int want_wrap = (new_act.sa_handler > 1ul && !(new_act.sa_flags & SA_ONSTACK_));
        if (want_wrap) {
            /* Publish handler before installing trampoline so a concurrent
             * signal immediately sees a valid target. */
            memcpy(&g_guest_sigact[sig], &new_act, sizeof(new_act));
            __atomic_store_n(&g_sig_wrapped[sig], 1, __ATOMIC_RELEASE);
            struct k_sigaction_rec wrap = new_act;
            wrap.sa_handler = (unsigned long)(uintptr_t)&payload_sig_trampoline;
            wrap.sa_flags |= SA_SIGINFO_;
            rc = raw_syscall(__NR_rt_sigaction, sig, (long)&wrap, (long)&host_old, 8, 0, 0);
            if (rc < 0)
                __atomic_store_n(&g_sig_wrapped[sig], was_wrapped, __ATOMIC_RELEASE);
        } else {
            rc = raw_syscall(__NR_rt_sigaction, sig, (long)&new_act, (long)&host_old, 8, 0, 0);
            if (rc == 0)
                __atomic_store_n(&g_sig_wrapped[sig], 0, __ATOMIC_RELEASE);
        }
    } else {
        rc = raw_syscall(__NR_rt_sigaction, sig, 0, (long)&host_old, 8, 0, 0);
    }

    if (rc == 0 && a[2]) {
        if (was_wrapped && host_old.sa_handler == (unsigned long)(uintptr_t)&payload_sig_trampoline)
            memcpy((void *)a[2], &prev_guest, sizeof(prev_guest));
        else
            memcpy((void *)a[2], &host_old, sizeof(host_old));
    }
    return rc;
}

int integrity_check(long number, const long a[6], long *result)
{
    if (touches_protected(number, a)) {
        *result = -EPERM;
        return 1;
    }
    if (broker_fd_guard(number, a, result))
        return 1;
    if ((g_payload_config.seccomp_backstop || g_payload_config.trap_sigsys) &&
        number == __NR_rt_sigaction && (int)a[0] == SIGSYS) {
        *result = sigsys_action(a);
        return 1;
    }
    if (number == __NR_rt_sigaction && !is_sync_fault_sig((int)a[0])) {
        *result = wrapped_sigaction(a);
        return 1;
    }
    if ((g_payload_config.seccomp_backstop || g_payload_config.trap_sigsys) &&
        number == __NR_rt_sigaction && a[1] && a[3] == 8) {
        struct k_sigaction_rec na;
        memcpy(&na, (const void *)a[1], sizeof(na));
        unsigned long sigsys_bit = 1ul << (SIGSYS - 1);
        if (na.sa_mask & sigsys_bit) {
            na.sa_mask &= ~sigsys_bit;
            *result = raw_syscall(__NR_rt_sigaction, a[0], (long)&na, a[2], a[3], 0, 0);
            return 1;
        }
    }
    if ((g_payload_config.seccomp_backstop || g_payload_config.trap_sigsys) &&
        number == __NR_rt_sigprocmask && a[1] && a[3] == 8 &&
        (a[0] == 0 /* SIG_BLOCK */ || a[0] == 2 /* SIG_SETMASK */)) {
        unsigned long set = 0;
        memcpy(&set, (const void *)a[1], sizeof(set));
        unsigned long sigsys_bit = 1ul << (SIGSYS - 1);
        if (set & sigsys_bit) {
            set &= ~sigsys_bit;
            *result = raw_syscall(__NR_rt_sigprocmask, a[0], (long)&set, a[2], a[3], 0, 0);
            return 1;
        }
    }
    return 0;
}
