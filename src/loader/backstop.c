/* SPDX-License-Identifier: MIT */
#include <asm/unistd.h>
#include <ucontext.h>
#include "loader.h"
#include "elf_abi.h"

/* --seccomp-backstop: a seccomp filter traps every syscall that does not
 * come from the loader image or the payload (both at fixed addresses, so
 * the filter, which survives exec, stays valid in every descendant). The
 * SIGSYS handler forwards the trapped call into the payload exactly as a
 * stub would, so unhooked svc (JIT code, unreachable sites, the vDSO
 * fallback) still gets guest semantics. rt_sigreturn, exit, exit_group,
 * restart_syscall and clone are allowed by number: they take no paths and
 * clone cannot run inside a signal handler. */
static unsigned long g_payload_entry;
static int g_trap_host_sigsys;
extern char __ehdr_start[], _end[];

static long backstop_call(unsigned long entry, const unsigned long *r)
{
	register long x0 __asm__("x0") = (long)r[0];
	register long x1 __asm__("x1") = (long)r[1], x2 __asm__("x2") = (long)r[2];
	register long x3 __asm__("x3") = (long)r[3], x4 __asm__("x4") = (long)r[4];
	register long x5 __asm__("x5") = (long)r[5];
	register long x8 __asm__("x8") = (long)(unsigned)r[8]; /* The kernel's int. */
	register unsigned long x17 __asm__("x17") = entry;
	/* The payload entry restores every register except x0 (and the x16,
	 * x17 and x30 a stub saves itself). */
	__asm__ volatile("blr x17"
			 : "+r"(x0), "+r"(x8), "+r"(x17)
			 : "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
			 : "x16", "x30", "memory", "cc");
	return x0;
}

static void forward_guest_sigsys(int sig, siginfo_t *si, void *ucontext)
{
	struct {
		unsigned long handler;
		unsigned long flags;
		unsigned long restorer;
		unsigned long mask;
	} gact = {0, 0, 0, 0};
	unsigned long qregs[9] = {31 /* SIGSYS */, 0, (unsigned long)&gact, 8, 0, 0, 0, 0, __NR_rt_sigaction};
	if (g_payload_entry && backstop_call(g_payload_entry, qregs) == 0) {
		if (gact.handler == 1ul /* SIG_IGN */)
			return;
		if (gact.handler > 1ul) {
			if (gact.flags & 0x80000000ul /* SA_RESETHAND */) {
				struct {
					unsigned long handler, flags, restorer, mask;
				} dfl = {0, 0, 0, 0};
				unsigned long rregs[9] = {31, (unsigned long)&dfl, 0, 8, 0, 0, 0, 0, __NR_rt_sigaction};
				backstop_call(g_payload_entry, rregs);
			}
			if (gact.flags & 0x00000004ul /* SA_SIGINFO */)
				((void (*)(int, siginfo_t *, void *))gact.handler)(sig, si, ucontext);
			else
				((void (*)(int))gact.handler)(sig);
			return;
		}
	}
	die_of_signal(sig);
}

static void loader_sigsys_handler(int sig, siginfo_t *si, void *ucontext)
{
	ucontext_t *uc = (ucontext_t *)ucontext;
	/* Our TRAP action's data comes in si_errno: the host sandbox's own
	 * filter traps some calls too. Non-SYS_SECCOMP SIGSYS (e.g. raised by
	 * the guest via kill/tgkill) is forwarded to the guest's SIGSYS action. */
	if (!si || si->si_code != 1 /* SYS_SECCOMP */ || !uc) {
		forward_guest_sigsys(sig, si, ucontext);
		return;
	}
	unsigned long *regs = (unsigned long *)uc->uc_mcontext.regs;
	if (si->si_errno == BACKSTOP_TRAP_DATA) {
		unsigned long nr = (unsigned)regs[8];
		long ret = backstop_call(g_payload_entry, regs);
		regs[0] = (unsigned long)ret;
		/* rt_sigreturn restores current->blocked from uc->uc_sigmask,
		 * which would otherwise undo any rt_sigprocmask executed here. */
		if (nr == __NR_rt_sigprocmask && ret == 0 && regs[1] != 0) {
			unsigned long cur_mask = 0;
			if (z_syscall(__NR_rt_sigprocmask, 0, 0, (long)&cur_mask, 8) == 0) {
				cur_mask &= ~(1ul << (31 - 1)); /* keep SIGSYS unblocked */
				*(unsigned long *)&uc->uc_sigmask = cur_mask;
			}
		}
		return;
	}
	if (g_trap_host_sigsys) {
		regs[0] = (unsigned long)-38L; /* -ENOSYS */
		return;
	}
	die_of_signal(sig);
}

static int backstop_filter(int fast_io)
{
	unsigned long ranges[2][2] = {{(unsigned long)__ehdr_start, (unsigned long)_end},
				      {g_payload_lo, g_payload_hi}};
	struct { unsigned short code; unsigned char jt, jf; unsigned int k; } f[128];
	int n = 0;
#define BPF(c, t, e, v) (f[n++] = (typeof(f[0])){(c), (t), (e), (v)})
	/* seccomp_data: nr at 0, arch at 4, instruction_pointer at 8.
	 * Fast-path pure passthrough syscalls directly in BPF so unpatched
	 * libraries avoid SIGSYS trap overhead on hot sync/time/poll/I/O paths,
	 * and return -ENOSYS directly for rseq/clone3 so libc falls back cleanly. */
	BPF(0x20, 0, 0, 0); /* ld nr */
	static const unsigned enosys_nrs[] = {
		293, /* rseq */
		435, /* clone3 */
	};
	int enosys_start = n;
	for (unsigned i = 0; i < sizeof(enosys_nrs) / sizeof(enosys_nrs[0]); i++)
		BPF(0x15, 0, 0, enosys_nrs[i]); /* jeq -> enosys (patched below) */
	int enosys_end = n;

	static const unsigned allowed[] = {
		139, /* rt_sigreturn */
		93,  /* exit */
		94,  /* exit_group */
		128, /* restart_syscall */
		220, /* clone */
		98,  /* futex */
		101, /* nanosleep */
		113, /* clock_gettime */
		114, /* clock_getres */
		115, /* clock_nanosleep */
		120, /* sched_getparam */
		121, /* sched_getscheduler */
		124, /* sched_yield */
		130, /* tkill */
		131, /* tgkill */
		132, /* sigaltstack */
		133, /* rt_sigsuspend */
		136, /* rt_sigpending */
		137, /* rt_sigtimedwait */
		140, /* setpriority */
		141, /* getpriority */
		165, /* getrusage */
		169, /* gettimeofday */
		172, /* getpid */
		173, /* getppid */
		178, /* gettid */
		21,  /* epoll_ctl */
		22,  /* epoll_pwait */
		73,  /* ppoll */
		95,  /* waitid */
		214, /* brk */
		260, /* wait4 */
	};
	static const unsigned io_allowed[] = {
		62,  /* lseek */
		63,  /* read */
		64,  /* write */
		65,  /* readv */
		66,  /* writev */
		67,  /* pread64 */
		68,  /* pwrite64 */
	};
	int allow_start = n;
	for (unsigned i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++)
		BPF(0x15, 0, 0, allowed[i]); /* jeq -> allow (patched below) */
	if (fast_io) {
		for (unsigned i = 0; i < sizeof(io_allowed) / sizeof(io_allowed[0]); i++)
			BPF(0x15, 0, 0, io_allowed[i]); /* jeq -> allow (patched below) */
	}
	int allow_end = n;

	for (int r = 0; r < 2; r++) {
		if ((ranges[r][0] >> 32) != ((ranges[r][1] - 1) >> 32))
			return -1; /* A range across a 4 GiB boundary: unsupported. */
		BPF(0x20, 0, 0, 12);                                /* ld ip high */
		BPF(0x15, 0, 4, (unsigned)(ranges[r][0] >> 32));    /* jeq hi */
		BPF(0x20, 0, 0, 8);                                 /* ld ip low */
		BPF(0x35, 0, 2, (unsigned)ranges[r][0]);            /* jge lo */
		BPF(0x35, 1, 0, (unsigned)ranges[r][1]);            /* jge hi -> next */
		BPF(0x06, 0, 0, 0x7fff0000u);                       /* ret ALLOW */
	}
	BPF(0x06, 0, 0, 0x00030000u | BACKSTOP_TRAP_DATA);          /* ret TRAP */
	int allow_idx = n;
	BPF(0x06, 0, 0, 0x7fff0000u);                               /* ret ALLOW */
	int enosys_idx = n;
	BPF(0x06, 0, 0, 0x00050000u | 38u);                         /* ret ERRNO(ENOSYS) */
	for (int i = enosys_start; i < enosys_end; i++)
		f[i].jt = (unsigned char)(enosys_idx - i - 1);
	for (int i = allow_start; i < allow_end; i++)
		f[i].jt = (unsigned char)(allow_idx - i - 1);
#undef BPF
	struct { unsigned short len; void *filter; } prog = {(unsigned short)n, f};
	if (z_syscall(__NR_prctl, 38 /* PR_SET_NO_NEW_PRIVS */, 1, 0, 0, 0) < 0)
		return -1;
	return z_syscall(__NR_seccomp, 1 /* SECCOMP_SET_MODE_FILTER */, 0, &prog) < 0 ? -1 : 0;
}

/* The filter survives exec, so only the initial loader installs it; every
 * loader installs the handler. */
void backstop_install(unsigned long payload_entry, int with_filter,
		      int trap_host_sigsys, int fast_io)
{
	g_payload_entry = payload_entry;
	g_trap_host_sigsys = trap_host_sigsys;
	if (g_payload_lo != PAYLOAD_FIXED_BASE)
		z_errx(1, "seccomp backstop: payload not at its fixed address");
	/* NODEFER + explicit SA_RESTORER: a guest handler run from here may
	 * itself trap, and rt_sigreturn runs from our loader's allowed range. */
	if (sigsys_install_handler(loader_sigsys_handler) < 0)
		z_errx(1, "seccomp backstop: cannot install SIGSYS handler");
	if (with_filter && backstop_filter(fast_io) < 0)
		z_errx(1, "seccomp backstop: cannot install the filter");
}

