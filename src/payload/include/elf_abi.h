/* SPDX-License-Identifier: MIT */
/* Fixed numbers shared by the loader, the payload and the tests. */
#ifndef ELF_ABI_H
#define ELF_ABI_H

/* Layout of payload_config_t and the stub contract; the loader refuses a
 * payload with another version. */
#define PAYLOAD_ABI_VERSION 31

/* Fixed addresses: the seccomp backstop allows syscalls by address. */
#define LOADER_FIXED_BASE  0x3f00000000ul
#define PAYLOAD_FIXED_BASE 0x3f80000000ul

/* Linux 6.4 prctl, served from the guest's auxv. */
#ifndef PR_GET_AUXV
#define PR_GET_AUXV 0x41555856
#endif
/* Diagnostics of the guarded runtime's FD records ("FDTR"). */
#define PR_ELF_FD_QUERY 0x46445452
/* HarmonyOS: prctl(PR_HM_JIT, 0, 0) lets the next mprotect make anonymous
 * memory executable; prctl(PR_HM_JIT, 0, 1) closes that window again. */
#define PR_HM_JIT 0x6a6974

/* SECCOMP_RET_TRAP data of the backstop filter (si_errno), telling its
 * traps from those of the host sandbox's or guest's own filters. Using 0xffff
 * gives every guest SECCOMP_RET_TRAP | (0..0xfffe) higher seccomp precedence
 * than the backstop filter. */
#define BACKSTOP_TRAP_DATA 0xffff

/* Private prctl queried by loader/backstop.c to distinguish guest-installed
 * SECCOMP_RET_TRAP | 0 filters from host-sandbox traps: bit 0 = data==0,
 * bit 1 = data!=0. */
#define SVBOX_PR_GET_GUEST_SECCOMP_TRAPS 0x53564258

#endif
