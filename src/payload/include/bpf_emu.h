/* SPDX-License-Identifier: MIT */
#ifndef SVBOX_BPF_EMU_H
#define SVBOX_BPF_EMU_H

/* Generic userspace Linux bpf(2) map & object emulation (--emulate-bpf).
 * Provides standard in-memory BPF map/object operations (MAP_CREATE, OBJ_PIN,
 * OBJ_GET, OBJ_GET_INFO_BY_FD, MAP_LOOKUP_ELEM, MAP_UPDATE_ELEM,
 * MAP_DELETE_ELEM, MAP_GET_NEXT_KEY, PROG_ATTACH, PROG_DETACH) when the host
 * kernel forbids or lacks bpf(2).
 *
 * Returns 1 with *result when the syscall was handled, 0 to continue dispatch. */
int bpf_emu_syscall(long number, long a[6], long *result);

#endif /* SVBOX_BPF_EMU_H */
