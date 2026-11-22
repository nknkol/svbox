/* SPDX-License-Identifier: MIT */
/* Generic userspace virtual character-device proxy (--vdev GUEST:SOCK[:TYPE]). */
#ifndef SVBOX_VDEV_H
#define SVBOX_VDEV_H

#include <stddef.h>
#include "config.h"

static inline int vdev_enabled(void)
{
    return g_payload_config.vdev_count > 0;
}

/* Returns vdev config index [0..vdev_count-1] if guest path matches, or -1. */
int vdev_match_path(const char *guest_path);

/* Handles openat / newfstatat / statx / faccessat / faccessat2 on a vdev path. */
long vdev_path_call(long number, long a[6], int vdev_idx);

/* Intercepts FD-based syscalls (ioctl, mmap, fstat, close, dup2, dup3) if the
 * target FD belongs to an active vdev. Returns 1 and stores result in *out if
 * handled; returns 0 to let normal dispatch continue. */
int vdev_fd_call(long number, long a[6], long *out);

#endif /* SVBOX_VDEV_H */
