/* SPDX-License-Identifier: MIT */
#ifndef PROOT_SCRATCH_H
#define PROOT_SCRATCH_H
#include <stddef.h>
#include <asm/unistd.h>
#include "config.h"
#include "fd_runtime.h"
extern long raw_syscall(long,long,long,long,long,long,long);
static inline long proot_scratch_alloc(size_t size)
{
    if (g_payload_config.guard != GUARD_NONE)
        return fd_runtime_scratch_alloc(size);
    return raw_syscall(__NR_mmap,0,size,3,0x22,-1,0);
}
static inline void proot_scratch_free(void *p,size_t size)
{
    if (g_payload_config.guard != GUARD_NONE) {
        fd_runtime_scratch_free(p,size);
        return;
    }
    raw_syscall(__NR_munmap,(long)p,size,0,0,0,0);
}
#endif
