/* SPDX-License-Identifier: MIT */
#include <asm/unistd.h>
#include "elf_abi.h"
#include "platform.h"

extern long raw_syscall(long number, long a1, long a2, long a3, long a4, long a5, long a6);

int platform_is_harmonyos(void)
{
    static int cached = -1;
    if (cached < 0) {
        char u[6][65];
        static const char name1[] = "HarmonyOS";
        static const char name2[] = "HongMeng";
        cached = 0;
        if (raw_syscall(__NR_uname, (long)u, 0, 0, 0, 0, 0) >= 0) {
            size_t i = 0;
            while (i < sizeof(name1) && u[0][i] == name1[i]) i++;
            if (i == sizeof(name1)) {
                cached = 1;
            } else {
                i = 0;
                while (i < sizeof(name2) - 1 && u[0][i] == name2[i]) i++;
                cached = (i == sizeof(name2) - 1);
            }
        }
    }
    return cached;
}

long platform_mprotect_exec(unsigned long addr, size_t len, int prot)
{
    int jit = (prot & 4 /* PROT_EXEC */) && platform_is_harmonyos();
    long rc = -1;
    for (int attempt = 0; attempt < (jit ? 32 : 1); attempt++) {
        if (jit) raw_syscall(__NR_prctl, PR_HM_JIT, 0, 0, 0, 0, 0);
        rc = raw_syscall(__NR_mprotect, (long)addr, (long)len, prot, 0, 0, 0);
        if (jit) raw_syscall(__NR_prctl, PR_HM_JIT, 0, 1, 0, 0, 0);
        if (rc >= 0) break;
        if (jit) raw_syscall(__NR_sched_yield, 0, 0, 0, 0, 0, 0);
    }
    return rc;
}
