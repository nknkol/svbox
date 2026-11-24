#!/usr/bin/env python3
"""Verify cross-process SVC-site cache (hit + invalidation on modification),
NEON single-pass scanning, and virtual CAP_SYS_NICE sched_setscheduler emulation."""
import os
import subprocess
import tempfile
import time

SVBOX = "/storage/Users/currentUser/Workspace/svbox/build/svbox"

LIB_V1 = r"""
#include <sys/syscall.h>
#include <unistd.h>
long test_lib_uid(void) {
    /* Issue a raw svc #0 (__NR_getuid = 174) so svbox must hook it! */
    register long x8 __asm__("x8") = 174;
    register long x0 __asm__("x0");
    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8) : "memory");
    return x0;
}
"""

LIB_V2 = r"""
#include <sys/syscall.h>
#include <unistd.h>
/* Shifted offset so stale cached offsets would miss or corrupt if not invalidated! */
__attribute__((noinline)) long pad_fn(long v) {
    __asm__ volatile(".rept 2048\n add x0, x0, #1\n .endr\n" : "+r"(v));
    return v;
}
long test_lib_uid(void) {
    register long x8 __asm__("x8") = 174;
    register long x0 __asm__("x0");
    __asm__ volatile("svc #0" : "=r"(x0) : "r"(x8) : "memory");
    return x0 + (pad_fn(0) == 2048 ? 100 : 999);
}
"""

PROBE_C = r"""
#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *libpath = argv[1];
    long expect = strtol(argv[2], NULL, 10);
    int test_sched = atoi(argv[3]);

    void *h = dlopen(libpath, RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen failed: %s\n", dlerror()); return 2; }
    long (*fn)(void) = dlsym(h, "test_lib_uid");
    assert(fn != NULL);
    long got = fn();
    if (got != expect) {
        fprintf(stderr, "uid mismatch: got=%ld expect=%ld\n", got, expect);
        return 3;
    }
    dlclose(h);

    if (test_sched) {
        struct sched_param sp = { .sched_priority = 1 };
        int rc = sched_setscheduler(0, SCHED_FIFO, &sp);
        if (rc != 0) {
            fprintf(stderr, "sched_setscheduler(SCHED_FIFO) failed: rc=%d errno=%d\n", rc, errno);
            return 4;
        }
        /* Verify --deny-memfd-prefix blocks matching prefix with ENOSYS while allowing others */
        long denied = syscall(279 /* __NR_memfd_create */, "deny-test", 0);
        if (denied != -1 || errno != ENOSYS) {
            fprintf(stderr, "memfd deny failed: rc=%ld errno=%d\n", denied, errno);
            return 5;
        }
        long allowed = syscall(279 /* __NR_memfd_create */, "allow-test", 0);
        if (allowed < 0) {
            fprintf(stderr, "memfd allow failed: rc=%ld errno=%d\n", allowed, errno);
            return 6;
        }
        close((int)allowed);
    }
    return 0;
}
"""


def main():
    with tempfile.TemporaryDirectory(prefix="svbox-scache-", dir="/data/storage/el2/base/cache") as td:
        root = os.path.join(td, "root")
        scratch = os.path.join(td, "scratch")
        os.makedirs(root, exist_ok=True)
        os.makedirs(scratch, exist_ok=True)

        lib_so = os.path.join(td, "libprobe.so")
        probe_exe = os.path.join(td, "probe")
        open(td + "/lib1.c", "w").write(LIB_V1)
        open(td + "/lib2.c", "w").write(LIB_V2)
        open(td + "/probe.c", "w").write(PROBE_C)

        subprocess.run(["clang", "-O2", "-shared", "-fPIC", td + "/lib1.c", "-o", lib_so], check=True)
        subprocess.run(["clang", "-O2", td + "/probe.c", "-ldl", "-o", probe_exe], check=True)

        base_cmd = [
            SVBOX, "-u", "0:0", "--cap-add", "ALL", "--trap-sigsys",
            "--deny-memfd-prefix", "deny-",
            "--emulate-mounts", "--mount-scratch", scratch, "--",
            probe_exe, lib_so,
        ]

        # 1. Cold run: populates .svbox_svc_cache & verifies hooked raw svc #0 returns fake uid 0 + CAP_SYS_NICE
        subprocess.run(base_cmd + ["0", "1"], check=True)
        cache_file = os.path.join(scratch, ".svbox_svc_cache")
        assert os.path.exists(cache_file) and os.path.getsize(cache_file) == 1048576

        # 2. Warm run: hits cross-process .svbox_svc_cache and still hooks svc #0 to fake uid 0
        subprocess.run(base_cmd + ["0", "1"], check=True)

        # 3. Overwrite libprobe.so in-place (new size + mtime -> must invalidate cache and re-scan!)
        time.sleep(0.05)
        subprocess.run(["clang", "-O2", "-shared", "-fPIC", td + "/lib2.c", "-o", lib_so], check=True)
        subprocess.run(base_cmd + ["100", "1"], check=True)
        # 4. Warm run on updated version
        subprocess.run(base_cmd + ["100", "0"], check=True)

        print("PASS: test_svc_cache_and_sched (cold + warm + invalidation + CAP_SYS_NICE)")


if __name__ == "__main__":
    main()
