#!/usr/bin/env python3
"""Stub-island resilience & fallback tests:
1. 5,000 JIT mmap/mprotect(RX)/call/munmap cycles (verifies Shared Region Pool
   reclamation never exhausts PROTECTED_MAX=4096).
2. Tight 64 KiB VA gap inside crowded ±128 MiB neighborhood (verifies fine scan).
3. Zero unmapped space within ±128 MiB under --seccomp-backstop (verifies 100%
   SIGSYS fallback executes intercepted guest syscalls without -ENOMEM)."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

PROBE_C = r"""
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Emit: mov w8, #174 (__NR_getuid); svc #0; ret */
static void emit_getuid(uint32_t *p) {
    p[0] = 0x528015c8u; /* mov w8, #174 */
    p[1] = 0xd4000001u; /* svc #0 */
    p[2] = 0xd65f03c0u; /* ret */
    __builtin___clear_cache((char *)p, (char *)(p + 3));
}

int main(int argc, char **argv) {
    int mode = argc > 1 ? atoi(argv[1]) : 0;

    if (mode == 0) {
        /* 1. 5,000 JIT cycles (> PROTECTED_MAX=4096) */
        for (int i = 0; i < 5000; i++) {
            uint32_t *p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (p == MAP_FAILED) {
                fprintf(stderr, "jit mmap failed at %d errno=%d\n", i, errno);
                return 1;
            }
            emit_getuid(p);
            if (mprotect(p, 4096, PROT_READ | PROT_EXEC) != 0) {
                fprintf(stderr, "jit mprotect failed at %d errno=%d\n", i, errno);
                return 2;
            }
            long (*fn)(void) = (long (*)(void))p;
            long uid = fn();
            if (uid != 1234) {
                fprintf(stderr, "jit uid=%ld want 1234 at %d\n", uid, i);
                return 3;
            }
            munmap(p, 4096);
        }
        printf("POOL_5000_OK\n");
        return 0;
    }

    if (mode == 1) {
        /* 2. Completely surround a 4 KiB code page with 132 MiB PROT_NONE slabs
         * on BOTH sides (total 264 MiB + 4 KiB): ZERO unmapped bytes within ±128 MiB! */
        size_t side = 132ul << 20;
        size_t total = side + 4096 + side;
        unsigned char *arena = mmap(NULL, total, PROT_NONE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (arena == MAP_FAILED) {
            perror("arena mmap");
            return 10;
        }
        uint32_t *code = (uint32_t *)(arena + side);
        if (mprotect(code, 4096, PROT_READ | PROT_WRITE) != 0) {
            perror("code rw");
            return 11;
        }
        emit_getuid(code);
        int rc = mprotect(code, 4096, PROT_READ | PROT_EXEC);
        if (rc != 0) {
            fprintf(stderr, "packed mprotect RX failed rc=%d errno=%d\n", rc, errno);
            return 12;
        }
        long (*fn)(void) = (long (*)(void))code;
        long uid = fn();
        if (uid != 1234) {
            fprintf(stderr, "packed uid=%ld want 1234\n", uid);
            return 13;
        }
        munmap(arena, total);
        printf("PACKED_FALLBACK_OK\n");
        return 0;
    }

    if (mode == 2) {
        /* 3. Packed ±128 MiB EXCEPT a single 64 KiB hole at +64 KiB (invisible to 1 MiB coarse stride!). */
        size_t side = 132ul << 20;
        size_t total = side + 4096 + side;
        unsigned char *arena = mmap(NULL, total, PROT_NONE,
                                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (arena == MAP_FAILED) {
            perror("arena2 mmap");
            return 20;
        }
        /* Punch a 64 KiB hole at offset +64 KiB after code page (between 0 and 1 MiB) */
        unsigned char *code_addr = arena + side;
        munmap(code_addr + 65536, 65536);
        uint32_t *code = (uint32_t *)code_addr;
        if (mprotect(code, 4096, PROT_READ | PROT_WRITE) != 0) return 21;
        emit_getuid(code);
        if (mprotect(code, 4096, PROT_READ | PROT_EXEC) != 0) {
            fprintf(stderr, "fine-gap mprotect failed errno=%d\n", errno);
            return 22;
        }
        long (*fn)(void) = (long (*)(void))code;
        long uid = fn();
        if (uid != 1234) {
            fprintf(stderr, "fine-gap uid=%ld want 1234\n", uid);
            return 23;
        }
        munmap(arena, side + 65536);
        munmap(code_addr + 131072, side - 131072 + 4096);
        printf("FINE_GAP_OK\n");
        return 0;
    }

    return 99;
}
"""


def main():
    with tempfile.TemporaryDirectory(prefix="island-fb-", dir=lib.BUILD) as td:
        src = Path(td) / "probe.c"
        exe = Path(td) / "probe"
        src.write_text(PROBE_C)
        subprocess.run(["clang", "-O2", "-static", str(src), "-o", str(exe)], check=True)

        # 1. 5,000 JIT cycles (no backstop needed — pool reclaims pages!)
        p1 = subprocess.run([str(lib.loader()), "-u", "1234:1234", "--", str(exe), "0"],
                            capture_output=True, text=True, timeout=30)
        assert p1.returncode == 0 and "POOL_5000_OK" in p1.stdout, (p1.returncode, p1.stdout, p1.stderr)

        # 2. Fine 64 KiB gap inside packed ±128 MiB (no backstop needed — fine search finds it!)
        p2 = subprocess.run([str(lib.loader()), "-u", "1234:1234", "--", str(exe), "2"],
                            capture_output=True, text=True, timeout=30)
        assert p2.returncode == 0 and "FINE_GAP_OK" in p2.stdout, (p2.returncode, p2.stdout, p2.stderr)

        # 3. Zero gap in ±128 MiB WITH --seccomp-backstop -> 100% SIGSYS fallback succeeds!
        p3 = subprocess.run([str(lib.loader()), "--seccomp-backstop", "-u", "1234:1234", "--", str(exe), "1"],
                            capture_output=True, text=True, timeout=30)
        assert p3.returncode == 0 and "PACKED_FALLBACK_OK" in p3.stdout, (p3.returncode, p3.stdout, p3.stderr)

        # 4. Zero gap in ±128 MiB WITHOUT --seccomp-backstop -> still fails closed (-ENOMEM)!
        p4 = subprocess.run([str(lib.loader()), "-u", "1234:1234", "--", str(exe), "1"],
                            capture_output=True, text=True, timeout=30)
        assert p4.returncode != 0 and "errno=12" in p4.stderr, (p4.returncode, p4.stdout, p4.stderr)

        print("PASS: stub islands (5000 JIT pool cycles, 64KiB fine-gap scan, 100% --seccomp-backstop fallback, fail-closed without backstop)")


if __name__ == "__main__":
    main()
