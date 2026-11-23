#!/usr/bin/env python3
"""Verify generic userspace Linux bpf(2) emulation (--emulate-bpf) and O_PATH fchmodat."""
import os
import subprocess
import tempfile

SVBOX = "/storage/Users/currentUser/Workspace/svbox/build/svbox"

C_SRC = r"""
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

struct bpf_map_info {
    uint32_t type, id, key_size, value_size, max_entries, map_flags;
    char name[16];
    uint32_t pad[10];
};

static long sys_bpf(int cmd, void *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}

int main(void) {
    /* 1. Test BPF_OBJ_GET on a metadata-backed ARRAY map */
    struct { uint64_t pathname; uint32_t bpf_fd; uint32_t file_flags; } gattr;
    memset(&gattr, 0, sizeof(gattr));
    gattr.pathname = (uint64_t)(uintptr_t)"/bpffs/cfg_map";
    long fd = sys_bpf(7 /* BPF_OBJ_GET */, &gattr, sizeof(gattr));
    assert(fd >= 0);

    struct bpf_map_info info;
    memset(&info, 0, sizeof(info));
    struct { uint32_t bpf_fd; uint32_t info_len; uint64_t info; } iattr = {
        (uint32_t)fd, sizeof(info), (uint64_t)(uintptr_t)&info
    };
    assert(sys_bpf(15 /* BPF_OBJ_GET_INFO_BY_FD */, &iattr, sizeof(iattr)) == 0);
    assert(info.type == 2 && info.key_size == 4 && info.value_size == 4 && info.max_entries == 2);

    /* ARRAY lookup default 0, update, re-lookup, get_next_key */
    uint32_t k = 0, v = 0xdeadbeef, nk = 99;
    struct { uint32_t map_fd; uint32_t pad; uint64_t key; uint64_t val; uint64_t flags; } mop;
    memset(&mop, 0, sizeof(mop));
    mop.map_fd = (uint32_t)fd; mop.key = (uint64_t)(uintptr_t)&k; mop.val = (uint64_t)(uintptr_t)&v;
    assert(sys_bpf(1 /* LOOKUP */, &mop, sizeof(mop)) == 0 && v == 0);
    v = 42;
    assert(sys_bpf(2 /* UPDATE */, &mop, sizeof(mop)) == 0);
    v = 0;
    assert(sys_bpf(1 /* LOOKUP */, &mop, sizeof(mop)) == 0 && v == 42);
    mop.key = 0; mop.val = (uint64_t)(uintptr_t)&nk;
    assert(sys_bpf(4 /* GET_NEXT_KEY */, &mop, sizeof(mop)) == 0 && nk == 0);
    mop.key = (uint64_t)(uintptr_t)&k;
    assert(sys_bpf(4 /* GET_NEXT_KEY */, &mop, sizeof(mop)) == 0 && nk == 1);
    k = 1;
    assert(sys_bpf(4 /* GET_NEXT_KEY */, &mop, sizeof(mop)) < 0 && errno == ENOENT);
    close((int)fd);

    /* 2. Test HASH map via metadata file */
    gattr.pathname = (uint64_t)(uintptr_t)"/bpffs/hash_map";
    long hfd = sys_bpf(7, &gattr, sizeof(gattr));
    assert(hfd >= 0);
    uint64_t hk1 = 1001, hv1 = 0x1122334455667788ULL, hv_out = 0;
    memset(&mop, 0, sizeof(mop));
    mop.map_fd = (uint32_t)hfd; mop.key = (uint64_t)(uintptr_t)&hk1; mop.val = (uint64_t)(uintptr_t)&hv_out;
    assert(sys_bpf(1, &mop, sizeof(mop)) < 0 && errno == ENOENT);
    mop.val = (uint64_t)(uintptr_t)&hv1; mop.flags = 1 /* BPF_NOEXIST */;
    assert(sys_bpf(2, &mop, sizeof(mop)) == 0);
    assert(sys_bpf(2, &mop, sizeof(mop)) < 0 && errno == EEXIST);
    mop.val = (uint64_t)(uintptr_t)&hv_out; mop.flags = 0;
    assert(sys_bpf(1, &mop, sizeof(mop)) == 0 && hv_out == hv1);
    assert(sys_bpf(3 /* DELETE */, &mop, sizeof(mop)) == 0);
    assert(sys_bpf(1, &mop, sizeof(mop)) < 0 && errno == ENOENT);
    close((int)hfd);

    /* 3. Non-existent path must return ENOENT */
    gattr.pathname = (uint64_t)(uintptr_t)"/bpffs/no_such_map";
    assert(sys_bpf(7, &gattr, sizeof(gattr)) < 0 && errno == ENOENT);

    /* 4. Raw __NR_fchmod on O_PATH must return EBADF, so libc fchmod() falls back cleanly */
    int wfd = open("/bpffs/chmod_test", O_WRONLY | O_CREAT | O_TRUNC, 0666);
    assert(wfd >= 0);
    close(wfd);
    int opfd = openat(AT_FDCWD, "/bpffs/chmod_test", O_PATH | O_NOFOLLOW | O_CLOEXEC);
    assert(opfd >= 0);
    assert(syscall(__NR_fchmod, opfd, 0644) < 0 && errno == EBADF);
    assert(fchmod(opfd, 0644) == 0);
    close(opfd);
    unlink("/bpffs/chmod_test");

    puts("BPF_EMU_OK");
    return 0;
}
"""

def main():
    with tempfile.TemporaryDirectory(prefix="svbox_bpf_") as td:
        src = os.path.join(td, "t.c")
        exe = os.path.join(td, "t")
        bpffs = os.path.join(td, "bpffs")
        os.makedirs(bpffs)
        open(os.path.join(bpffs, "cfg_map"), "w").write("bpf-map type=2 key=4 value=4 max=2\n")
        open(os.path.join(bpffs, "hash_map"), "w").write("bpf-map type=1 key=8 value=8 max=128\n")
        open(src, "w").write(C_SRC)
        subprocess.run(["clang", "-O2", src, "-o", exe], check=True)
        r = subprocess.run([
            SVBOX, "--mode", "container", "--emulate-bpf",
            "-v", f"{bpffs}:/bpffs",
            "--", exe
        ], capture_output=True, text=True, timeout=15)
        print(r.stdout, r.stderr)
        assert r.returncode == 0 and "BPF_EMU_OK" in r.stdout, f"Failed rc={r.returncode}"

if __name__ == "__main__":
    main()
