#!/usr/bin/env python3
"""Generic container resource limits (--mem-mb, --disk-mb) and memfd fstat/statx fallback."""
import subprocess
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

build = lib.BUILD
loader = lib.loader()

PROBE_C = r"""
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/stat.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    /* 1. Virtual /proc/meminfo fstat + fstatat(AT_EMPTY_PATH) + statx(AT_EMPTY_PATH) */
    int fd = open("/proc/meminfo", O_RDONLY);
    if (fd < 0) { fprintf(stderr, "open /proc/meminfo: %d\n", errno); return 1; }
    struct stat st, st2;
    memset(&st, 0, sizeof(st));
    memset(&st2, 0, sizeof(st2));
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        fprintf(stderr, "fstat(/proc/meminfo): errno=%d size=%lld\n", errno, (long long)st.st_size);
        return 2;
    }
    if (fstatat(fd, "", &st2, AT_EMPTY_PATH) != 0 || st2.st_size != st.st_size) {
        fprintf(stderr, "fstatat(/proc/meminfo): errno=%d size=%lld\n", errno, (long long)st2.st_size);
        return 3;
    }
    struct statx sx;
    memset(&sx, 0, sizeof(sx));
    if (syscall(SYS_statx, fd, "", AT_EMPTY_PATH, STATX_BASIC_STATS, &sx) != 0 ||
        (long long)sx.stx_size != st.st_size) {
        fprintf(stderr, "statx(/proc/meminfo): errno=%d size=%llu\n", errno, (unsigned long long)sx.stx_size);
        return 4;
    }
    char buf[4096] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0 || !strstr(buf, "2097152 kB")) {
        fprintf(stderr, "meminfo mismatch: %s\n", buf);
        return 5;
    }
    /* Verify Cached/Buffers/MemFree/MemAvailable stay bounded within MemTotal */
    unsigned long long v_free = 0, v_avail = 0, v_cached = 0;
    const char *p = strstr(buf, "MemFree:");
    if (p) sscanf(p, "MemFree: %llu", &v_free);
    p = strstr(buf, "MemAvailable:");
    if (p) sscanf(p, "MemAvailable: %llu", &v_avail);
    p = strstr(buf, "\nCached:");
    if (p) sscanf(p, "\nCached: %llu", &v_cached);
    if (v_free > 2097152ULL || v_avail > 2097152ULL || v_cached > 2097152ULL / 4 ||
        v_free + v_cached > 2097152ULL) {
        fprintf(stderr, "meminfo clamp violation: free=%llu avail=%llu cached=%llu\n",
                v_free, v_avail, v_cached);
        return 5;
    }

    /* 2. Guest memfd_create + write + fstat */
    int mfd = (int)syscall(SYS_memfd_create, "svbox_res_mfd", 1);
    if (mfd < 0) { fprintf(stderr, "memfd_create: %d\n", errno); return 6; }
    if (write(mfd, "hello-memfd-12345", 17) != 17) return 7;
    memset(&st, 0, sizeof(st));
    if (fstat(mfd, &st) != 0 || st.st_size != 17) {
        fprintf(stderr, "fstat(memfd): errno=%d size=%lld\n", errno, (long long)st.st_size);
        return 8;
    }
    close(mfd);

    /* 3. --disk-mb 4096 via statfs and fstatfs */
    struct statfs sf, sf2;
    if (statfs("/", &sf) != 0) { fprintf(stderr, "statfs: %d\n", errno); return 9; }
    unsigned long long unit = sf.f_frsize ? (unsigned long long)sf.f_frsize : (unsigned long long)sf.f_bsize;
    unsigned long long total_mb = ((unsigned long long)sf.f_blocks * unit) / (1024ULL * 1024ULL);
    unsigned long long free_mb = ((unsigned long long)sf.f_bfree * unit) / (1024ULL * 1024ULL);
    if (total_mb != 4096ULL || free_mb > 4096ULL) {
        fprintf(stderr, "statfs mismatch: total=%lluMB free=%lluMB\n", total_mb, free_mb);
        return 10;
    }
    int rfd = open("/", O_RDONLY);
    if (rfd < 0 || fstatfs(rfd, &sf2) != 0 || sf2.f_blocks != sf.f_blocks) {
        fprintf(stderr, "fstatfs mismatch\n");
        return 11;
    }
    close(rfd);

    /* 4. Reverse /proc/self/fd path on a bind of a --lower subdir (even when upper path is longer) */
    int afd = open("/mnt/alias/data.txt", O_RDONLY);
    if (afd < 0) { fprintf(stderr, "open /mnt/alias/data.txt: %d\n", errno); return 12; }
    char proc_fd[64], link_buf[256];
    snprintf(proc_fd, sizeof(proc_fd), "/proc/self/fd/%d", afd);
    ssize_t lr = readlink(proc_fd, link_buf, sizeof(link_buf) - 1);
    close(afd);
    if (lr <= 0) { fprintf(stderr, "readlink %s: %d\n", proc_fd, errno); return 13; }
    link_buf[lr] = '\0';
    if (strcmp(link_buf, "/mnt/alias/data.txt") != 0) {
        fprintf(stderr, "reverse fd path mismatch: got '%s', want '/mnt/alias/data.txt'\n", link_buf);
        return 14;
    }

    /* 5. getsockopt(SOL_SOCKET, SO_PEERCRED) remaps host UID/GID to container fake UID/GID */
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sp) != 0) {
        fprintf(stderr, "socketpair: %d\n", errno);
        return 15;
    }
    struct ucred uc = { -1, 999999u, 999999u };
    socklen_t uclen = sizeof(uc);
    if (getsockopt(sp[0], SOL_SOCKET, SO_PEERCRED, &uc, &uclen) != 0) {
        fprintf(stderr, "SO_PEERCRED: %d\n", errno);
        close(sp[0]); close(sp[1]);
        return 16;
    }
    close(sp[0]); close(sp[1]);
    if (uc.uid != 0 || uc.gid != 0) {
        fprintf(stderr, "SO_PEERCRED mismatch: pid=%d uid=%u gid=%u (expected 0:0)\n", uc.pid, uc.uid, uc.gid);
        return 17;
    }

    printf("RESOURCE_LIMITS_OK\n");
    return 0;
}
"""

with tempfile.TemporaryDirectory(prefix='reslim-', dir=build) as temp:
    td = Path(temp)
    lower = td / 'l'
    upper = td / 'very_long_upper_directory_name_longer_than_bind'
    (lower / 'sub').mkdir(parents=True)
    (lower / 'sub' / 'data.txt').write_text('hello-alias\n')
    upper.mkdir()
    src = td / 'probe.c'
    bin_path = lower / 'probe'
    src.write_text(PROBE_C)
    subprocess.run(['clang', '-static', str(src), '-o', str(bin_path)], check=True)

    p = subprocess.run([
        str(loader),
        '--root', str(upper),
        '--lower', str(lower),
        '-u', '0:0',
        '--mem-mb', '2048',
        '--disk-mb', '4096',
        '-v', '/proc:/proc',
        '-v', f'{lower / "sub"}:/mnt/alias',
        '--', 'probe',
    ], capture_output=True, text=True, timeout=15)
    assert p.returncode == 0 and 'RESOURCE_LIMITS_OK\n' in p.stdout, (p.returncode, p.stdout, p.stderr)

    # Second pass: verify --root-disk-mb vs external volume --disk-mb + --disk-used-mb
    extvol = td / 'extvol'
    extvol.mkdir()
    SPLIT_PROBE_C = r"""
#include <fcntl.h>
#include <stdio.h>
#include <sys/statfs.h>
#include <unistd.h>
static int check_sf(const char *p, unsigned long long want_tot, unsigned long long want_free_max, int want_zero_free) {
    struct statfs sf, sf2;
    if (statfs(p, &sf) != 0) return 1;
    int fd = open(p, O_RDONLY);
    if (fd < 0 || fstatfs(fd, &sf2) != 0) return 2;
    close(fd);
    if (sf.f_blocks != sf2.f_blocks || sf.f_bfree != sf2.f_bfree) return 3;
    unsigned long long unit = sf.f_frsize ? (unsigned long long)sf.f_frsize : (unsigned long long)sf.f_bsize;
    unsigned long long tot = ((unsigned long long)sf.f_blocks * unit) / (1024ULL * 1024ULL);
    unsigned long long fre = ((unsigned long long)sf.f_bfree * unit) / (1024ULL * 1024ULL);
    if (tot != want_tot) { fprintf(stderr, "%s tot=%llu want=%llu\n", p, tot, want_tot); return 4; }
    if (want_zero_free && fre != 0) { fprintf(stderr, "%s fre=%llu want=0\n", p, fre); return 5; }
    if (!want_zero_free && fre > want_free_max) { fprintf(stderr, "%s fre=%llu max=%llu\n", p, fre, want_free_max); return 6; }
    return 0;
}
int main(void) {
    int rc;
    if ((rc = check_sf("/", 1900, 0, 1)) != 0) return 10 + rc;
    if ((rc = check_sf("/mnt/alias", 1900, 0, 1)) != 0) return 20 + rc;
    if ((rc = check_sf("/mnt/extvol", 8192, 6192, 0)) != 0) return 30 + rc;
    printf("SPLIT_DISK_OK\n");
    return 0;
}
"""
    src2 = td / 'split_probe.c'
    bin2 = lower / 'split_probe'
    src2.write_text(SPLIT_PROBE_C)
    subprocess.run(['clang', '-static', str(src2), '-o', str(bin2)], check=True)
    p2 = subprocess.run([
        str(loader),
        '--root', str(upper),
        '--lower', str(lower),
        '-u', '0:0',
        '--root-disk-mb', '1900',
        '--disk-mb', '8192',
        '--disk-used-mb', '2000',
        '-v', f'{lower / "sub"}:/mnt/alias',
        '-v', f'{extvol}:/mnt/extvol',
        '--', 'split_probe',
    ], capture_output=True, text=True, timeout=15)
    assert p2.returncode == 0 and 'SPLIT_DISK_OK\n' in p2.stdout, (p2.returncode, p2.stdout, p2.stderr)
    print('PASS: --mem-mb, --disk-mb, --root-disk-mb, --disk-used-mb, memfd fstat/fstatat/statx, RO --lower, and lower-bind /proc/self/fd')
