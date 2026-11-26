/* SPDX-License-Identifier: MIT */
/* PRoot path backend, /proc: links of loader-run processes (exe, cwd,
 * fd), their cmdline, readlink of /proc names, and the mount tables
 * generated from the R4 table. */
#include "vfs_bridge_internal.h"
#include "fake_ids.h"
#include "hook_runtime.h"
#include "integrity.h"
#include "platform.h"
#include "vdev.h"

static int parse_hex_u64(const char **pp, const char *end, uint64_t *out);
static size_t append_hex_u64(char *dst, size_t cap, size_t pos, uint64_t v, int min_digits);
static long write_all_fd(int fd, const char *buf, size_t len);
static uint32_t popcount64(uint64_t x);

/* Reverse-map a backing memfd path of a configured --vdev or emulated loop
 * device (e.g. "/memfd:svbox-binder (deleted)") to its guest device path. */
static int translate_vdev_or_loop_memfd(const char *path, size_t len, char *out, size_t cap)
{
    if (!path || len < 8 || strncmp(path, "/memfd:", 7) != 0)
        return 0;
    const char *vg = vdev_match_memfd(path, len);
    if (vg) {
        size_t vl = strlen(vg);
        if (vl < cap) {
            memcpy(out, vg, vl + 1);
            return 1;
        }
    }
    size_t core = len;
    if (core > 10 && strncmp(path + core - 10, " (deleted)", 10) == 0)
        core -= 10;
    static const char lpfx[] = "/memfd:elf-loop";
    size_t plen = sizeof(lpfx) - 1;
    if (core > plen && strncmp(path, lpfx, plen) == 0) {
        const char *suf = path + plen;
        size_t slen = core - plen;
        if (slen == 8 && strncmp(suf, "-control", 8) == 0 && cap > 17) {
            memcpy(out, "/dev/loop-control", 18);
            return 1;
        }
        if (slen == 1 && suf[0] >= '0' && suf[0] <= '7' && cap > 10) {
            memcpy(out, "/dev/loop", 9);
            out[9] = suf[0];
            out[10] = '\0';
            return 1;
        }
    }
    return 0;
}

static long current_id(long number)
{
    return raw_syscall(number, 0, 0, 0, 0, 0, 0);
}

/* Writes "/proc/<pid>" or "/proc/<pid>/task/<tid>" into out. */
static int format_proc(char *out, long pid, long tid)
{
    char *p = out;
    const char *prefix = "/proc/";
    while (*prefix) *p++ = *prefix++;
    for (int pass = 0; pass < (tid ? 2 : 1); pass++) {
        long value = pass ? tid : pid;
        char digits[24];
        int count = 0;
        do { digits[count++] = '0' + value % 10; value /= 10; } while (value);
        if (pass) { const char *task = "/task/"; while (*task) *p++ = *task++; }
        while (count) *p++ = digits[--count];
    }
    *p = 0;
    return FS_LINK_CANONICALIZE;
}

/* A loader-run process's kernel cmdline is the loader's own: loader options,
 * "--", then the guest argv (exactly what the guest received). Returns the
 * offset of the guest argv in proc_data and its length, or 0 if pid is not
 * loader-run or has no separator. exe receives --exec-exe when present. */
static long loader_argv(Bridge *b, long pid, size_t *start, const char **exe)
{
    char path[48];
    format_proc(path, pid, 0);
    strcat(path, "/cmdline");
    long fd = raw_syscall(__NR_openat, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (fd < 0) return 0;
    long total = 0, n;
    while (total < (long)sizeof(b->proc_data) &&
           (n = raw_syscall(__NR_read, fd, (long)b->proc_data + total,
                            sizeof(b->proc_data) - total, 0, 0, 0)) > 0)
        total += n;
    raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
    if (total <= 0 || total == (long)sizeof(b->proc_data) || b->proc_data[total - 1]) return 0;
    if (!g_payload_config.loader_path[0] || strcmp(b->proc_data, g_payload_config.loader_path))
        return 0;
    *exe = NULL;
    for (long at = (long)strlen(b->proc_data) + 1; at < total; at += (long)strlen(b->proc_data + at) + 1) {
        const char *arg = b->proc_data + at;
        if (!strcmp(arg, "--")) {
            *start = (size_t)(at + 3);
            return total - (long)*start;
        }
        if (!strcmp(arg, SVBOX_CHILD_EXEC_EXE)) {
            long next = at + (long)strlen(arg) + 1;
            if (next < total)
                *exe = b->proc_data + next;
        }
    }
    return 0;
}

/* PRoot's readlink_proc without a PID namespace: guest PIDs are kernel PIDs.
 * self/thread-self canonicalize to the caller; this process's exe is the guest
 * program (the kernel link names the loader); cwd, root and other processes'
 * exe are kernel targets reported in guest terms; fd entries stay magic links
 * when final (PRoot's DONT_CANONICALIZE), except under the read guard, where
 * a file target is resolved by its guest path so the policy applies. */
int pb_proc_link(void *opaque, char *out, const char *path,
                     const char *component, Comparison comparison)
{
    Bridge *b = opaque;
    if (comparison == PATHS_ARE_EQUAL) {
        if (!strcmp(component, "self"))
            return format_proc(out, current_id(__NR_getpid), 0);
        if (!strcmp(component, "thread-self"))
            return format_proc(out, current_id(__NR_getpid), current_id(__NR_gettid));
        return FS_LINK_DEFAULT;
    }
    if (comparison != PATH1_IS_PREFIX) return FS_LINK_DEFAULT;
    const char *cursor = path + strlen("/proc/");
    long pid = 0;
    /* Uncanonicalized self names: the broker resolves them to the caller,
     * so a walk through it never meets them as links. */
    if (!strncmp(cursor, "self", 4) && (!cursor[4] || cursor[4] == '/')) {
        pid = current_id(__NR_getpid);
        cursor += 4;
    } else if (!strncmp(cursor, "thread-self", 11) && (!cursor[11] || cursor[11] == '/')) {
        pid = current_id(__NR_getpid);
        cursor += 11;
    } else if (*cursor < '1' || *cursor > '9') return FS_LINK_DEFAULT;
    while (*cursor >= '0' && *cursor <= '9') pid = pid * 10 + (*cursor++ - '0');
    if (*cursor == '/' && !strncmp(cursor, "/task/", 6)) {
        cursor += 6;
        if (*cursor < '0' || *cursor > '9') return FS_LINK_DEFAULT;
        while (*cursor >= '0' && *cursor <= '9') cursor++;
    }
    size_t base = strlen(path);
    if (base + 1 + strlen(component) >= PATH_MAX) return -ENAMETOOLONG;
    int fd = !strcmp(cursor, "/fd");
    if (*cursor && !fd) return FS_LINK_DEFAULT;
    if (!fd && strcmp(component, "exe") && strcmp(component, "cwd") && strcmp(component, "root"))
        return FS_LINK_DEFAULT;
    if (!fd && !strcmp(component, "root")) {
        /* No chroot: the kernel names the host root. Guests share the view's. */
        strcpy(out, "/");
        return FS_LINK_CANONICALIZE;
    }
    if (!fd && !strcmp(component, "exe")) {
        const char *exe = pid == current_id(__NR_getpid) && g_payload_config.exec_exe[0] ?
            g_payload_config.exec_exe : NULL;
        size_t start;
        /* Another loader-run guest names its exe on its own command line. */
        if (!exe && loader_argv(b, pid, &start, &exe) && !exe) {
            const char *target = b->proc_data + start;
            while (target[0] == '.' && target[1] == '/') target += 2;
            if (strlen(target) + 2 < PATH_MAX) {
                out[0] = '/';
                strcpy(out + (target[0] != '/'), target);
                return FS_LINK_CANONICALIZE;
            }
        }
        if (exe && strlen(exe) < PATH_MAX) {
            strcpy(out, exe);
            return FS_LINK_CANONICALIZE;
        }
    }
    strcpy(b->proc_guest, path);
    strcat(b->proc_guest, "/");
    strcat(b->proc_guest, component);
    int keep = fd && g_payload_config.guard != GUARD_READS;
    if (keep) {
        strcpy(out, b->proc_guest);
        return FS_LINK_KEEP;
    }
    int rc = binding_table_map(&b->table, GUEST, b->proc_guest, b->proc_host);
    if (rc < 0) return rc;
    rc = pb_host_readlink(b, b->proc_host, out, PATH_MAX);
    if (rc < 0) return rc;
    if (rc >= PATH_MAX) return -ENAMETOOLONG;
    out[rc] = 0;
    if (out[0] != '/') {
        /* Pipes, sockets and anonymous objects: keep the magic link. */
        strcpy(out, b->proc_guest);
        return FS_LINK_KEEP;
    }
    rc = pb_guest_link_target(b, out);
    return rc < 0 ? rc : FS_LINK_CANONICALIZE;
}

/* /proc/<pid>/cmdline of a loader-run process is served from a memfd with
 * its guest argv; under ptrace PRoot simply shows the real (guest) argv.
 * Returns -ENOENT when the kernel file should be opened instead. */
long pb_proc_cmdline(Bridge *b, int flags)
{
    Comparison c = compare_paths("/proc", b->guest);
    if (c != PATH1_IS_PREFIX) return -ENOENT;
    const char *cursor = b->guest + strlen("/proc/");
    long pid = 0;
    if (*cursor < '1' || *cursor > '9') return -ENOENT;
    while (*cursor >= '0' && *cursor <= '9') pid = pid * 10 + (*cursor++ - '0');
    if (strcmp(cursor, "/cmdline")) return -ENOENT;
    size_t start;
    const char *exe;
    long length = loader_argv(b, pid, &start, &exe);
    if (!length) return -ENOENT;
    long fd = raw_syscall(__NR_memfd_create, (long)"cmdline",
                          (flags & O_CLOEXEC) ? 1 /* MFD_CLOEXEC */ : 0, 0, 0, 0, 0);
    if (fd < 0) return fd;
    long done = 0, n = 0;
    while (done < length && (n = raw_syscall(__NR_write, fd, (long)b->proc_data + start + done,
                                             length - done, 0, 0, 0)) > 0)
        done += n;
    if (n < 0 || raw_syscall(__NR_lseek, fd, 0, 0, 0, 0, 0) < 0) {
        raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
        return n < 0 ? n : -EIO;
    }
    return fd;
}

/* readlink of a canonical /proc path: emulate it like resolution does, then
 * return at most bufsiz bytes without NUL, like the kernel. */
long pb_proc_readlink(Bridge *b, long a[6])
{
    if (!a[2]) return -EFAULT;
    size_t length = strlen(b->guest);
    while (length > 1 && b->guest[length - 1] == '/') b->guest[--length] = 0;
    char *slash = b->guest + length;
    while (slash > b->guest && *slash != '/') slash--;
    *slash = 0;
    const char *component = slash + 1;
    Comparison c = compare_paths("/proc", b->guest);
    int action = pb_proc_link(b, b->cwd, b->guest, component, c);
    if (action < 0) return action;
    long count;
    if (action == FS_LINK_DEFAULT || action == FS_LINK_KEEP) {
        /* Report virtual device or synthesized procfs/sysfs guest paths for
         * /proc/<self>/fd/<N> instead of internal host memfd backing names. */
        if (component[0] >= '0' && component[0] <= '9') {
            const char *cur = b->guest;
            if (!strncmp(cur, "/proc/", 6)) {
                cur += 6;
                long self_pid = current_id(__NR_getpid);
                long pid = 0;
                if (!strncmp(cur, "self", 4) && cur[4] == '/') {
                    pid = self_pid; cur += 4;
                } else if (!strncmp(cur, "thread-self", 11) && cur[11] == '/') {
                    pid = self_pid; cur += 11;
                } else {
                    while (*cur >= '0' && *cur <= '9') pid = pid * 10 + (*cur++ - '0');
                }
                if (pid == self_pid && !strcmp(cur, "/fd")) {
                    int fdn = 0;
                    const char *d = component;
                    while (*d >= '0' && *d <= '9') { fdn = fdn * 10 + (*d++ - '0'); }
                    if (!*d) {
                        const char *vg = vdev_enabled() ? vdev_fd_guest_path(fdn) : NULL;
                        if (vg && strlen(vg) < sizeof(b->cwd)) {
                            strcpy(b->cwd, vg);
                            count = (long)strlen(b->cwd);
                            if ((unsigned long)a[3] < (unsigned long)count) count = (long)a[3];
                            memcpy((void *)a[2], b->cwd, (size_t)count);
                            return count;
                        }
                        if (pb_vfd_guest_path(fdn, b->cwd, sizeof(b->cwd)) == 0) {
                            count = (long)strlen(b->cwd);
                            if ((unsigned long)a[3] < (unsigned long)count) count = (long)a[3];
                            memcpy((void *)a[2], b->cwd, (size_t)count);
                            return count;
                        }
                    }
                }
            }
        }
        /* Not emulated, or a kept magic link: the kernel's own answer,
         * with an absolute target reported in guest terms. */
        *slash = '/';
        count = pb_host_readlink(b, b->host, b->cwd, sizeof(b->cwd) - 1);
        if (count < 0) return count;
        b->cwd[count] = 0;
        if (translate_vdev_or_loop_memfd(b->cwd, (size_t)count, b->proc_candidate,
                                         sizeof(b->proc_candidate))) {
            strcpy(b->cwd, b->proc_candidate);
        } else {
            int rc = pb_guest_link_target(b, b->cwd);
            if (rc < 0) return rc;
        }
    }
    count = (long)strlen(b->cwd);
    if ((unsigned long)a[3] < (unsigned long)count) count = (long)a[3];
    memcpy((void *)a[2], b->cwd, (size_t)count);
    return count;
}

/* /proc/<pid>/mounts, mountinfo (and the task/<tid> ones) of a process of
 * this view: generated from the table. -ENOENT: the kernel's file. */
long pb_proc_mounts(Bridge *b, int flags)
{
    if (compare_paths("/proc", b->guest) != PATH1_IS_PREFIX)
        return -ENOENT;
    const char *cursor = b->guest + strlen("/proc/");
    long pid = 0;
    /* A file of its own on HongMeng, a link to self/mounts on Linux. */
    if (!strcmp(cursor, "mounts")) {
        pid = raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
        cursor--;
    } else if (!strncmp(cursor, "self/", 5) || !strncmp(cursor, "thread-self/", 12)) {
        pid = raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
        cursor = strchr(cursor, '/');
    } else {
        if (*cursor < '1' || *cursor > '9') return -ENOENT;
        while (*cursor >= '0' && *cursor <= '9') pid = pid * 10 + (*cursor++ - '0');
    }
    if (!strncmp(cursor, "/task/", 6)) {
        cursor += 6;
        if (*cursor < '1' || *cursor > '9') return -ENOENT;
        while (*cursor >= '0' && *cursor <= '9') cursor++;
    }
    int info;
    if (!strcmp(cursor, "/mounts")) info = 0;
    else if (!strcmp(cursor, "/mountinfo")) info = 1;
    else return -ENOENT;
    if (pid != raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0)) {
        size_t start;
        const char *exe;
        if (!loader_argv(b, pid, &start, &exe)) return -ENOENT;
    }
    long fd = raw_syscall(__NR_memfd_create, (long)(info ? "mountinfo" : "mounts"),
                          (flags & O_CLOEXEC) ? 1 /* MFD_CLOEXEC */ : 0, 0, 0, 0, 0);
    if (fd < 0) return fd;
    long rc = mounts_render((int)fd, info);
    if (rc >= 0) rc = raw_syscall(__NR_lseek, fd, 0, 0, 0, 0, 0);
    if (rc < 0) {
        raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
        return rc;
    }
    return fd;
}

static size_t append_u32(char *dst, size_t cap, size_t pos, uint32_t v)
{
    char tmp[16];
    int d = 0;
    do { tmp[d++] = (char)('0' + (v % 10)); v /= 10; } while (v);
    while (d > 0 && pos < cap) dst[pos++] = tmp[--d];
    return pos;
}

static size_t format_id_line(char *dst, size_t cap, const char *label, const uint32_t ids[4])
{
    size_t p = 0;
    for (size_t i = 0; label[i] && p < cap; i++) dst[p++] = label[i];
    for (int k = 0; k < 4; k++) {
        if (p < cap) dst[p++] = '\t';
        p = append_u32(dst, cap, p, ids[k]);
    }
    if (p < cap) dst[p++] = '\n';
    return p;
}

/* /proc/<pid>/status (and self / thread-self / task/<tid>): reflect fake_ids
 * Uid:/Gid: lines consistently with getuid()/set*id(). -ENOENT: kernel file. */
long pb_proc_status(Bridge *b, int flags)
{
    if (compare_paths("/proc", b->guest) != PATH1_IS_PREFIX)
        return -ENOENT;
    const char *cursor = b->guest + strlen("/proc/");
    long self_pid = raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
    long pid = 0;
    if (!strncmp(cursor, "self/", 5) || !strncmp(cursor, "thread-self/", 12)) {
        pid = self_pid;
        cursor = strchr(cursor, '/');
    } else {
        if (*cursor < '1' || *cursor > '9') return -ENOENT;
        while (*cursor >= '0' && *cursor <= '9') pid = pid * 10 + (*cursor++ - '0');
    }
    if (!strncmp(cursor, "/task/", 6)) {
        cursor += 6;
        if (*cursor < '1' || *cursor > '9') return -ENOENT;
        while (*cursor >= '0' && *cursor <= '9') cursor++;
    }
    if (strcmp(cursor, "/status") != 0)
        return -ENOENT;

    uint32_t ids[8];
    if (pid == self_pid) {
        fake_ids_current(ids);
    } else {
        int found = 0;
        const char *base = g_payload_config.mount_scratch;
        if (base[0]) {
            char ppath[CONFIG_MAX_PATH + 32];
            size_t n = 0;
            while (base[n] && n < CONFIG_MAX_PATH - 1) { ppath[n] = base[n]; n++; }
            const char *sub = "/.pid_ids/";
            for (size_t i = 0; sub[i]; i++) ppath[n++] = sub[i];
            n = append_u32(ppath, sizeof(ppath) - 1, n, (uint32_t)pid);
            ppath[n] = '\0';
            long pfd = raw_syscall(__NR_openat, AT_FDCWD, (long)ppath, O_RDONLY | O_CLOEXEC, 0, 0, 0);
            if (pfd >= 0) {
                long nr = raw_syscall(__NR_read, pfd, (long)ids, sizeof(ids), 0, 0, 0);
                raw_syscall(__NR_close, pfd, 0, 0, 0, 0, 0);
                if (nr == (long)sizeof(ids)) found = 1;
            }
        }
        if (!found) {
            size_t start;
            const char *exe;
            if (!loader_argv(b, pid, &start, &exe)) return -ENOENT;
            for (int i = 0; i < 8; i++) ids[i] = g_payload_config.fake_ids[i];
        }
    }

    long kfd = raw_syscall(__NR_openat, AT_FDCWD, (long)b->host, O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (kfd < 0) return kfd;
    size_t total = 0;
    while (total < sizeof(b->proc_data)) {
        long r = raw_syscall(__NR_read, kfd, (long)(b->proc_data + total),
                             (long)(sizeof(b->proc_data) - total), 0, 0, 0);
        if (r <= 0) break;
        total += (size_t)r;
    }
    raw_syscall(__NR_close, kfd, 0, 0, 0, 0, 0);

    long mfd = raw_syscall(__NR_memfd_create, (long)"status",
                           (flags & O_CLOEXEC) ? 1 /* MFD_CLOEXEC */ : 0, 0, 0, 0, 0);
    if (mfd < 0) return mfd;

    char out_buf[4096];
    size_t out_used = 0;
    long rc = 0;
    size_t pos = 0;
    int is_hm = platform_is_harmonyos();
    uint32_t vcpus = g_payload_config.cpu_mask ? popcount64(g_payload_config.cpu_mask) : 0;
    if (vcpus > 64) vcpus = 64;

    while (pos < total && rc >= 0) {
        size_t nl = pos;
        while (nl < total && b->proc_data[nl] != '\n') nl++;
        size_t line_len = (nl < total) ? (nl - pos + 1) : (nl - pos);
        const char *lp = b->proc_data + pos;

        /* Strip host-specific non-Linux memory fields on HarmonyOS HMKernel. */
        if (is_hm && ((line_len >= 7 && !strncmp(lp, "VmKobj:", 7)) ||
                      (line_len >= 8 && !strncmp(lp, "PurgSum:", 8)) ||
                      (line_len >= 8 && !strncmp(lp, "PurgPin:", 8)))) {
            pos += line_len;
            continue;
        }

        int is_uid = (line_len >= 4 && !strncmp(lp, "Uid:", 4));
        int is_gid = (!is_uid && line_len >= 4 && !strncmp(lp, "Gid:", 4));
        int is_groups = (!is_uid && !is_gid && line_len >= 7 && !strncmp(lp, "Groups:", 7));
        int is_fdsize = (!is_uid && !is_gid && !is_groups &&
                         line_len >= 9 && !strncmp(lp, "FDSize:\t0", 9) &&
                         (line_len == 9 || lp[9] == '\n'));
        int is_cpus_mask = (vcpus > 0 && line_len >= 13 && !strncmp(lp, "Cpus_allowed:", 13));
        int is_cpus_list = (vcpus > 0 && line_len >= 18 && !strncmp(lp, "Cpus_allowed_list:", 18));
        int is_mems_zero = (is_hm && line_len >= 22 && !strncmp(lp, "Mems_allowed:\t00000000", 22));
        int hide_sec = (g_payload_config.seccomp_backstop || g_payload_config.trap_sigsys);
        int is_sigcgt = (hide_sec && line_len >= 7 && !strncmp(lp, "SigCgt:", 7));
        int is_sigign = (hide_sec && line_len >= 7 && !strncmp(lp, "SigIgn:", 7));
        int is_seccomp = (hide_sec && line_len >= 8 && !strncmp(lp, "Seccomp:", 8));
        int is_secfilt = (hide_sec && line_len >= 16 && !strncmp(lp, "Seccomp_filters:", 16));
        int is_nnp = (hide_sec && line_len >= 11 && !strncmp(lp, "NoNewPrivs:", 11));
        int is_cap_zero = (ids[1] != 0 && line_len >= 7 &&
                           (!strncmp(lp, "CapInh:", 7) ||
                            !strncmp(lp, "CapPrm:", 7) ||
                            !strncmp(lp, "CapEff:", 7) ||
                            !strncmp(lp, "CapAmb:", 7)));

        const char *emit_ptr = lp;
        size_t emit_len = line_len;
        char line[256];
        if (is_uid || is_gid || is_groups || is_fdsize || is_cpus_mask || is_cpus_list ||
            is_mems_zero || is_sigcgt || is_sigign || is_seccomp || is_secfilt || is_nnp || is_cap_zero) {
            size_t llen = 0;
            if (is_uid || is_gid) {
                llen = format_id_line(line, sizeof(line),
                                      is_uid ? "Uid:" : "Gid:",
                                      is_uid ? ids : (ids + 4));
            } else if (is_groups) {
                const char *lbl = "Groups:\t";
                llen = strlen(lbl);
                memcpy(line, lbl, llen);
                if (pid == self_pid) {
                    uint32_t grps[32];
                    int ng = fake_ids_groups(grps);
                    for (int gi = 0; gi < ng && llen + 13 < sizeof(line); gi++) {
                        llen = append_u32(line, sizeof(line) - 3, llen, grps[gi]);
                        line[llen++] = ' ';
                    }
                } else {
                    llen = append_u32(line, sizeof(line) - 3, llen, ids[4]);
                    line[llen++] = ' ';
                }
                line[llen++] = '\n';
            } else if (is_fdsize) {
                const char *s = "FDSize:\t64\n";
                llen = strlen(s);
                memcpy(line, s, llen);
            } else if (is_cpus_mask) {
                const char *lbl = "Cpus_allowed:\t";
                llen = strlen(lbl);
                memcpy(line, lbl, llen);
                if (vcpus <= 32) {
                    uint64_t m = (vcpus == 32) ? 0xffffffffull : ((1ull << vcpus) - 1ull);
                    int digits = (int)((vcpus + 3u) / 4u);
                    llen = append_hex_u64(line, sizeof(line) - 2, llen, m, digits);
                } else {
                    uint64_t hi = (vcpus == 64) ? 0xffffffffull : ((1ull << (vcpus - 32u)) - 1ull);
                    int hdigits = (int)(((vcpus - 32u) + 3u) / 4u);
                    llen = append_hex_u64(line, sizeof(line) - 12, llen, hi, hdigits);
                    line[llen++] = ',';
                    llen = append_hex_u64(line, sizeof(line) - 2, llen, 0xffffffffull, 8);
                }
                line[llen++] = '\n';
            } else if (is_cpus_list) {
                const char *lbl = "Cpus_allowed_list:\t0";
                llen = strlen(lbl);
                memcpy(line, lbl, llen);
                if (vcpus > 1) {
                    line[llen++] = '-';
                    llen = append_u32(line, sizeof(line) - 2, llen, vcpus - 1u);
                }
                line[llen++] = '\n';
            } else if (is_mems_zero) {
                const char *s = "Mems_allowed:\t1\n";
                llen = strlen(s);
                memcpy(line, s, llen);
            } else if (is_sigcgt || is_sigign) {
                const char *sp = lp + 7;
                const char *lend = lp + line_len;
                while (sp < lend && (*sp == ' ' || *sp == '\t')) sp++;
                uint64_t mask = 0;
                if (!parse_hex_u64(&sp, lend, &mask)) {
                    llen = line_len < sizeof(line) ? line_len : sizeof(line);
                    memcpy(line, lp, llen);
                } else {
                    int ss_state = (pid == self_pid) ? integrity_guest_sigsys_state() : 0;
                    const uint64_t sigsys_bit = 1ull << 30; /* SIGSYS (31) */
                    if (is_sigcgt) {
                        if (ss_state != 2) mask &= ~sigsys_bit;
                    } else {
                        if (ss_state == 1) mask |= sigsys_bit;
                        else if (ss_state == 0) mask &= ~sigsys_bit;
                    }
                    const char *lbl = is_sigcgt ? "SigCgt:\t" : "SigIgn:\t";
                    llen = strlen(lbl);
                    memcpy(line, lbl, llen);
                    llen = append_hex_u64(line, sizeof(line) - 2, llen, mask, 16);
                    line[llen++] = '\n';
                }
            } else if (is_seccomp) {
                const char *s = "Seccomp:\t0\n";
                llen = strlen(s);
                memcpy(line, s, llen);
            } else if (is_nnp) {
                const char *s = "NoNewPrivs:\t0\n";
                llen = strlen(s);
                memcpy(line, s, llen);
            } else if (is_cap_zero) {
                memcpy(line, lp, 7);
                const char *z = "\t0000000000000000\n";
                size_t zl = strlen(z);
                memcpy(line + 7, z, zl);
                llen = 7 + zl;
            } else {
                const char *s = "Seccomp_filters:\t0\n";
                llen = strlen(s);
                memcpy(line, s, llen);
            }
            emit_ptr = line;
            emit_len = llen;
        }

        if (out_used + emit_len > sizeof(out_buf)) {
            if (out_used > 0) {
                rc = write_all_fd((int)mfd, out_buf, out_used);
                out_used = 0;
            }
            if (rc >= 0 && emit_len >= sizeof(out_buf)) {
                rc = write_all_fd((int)mfd, emit_ptr, emit_len);
                emit_len = 0;
            }
        }
        if (rc >= 0 && emit_len > 0) {
            memcpy(out_buf + out_used, emit_ptr, emit_len);
            out_used += emit_len;
        }
        pos += line_len;
    }
    if (rc >= 0 && out_used > 0)
        rc = write_all_fd((int)mfd, out_buf, out_used);
    if (rc >= 0) rc = raw_syscall(__NR_lseek, mfd, 0, 0, 0, 0, 0);
    if (rc < 0) {
        raw_syscall(__NR_close, mfd, 0, 0, 0, 0, 0);
        return rc;
    }
    return mfd;
}

/* Helper: parse "/proc/<pid|self|thread-self>[/task/<tid>]" prefix and return
 * pointer to the trailing subpath (starting with '/'), or NULL on mismatch. */
static const char *parse_proc_pid_subpath(const char *guest, long self_pid, long *out_pid)
{
    if (compare_paths("/proc", guest) != PATH1_IS_PREFIX)
        return NULL;
    const char *cursor = guest + strlen("/proc/");
    long pid = 0;
    if (!strncmp(cursor, "self/", 5) || !strncmp(cursor, "thread-self/", 12)) {
        pid = self_pid;
        cursor = strchr(cursor, '/');
    } else {
        if (*cursor < '1' || *cursor > '9') return NULL;
        while (*cursor >= '0' && *cursor <= '9') pid = pid * 10 + (*cursor++ - '0');
    }
    if (!strncmp(cursor, "/task/", 6)) {
        cursor += 6;
        if (*cursor < '1' || *cursor > '9') return NULL;
        while (*cursor >= '0' && *cursor <= '9') cursor++;
    }
    if (*cursor != '/') return NULL;
    *out_pid = pid;
    return cursor;
}

/* Standard Linux cgroup v1/v2 controller names (excludes non-Linux host controllers). */
static int is_std_linux_cgroup_token(const char *tok, size_t len)
{
    if (len == 0) return 1; /* cgroup v2: "0::/" */
    if (len > 5 && !strncmp(tok, "name=", 5)) return 1;
    static const char *const std_ctrls[] = {
        "cpu", "cpuacct", "cpuset", "memory", "blkio", "io", "pids",
        "freezer", "devices", "net_cls", "net_prio", "perf_event",
        "hugetlb", "rdma", "misc", "schedtune"
    };
    for (size_t i = 0; i < sizeof(std_ctrls) / sizeof(std_ctrls[0]); i++) {
        if (strlen(std_ctrls[i]) == len && !strncmp(tok, std_ctrls[i], len))
            return 1;
    }
    return 0;
}

static int is_std_linux_cgroup_list(const char *s, size_t len)
{
    if (len == 0) return 1;
    size_t i = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && s[j] != ',') j++;
        if (!is_std_linux_cgroup_token(s + i, j - i))
            return 0;
        i = (j < len) ? (j + 1) : j;
    }
    return 1;
}

/* Container cgroup-namespace view: strip host cgroup paths in /proc/<pid>/cgroup
 * so each hierarchy reports container-relative root ("/") instead of host paths. */
long pb_proc_cgroup(Bridge *b, int flags)
{
    long self_pid = raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
    long pid = 0;
    const char *sub = parse_proc_pid_subpath(b->guest, self_pid, &pid);
    if (!sub || strcmp(sub, "/cgroup") != 0)
        return -ENOENT;

    long kfd = raw_syscall(__NR_openat, AT_FDCWD, (long)b->host, O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (kfd < 0) return kfd;
    size_t total = 0;
    while (total < sizeof(b->proc_data)) {
        long r = raw_syscall(__NR_read, kfd, (long)(b->proc_data + total),
                             (long)(sizeof(b->proc_data) - total), 0, 0, 0);
        if (r <= 0) break;
        total += (size_t)r;
    }
    raw_syscall(__NR_close, kfd, 0, 0, 0, 0, 0);

    long mfd = raw_syscall(__NR_memfd_create, (long)"cgroup",
                           (flags & O_CLOEXEC) ? 1 : 0, 0, 0, 0, 0);
    if (mfd < 0) return mfd;

    char out_buf[2048];
    size_t out_used = 0;
    int is_hm = platform_is_harmonyos();
    long rc = 0;
    size_t pos = 0;
    while (pos < total && rc >= 0) {
        size_t nl = pos;
        while (nl < total && b->proc_data[nl] != '\n') nl++;
        size_t llen = (nl < total) ? (nl - pos + 1) : (nl - pos);
        const char *lp = b->proc_data + pos;
        int colons = 0;
        size_t first_colon = 0, second_colon = 0;
        for (size_t k = 0; k < llen; k++) {
            if (lp[k] == ':') {
                colons++;
                if (colons == 1) first_colon = k;
                else if (colons == 2) { second_colon = k; break; }
            }
        }
        if (colons == 2) {
            if (is_hm && !is_std_linux_cgroup_list(lp + first_colon + 1, second_colon - first_colon - 1)) {
                pos += llen;
                continue;
            }
            size_t need = second_colon + 3;
            if (out_used + need > sizeof(out_buf)) {
                if (out_used > 0) {
                    rc = write_all_fd((int)mfd, out_buf, out_used);
                    out_used = 0;
                }
            }
            if (rc >= 0) {
                if (need <= sizeof(out_buf)) {
                    memcpy(out_buf + out_used, lp, second_colon + 1);
                    out_used += second_colon + 1;
                    out_buf[out_used++] = '/';
                    out_buf[out_used++] = '\n';
                } else {
                    rc = write_all_fd((int)mfd, lp, second_colon + 1);
                    if (rc >= 0) rc = write_all_fd((int)mfd, "/\n", 2);
                }
            }
        } else {
            if (out_used + llen > sizeof(out_buf)) {
                if (out_used > 0) {
                    rc = write_all_fd((int)mfd, out_buf, out_used);
                    out_used = 0;
                }
            }
            if (rc >= 0) {
                if (llen <= sizeof(out_buf)) {
                    memcpy(out_buf + out_used, lp, llen);
                    out_used += llen;
                } else {
                    rc = write_all_fd((int)mfd, lp, llen);
                }
            }
        }
        pos += llen;
    }
    if (rc >= 0 && out_used > 0)
        rc = write_all_fd((int)mfd, out_buf, out_used);
    if (rc >= 0) rc = raw_syscall(__NR_lseek, mfd, 0, 0, 0, 0, 0);
    if (rc < 0) {
        raw_syscall(__NR_close, mfd, 0, 0, 0, 0, 0);
        return rc;
    }
    return mfd;
}

/* Container /proc/<self>/environ: return the sanitized initial container
 * environment instead of the host execve environment of the loader. */
long pb_proc_environ(Bridge *b, int flags)
{
    if (!g_payload_config.init_env_addr)
        return -ENOENT;
    long self_pid = raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
    long pid = 0;
    const char *sub = parse_proc_pid_subpath(b->guest, self_pid, &pid);
    if (!sub || strcmp(sub, "/environ") != 0 || pid != self_pid)
        return -ENOENT;

    long mfd = raw_syscall(__NR_memfd_create, (long)"environ",
                           (flags & O_CLOEXEC) ? 1 : 0, 0, 0, 0, 0);
    if (mfd < 0) return mfd;
    long rc = 0;
    if (g_payload_config.init_env_addr > 1 && g_payload_config.init_env_size > 0) {
        rc = write_all_fd((int)mfd,
                          (const char *)(uintptr_t)g_payload_config.init_env_addr,
                          (size_t)g_payload_config.init_env_size);
    }
    if (rc >= 0) rc = raw_syscall(__NR_lseek, mfd, 0, 0, 0, 0, 0);
    if (rc < 0) {
        raw_syscall(__NR_close, mfd, 0, 0, 0, 0, 0);
        return rc;
    }
    return mfd;
}

/* Container LSM isolation: when running in a container without an active
 * LSM namespace, do not expose the host's /proc/<pid>/attr/<context> label. */
long pb_proc_attr(Bridge *b, int flags)
{
    (void)flags;
    long self_pid = raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
    long pid = 0;
    const char *sub = parse_proc_pid_subpath(b->guest, self_pid, &pid);
    if (!sub || strncmp(sub, "/attr/", 6) != 0)
        return -ENOENT;
    const char *attr = sub + 6;
    if (!strcmp(attr, "current") || !strcmp(attr, "prev") ||
        !strcmp(attr, "exec") || !strcmp(attr, "fscreate") ||
        !strcmp(attr, "keycreate") || !strcmp(attr, "sockcreate") ||
        !strncmp(attr, "smack/", 6) || !strncmp(attr, "apparmor/", 9))
        return -EINVAL;
    return -ENOENT;
}


static long write_all_fd(int fd, const char *buf, size_t len)
{
    size_t done = 0;
    while (done < len) {
        long w = raw_syscall(__NR_write, fd, (long)(buf + done), (long)(len - done), 0, 0, 0);
        if (w <= 0)
            return w ? w : -EIO;
        done += (size_t)w;
    }
    return 0;
}

static size_t append_u64(char *dst, size_t cap, size_t pos, uint64_t v)
{
    char tmp[24];
    int d = 0;
    do { tmp[d++] = (char)('0' + (v % 10)); v /= 10; } while (v);
    while (d > 0 && pos < cap) dst[pos++] = tmp[--d];
    return pos;
}

static uint32_t popcount64(uint64_t x)
{
    uint32_t c = 0;
    while (x) {
        x &= x - 1;
        c++;
    }
    return c;
}

/* Virtualize /proc/cpuinfo and /sys/devices/system/cpu/{online,present,possible}
 * when --cpuset restricts the container's CPU mask, so guest runtimes size their
 * thread pools to the allocated core count instead of host core count. */
long pb_proc_cpuinfo(Bridge *b, int flags)
{
    uint64_t mask = g_payload_config.cpu_mask;
    if (!mask)
        return -ENOENT;
    uint32_t ncpus = popcount64(mask);
    if (!ncpus)
        return -ENOENT;

    if (!strcmp(b->guest, "/sys/devices/system/cpu/online") ||
        !strcmp(b->guest, "/sys/devices/system/cpu/present") ||
        !strcmp(b->guest, "/sys/devices/system/cpu/possible")) {
        char buf[64];
        size_t p = 0;
        buf[p++] = '0';
        if (ncpus > 1) {
            buf[p++] = '-';
            p = append_u32(buf, sizeof(buf) - 2, p, ncpus - 1);
        }
        buf[p++] = '\n';
        long mfd = raw_syscall(__NR_memfd_create, (long)"cpu_online",
                               (flags & O_CLOEXEC) ? 1 : 0, 0, 0, 0, 0);
        if (mfd < 0)
            return mfd;
        long rc = write_all_fd((int)mfd, buf, p);
        if (rc >= 0) rc = raw_syscall(__NR_lseek, mfd, 0, 0, 0, 0, 0);
        if (rc < 0) {
            raw_syscall(__NR_close, mfd, 0, 0, 0, 0, 0);
            return rc;
        }
        return mfd;
    }

    if (strcmp(b->guest, "/proc/cpuinfo") != 0)
        return -ENOENT;

    /* Extract the first processor stanza's body from host /proc/cpuinfo to keep
     * authentic Features/implementer/part fields while emitting exactly ncpus entries. */
    size_t body_len = 0;
    long kfd = raw_syscall(__NR_openat, AT_FDCWD, (long)"/proc/cpuinfo", O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (kfd >= 0) {
        size_t total = 0;
        while (total < sizeof(b->proc_data)) {
            long r = raw_syscall(__NR_read, kfd, (long)(b->proc_data + total),
                                 (long)(sizeof(b->proc_data) - total), 0, 0, 0);
            if (r <= 0) break;
            total += (size_t)r;
        }
        raw_syscall(__NR_close, kfd, 0, 0, 0, 0, 0);
        size_t pos = 0;
        int in_first = 0;
        while (pos < total) {
            size_t nl = pos;
            while (nl < total && b->proc_data[nl] != '\n') nl++;
            size_t llen = (nl < total) ? (nl - pos + 1) : (nl - pos);
            if (llen >= 9 && !strncmp(b->proc_data + pos, "processor", 9)) {
                if (in_first)
                    break;
                in_first = 1;
            } else if (in_first) {
                if (llen <= 1)
                    break;
                if (body_len + llen < sizeof(b->proc_candidate)) {
                    memcpy(b->proc_candidate + body_len, b->proc_data + pos, llen);
                    body_len += llen;
                }
            }
            pos += llen;
        }
    }
    if (body_len == 0) {
        const char *fallback = "Features\t: fp asimd evtstrm crc32\nCPU architecture: 8\n";
        body_len = strlen(fallback);
        memcpy(b->proc_candidate, fallback, body_len);
    }

    long mfd = raw_syscall(__NR_memfd_create, (long)"cpuinfo",
                           (flags & O_CLOEXEC) ? 1 : 0, 0, 0, 0, 0);
    if (mfd < 0)
        return mfd;
    long rc = 0;
    for (uint32_t i = 0; i < ncpus && rc >= 0; i++) {
        char hdr[48];
        const char *pfx = "processor\t: ";
        size_t p = strlen(pfx);
        memcpy(hdr, pfx, p);
        p = append_u32(hdr, sizeof(hdr) - 2, p, i);
        hdr[p++] = '\n';
        rc = write_all_fd((int)mfd, hdr, p);
        if (rc >= 0) rc = write_all_fd((int)mfd, b->proc_candidate, body_len);
        if (rc >= 0) rc = write_all_fd((int)mfd, "\n", 1);
    }
    if (rc >= 0) rc = raw_syscall(__NR_lseek, mfd, 0, 0, 0, 0, 0);
    if (rc < 0) {
        raw_syscall(__NR_close, mfd, 0, 0, 0, 0, 0);
        return rc;
    }
    return mfd;
}


static uint64_t parse_kb_value(const char *line, size_t len)
{
    size_t i = 0;
    while (i < len && line[i] != ':') i++;
    if (i < len) i++;
    while (i < len && (line[i] == ' ' || line[i] == '\t')) i++;
    uint64_t v = 0;
    while (i < len && line[i] >= '0' && line[i] <= '9') {
        v = v * 10 + (uint64_t)(line[i] - '0');
        i++;
    }
    return v;
}

static size_t format_meminfo_line(char *dst, size_t cap, const char *key, uint64_t kb)
{
    size_t p = 0;
    for (size_t i = 0; key[i] && p < cap; i++) dst[p++] = key[i];
    if (p < cap) dst[p++] = ' ';
    char num[24];
    size_t nlen = append_u64(num, sizeof(num), 0, kb);
    size_t target_col = 24;
    while (p + nlen < target_col && p < cap) dst[p++] = ' ';
    for (size_t i = 0; i < nlen && p < cap; i++) dst[p++] = num[i];
    const char *suf = " kB\n";
    for (size_t i = 0; suf[i] && p < cap; i++) dst[p++] = suf[i];
    return p;
}

/* Virtualize /proc/meminfo when --mem-mb is configured: cap MemTotal to
 * mem_limit_mb * 1024 kB and clamp MemFree/MemAvailable/Buffers/Cached within it. */
long pb_proc_meminfo(Bridge *b, int flags)
{
    if (!g_payload_config.mem_limit_mb || strcmp(b->guest, "/proc/meminfo") != 0)
        return -ENOENT;
    uint64_t limit_kb = (uint64_t)g_payload_config.mem_limit_mb * 1024ull;

    long kfd = raw_syscall(__NR_openat, AT_FDCWD, (long)"/proc/meminfo", O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (kfd < 0)
        return kfd;
    size_t total = 0;
    while (total < sizeof(b->proc_data)) {
        long r = raw_syscall(__NR_read, kfd, (long)(b->proc_data + total),
                             (long)(sizeof(b->proc_data) - total), 0, 0, 0);
        if (r <= 0) break;
        total += (size_t)r;
    }
    raw_syscall(__NR_close, kfd, 0, 0, 0, 0, 0);

    long mfd = raw_syscall(__NR_memfd_create, (long)"meminfo",
                           (flags & O_CLOEXEC) ? 1 : 0, 0, 0, 0, 0);
    if (mfd < 0)
        return mfd;

    long rc = 0;
    size_t pos = 0;
    size_t span_start = 0;
    while (pos < total && rc >= 0) {
        size_t nl = pos;
        while (nl < total && b->proc_data[nl] != '\n') nl++;
        size_t llen = (nl < total) ? (nl - pos + 1) : (nl - pos);
        const char *lp = b->proc_data + pos;
        const char *rkey = NULL;
        uint64_t rval = 0;
        if (llen >= 9 && !strncmp(lp, "MemTotal:", 9)) {
            rkey = "MemTotal:";
            rval = limit_kb;
        } else if (llen >= 8 && !strncmp(lp, "MemFree:", 8)) {
            uint64_t v = parse_kb_value(lp, llen);
            if (v > limit_kb) { rkey = "MemFree:"; rval = limit_kb / 2; }
        } else if (llen >= 13 && !strncmp(lp, "MemAvailable:", 13)) {
            uint64_t v = parse_kb_value(lp, llen);
            if (v > limit_kb) { rkey = "MemAvailable:"; rval = (limit_kb * 3) / 4; }
        }
        if (rkey) {
            if (pos > span_start)
                rc = write_all_fd((int)mfd, b->proc_data + span_start, pos - span_start);
            if (rc >= 0) {
                char line[96];
                size_t n = format_meminfo_line(line, sizeof(line), rkey, rval);
                rc = write_all_fd((int)mfd, line, n);
            }
            span_start = pos + llen;
        }
        pos += llen;
    }
    if (rc >= 0 && total > span_start)
        rc = write_all_fd((int)mfd, b->proc_data + span_start, total - span_start);
    if (rc >= 0) rc = raw_syscall(__NR_lseek, mfd, 0, 0, 0, 0, 0);
    if (rc < 0) {
        raw_syscall(__NR_close, mfd, 0, 0, 0, 0, 0);
        return rc;
    }
    return mfd;
}


static int parse_hex_u64(const char **pp, const char *end, uint64_t *out)
{
    const char *p = *pp;
    uint64_t v = 0;
    int digits = 0;
    while (p < end) {
        char c = *p;
        unsigned d;
        if (c >= '0' && c <= '9') d = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') d = (unsigned)(c - 'A' + 10);
        else break;
        v = (v << 4) | d;
        digits++;
        p++;
    }
    if (!digits) return 0;
    *pp = p;
    *out = v;
    return 1;
}

static size_t append_hex_u64(char *dst, size_t cap, size_t pos, uint64_t v, int min_digits)
{
    static const char hex[] = "0123456789abcdef";
    char tmp[20];
    int d = 0;
    do {
        tmp[d++] = hex[v & 0xfu];
        v >>= 4;
    } while (v && d < 20);
    while (d < min_digits && d < 20)
        tmp[d++] = '0';
    while (d > 0 && pos < cap)
        dst[pos++] = tmp[--d];
    return pos;
}

static size_t format_maps_line(char *dst, size_t cap,
                               uint64_t start, uint64_t end, const char perms[4],
                               uint64_t off, uint64_t dev, uint64_t ino,
                               const char *path)
{
    size_t p = 0;
    p = append_hex_u64(dst, cap, p, start, 8);
    if (p < cap) dst[p++] = '-';
    p = append_hex_u64(dst, cap, p, end, 8);
    if (p < cap) dst[p++] = ' ';
    for (int i = 0; i < 4 && p < cap; i++) dst[p++] = perms[i];
    if (p < cap) dst[p++] = ' ';
    p = append_hex_u64(dst, cap, p, off, 8);
    if (p < cap) dst[p++] = ' ';
    uint32_t maj = (uint32_t)(((dev >> 8) & 0xfffu) | ((dev >> 32) & ~0xfffu));
    uint32_t min = (uint32_t)((dev & 0xffu) | ((dev >> 12) & ~0xffu));
    p = append_hex_u64(dst, cap, p, maj, 2);
    if (p < cap) dst[p++] = ':';
    p = append_hex_u64(dst, cap, p, min, 2);
    if (p < cap) dst[p++] = ' ';
    p = append_u64(dst, cap, p, ino);
    if (path && path[0]) {
        if (p < cap) dst[p++] = ' ';
        while (p < 73 && p < cap) dst[p++] = ' ';
        for (size_t i = 0; path[i] && p < cap; i++) dst[p++] = path[i];
    }
    if (p < cap) dst[p++] = '\n';
    return p;
}

static int path_is_internal_runtime(const char *path, size_t len)
{
    if (!path || !len) return 0;
    if (g_payload_config.loader_path[0]) {
        size_t lp = strlen(g_payload_config.loader_path);
        if (len >= lp && !strncmp(path, g_payload_config.loader_path, lp) &&
            (len == lp || path[lp] == ' '))
            return 1;
    }
    static const char *const suffixes[] = {
        "/.svbox_svc_cache", "/owner.db", "/memfd:mounts", "/memfd:mounts-ns",
        "/memfd:elf-mounts", "/memfd:svbox_net_state",
        "/memfd:svbox-handoff", "/memfd:elf-fd-state",
        "/memfd:broker-channel", "/memfd:guest-auxv"
    };
    for (size_t s = 0; s < sizeof(suffixes) / sizeof(suffixes[0]); s++) {
        size_t sl = strlen(suffixes[s]);
        if (len >= sl) {
            size_t cmp_len = len;
            if (cmp_len > 10 && !strncmp(path + cmp_len - 10, " (deleted)", 10))
                cmp_len -= 10;
            if (cmp_len >= sl && !strncmp(path + cmp_len - sl, suffixes[s], sl))
                return 1;
        }
    }
    return 0;
}

struct maps_writer {
    int fd;
    long rc;
    size_t used;
    char buf[4096];
};

static void maps_flush(struct maps_writer *w)
{
    if (w->rc < 0 || !w->used) return;
    w->rc = write_all_fd(w->fd, w->buf, w->used);
    w->used = 0;
}

static void maps_emit(struct maps_writer *w, const char *data, size_t len)
{
    if (w->rc < 0 || !len) return;
    if (len >= sizeof(w->buf)) {
        maps_flush(w);
        if (w->rc >= 0) w->rc = write_all_fd(w->fd, data, len);
        return;
    }
    if (w->used + len > sizeof(w->buf))
        maps_flush(w);
    if (w->rc < 0) return;
    memcpy(w->buf + w->used, data, len);
    w->used += len;
}

/* Virtualize /proc/<pid>/maps and /proc/<pid>/smaps:
 * - Omit internal runtime mappings (payload, stub islands, shared state).
 * - Restore guest paths/offsets/dev/ino for copied executable file segments.
 * - Translate any remaining host-side mapped file paths into guest paths. */
long pb_proc_maps(Bridge *b, int flags)
{
    if (compare_paths("/proc", b->guest) != PATH1_IS_PREFIX)
        return -ENOENT;
    const char *cursor = b->guest + strlen("/proc/");
    long self_pid = raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
    long pid = 0;
    if (!strncmp(cursor, "self/", 5) || !strncmp(cursor, "thread-self/", 12)) {
        pid = self_pid;
        cursor = strchr(cursor, '/');
    } else {
        if (*cursor < '1' || *cursor > '9') return -ENOENT;
        while (*cursor >= '0' && *cursor <= '9') pid = pid * 10 + (*cursor++ - '0');
    }
    if (!strncmp(cursor, "/task/", 6)) {
        cursor += 6;
        if (*cursor < '1' || *cursor > '9') return -ENOENT;
        while (*cursor >= '0' && *cursor <= '9') cursor++;
    }
    int is_smaps = 0;
    if (!strcmp(cursor, "/maps")) is_smaps = 0;
    else if (!strcmp(cursor, "/smaps")) is_smaps = 1;
    else if (!strcmp(cursor, "/smaps_rollup")) is_smaps = 2;
    else return -ENOENT;

    int is_self = (pid == self_pid);
    int is_hm = platform_is_harmonyos();
    long kfd = raw_syscall(__NR_openat, AT_FDCWD, (long)b->host, O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (kfd < 0) return kfd;

    long mfd = raw_syscall(__NR_memfd_create,
                           (long)(is_smaps == 2 ? "smaps_rollup" : (is_smaps ? "smaps" : "maps")),
                           (flags & O_CLOEXEC) ? 1 : 0, 0, 0, 0, 0);
    if (mfd < 0) {
        raw_syscall(__NR_close, kfd, 0, 0, 0, 0, 0);
        return mfd;
    }

    struct maps_writer w;
    w.fd = (int)mfd;
    w.rc = 0;
    w.used = 0;

    char rbuf[4096];
    char line[1024];
    size_t line_len = 0;
    int skip_smaps_body = 0;
    int exec_copy_smaps = 0;
    uint64_t smaps_rss_kb = 0;
    int eof = 0;

    while (!eof && w.rc >= 0) {
        long nr = raw_syscall(__NR_read, kfd, (long)rbuf, sizeof(rbuf), 0, 0, 0);
        if (nr <= 0) {
            eof = 1;
            if (!line_len) break;
        }
        size_t ri = 0;
        while (w.rc >= 0 && (ri < (size_t)(nr > 0 ? nr : 0) || (eof && line_len > 0))) {
            int got_line = 0;
            if (!eof) {
                while (ri < (size_t)nr) {
                    char ch = rbuf[ri++];
                    if (line_len + 1 < sizeof(line))
                        line[line_len++] = ch;
                    if (ch == '\n') {
                        got_line = 1;
                        break;
                    }
                }
            } else {
                got_line = 1;
            }
            if (!got_line) break;

            if (is_smaps && line_len > 0 && line[0] >= 'A' && line[0] <= 'Z') {
                if (!skip_smaps_body) {
                    if (is_hm && ((line_len >= 8 && !strncmp(line, "Pss_HHP:", 8)) ||
                                  (line_len >= 4 && !strncmp(line, "Purg", 4)))) {
                        /* Omit host-only non-Linux smaps/smaps_rollup metrics. */
                    } else if (exec_copy_smaps) {
                        char sl[96];
                        if (line_len >= 4 && !strncmp(line, "Rss:", 4)) {
                            smaps_rss_kb = parse_kb_value(line, line_len);
                            maps_emit(&w, line, line_len);
                        } else if (line_len >= 14 && !strncmp(line, "Private_Clean:", 14)) {
                            size_t n = format_meminfo_line(sl, sizeof(sl), "Private_Clean:", smaps_rss_kb);
                            maps_emit(&w, sl, n);
                        } else if (line_len >= 14 && !strncmp(line, "Private_Dirty:", 14)) {
                            size_t n = format_meminfo_line(sl, sizeof(sl), "Private_Dirty:", 0);
                            maps_emit(&w, sl, n);
                        } else if (line_len >= 10 && !strncmp(line, "Anonymous:", 10)) {
                            size_t n = format_meminfo_line(sl, sizeof(sl), "Anonymous:", 0);
                            maps_emit(&w, sl, n);
                        } else if (line_len >= 14 && !strncmp(line, "AnonHugePages:", 14)) {
                            size_t n = format_meminfo_line(sl, sizeof(sl), "AnonHugePages:", 0);
                            maps_emit(&w, sl, n);
                        } else if (line_len >= 8 && !strncmp(line, "VmFlags:", 8)) {
                            static const char vf[] = "VmFlags: pr \n";
                            maps_emit(&w, vf, sizeof(vf) - 1);
                        } else {
                            maps_emit(&w, line, line_len);
                        }
                    } else {
                        maps_emit(&w, line, line_len);
                    }
                }
                line_len = 0;
                if (eof) break;
                continue;
            }

            const char *p = line;
            const char *lend = line + line_len;
            uint64_t start = 0, end = 0;
            int header_ok = parse_hex_u64(&p, lend, &start) &&
                            p < lend && *p == '-' && (++p, parse_hex_u64(&p, lend, &end)) &&
                            p + 6 <= lend && *p == ' ';
            if (!header_ok) {
                skip_smaps_body = 0;
                exec_copy_smaps = 0;
                maps_emit(&w, line, line_len);
                line_len = 0;
                if (eof) break;
                continue;
            }

            const char *perms = p + 1;
            const char *q = perms + 4;
            int fields = 0;
            while (q < lend && fields < 3) {
                while (q < lend && (*q == ' ' || *q == '\t')) q++;
                while (q < lend && *q != ' ' && *q != '\t' && *q != '\n') q++;
                fields++;
            }
            const char *ino_end = q;
            while (q < lend && (*q == ' ' || *q == '\t')) q++;
            const char *path_start = q;
            const char *path_end = lend;
            while (path_end > path_start && (path_end[-1] == '\n' || path_end[-1] == '\r'))
                path_end--;
            size_t path_len = (size_t)(path_end - path_start);

            int omit = (is_smaps != 2) &&
                       ((end > start &&
                         (is_self ? hook_protected_overlap((uintptr_t)start, (size_t)(end - start))
                                  : hook_fixed_runtime_overlap((uintptr_t)start, (size_t)(end - start)))) ||
                        path_is_internal_runtime(path_start, path_len));
            if (omit) {
                skip_smaps_body = 1;
                exec_copy_smaps = 0;
                line_len = 0;
                if (eof) break;
                continue;
            }
            skip_smaps_body = 0;
            exec_copy_smaps = 0;
            smaps_rss_kb = 0;

            struct vma_info vma;
            if (is_self && is_smaps != 2 &&
                (path_len == 0 || (path_len >= 7 && !strncmp(path_start, "/memfd:", 7))) &&
                vma_track_lookup((uintptr_t)start, (uintptr_t)end, &vma)) {
                if (is_smaps == 1 && vma.is_exec_copy && perms[1] != 'w')
                    exec_copy_smaps = 1;
                const char *gpath = vma.path;
                if (!vma.is_guest_path) {
                    size_t pl = strlen(vma.path);
                    if (pl < sizeof(b->cwd)) {
                        memcpy(b->cwd, vma.path, pl + 1);
                        if (pb_guest_link_target(b, b->cwd) >= 0)
                            gpath = b->cwd;
                    }
                }
                char out_line[512];
                size_t olen = format_maps_line(out_line, sizeof(out_line),
                                               start, end, perms,
                                               vma.file_off + (start - (uint64_t)vma.start),
                                               vma.dev, vma.ino, gpath);
                maps_emit(&w, out_line, olen);
            } else if (path_len >= 8 && !strncmp(path_start, "/memfd:", 7) &&
                       translate_vdev_or_loop_memfd(path_start, path_len, b->cwd, sizeof(b->cwd))) {
                size_t prefix_len = (size_t)(ino_end - line);
                maps_emit(&w, line, prefix_len);
                size_t col = prefix_len;
                maps_emit(&w, " ", 1);
                col++;
                if (col < 73) {
                    static const char spaces[74] =
                        "                                                                         ";
                    maps_emit(&w, spaces, 73 - col);
                }
                maps_emit(&w, b->cwd, strlen(b->cwd));
                maps_emit(&w, "\n", 1);
            } else if (path_len > 0 && path_start[0] == '/' && path_len < sizeof(b->cwd) - 16) {
                int deleted = (path_len > 10 && !strncmp(path_end - 10, " (deleted)", 10));
                size_t core_len = deleted ? (path_len - 10) : path_len;
                memcpy(b->cwd, path_start, core_len);
                b->cwd[core_len] = '\0';
                if (pb_guest_link_target(b, b->cwd) >= 0 &&
                    (strlen(b->cwd) != core_len || strncmp(b->cwd, path_start, core_len) != 0)) {
                    size_t prefix_len = (size_t)(ino_end - line);
                    maps_emit(&w, line, prefix_len);
                    size_t col = prefix_len;
                    maps_emit(&w, " ", 1);
                    col++;
                    if (col < 73) {
                        static const char spaces[74] =
                            "                                                                         ";
                        maps_emit(&w, spaces, 73 - col);
                    }
                    maps_emit(&w, b->cwd, strlen(b->cwd));
                    if (deleted)
                        maps_emit(&w, " (deleted)", 10);
                    maps_emit(&w, "\n", 1);
                } else {
                    maps_emit(&w, line, line_len);
                }
            } else if (platform_is_harmonyos() && path_len > 0 && path_start[0] == '[' &&
                       ((path_len == 8 && !strncmp(path_start, "[kshare]", 8)) ||
                        (path_len == 6 && !strncmp(path_start, "[shmm]", 6)))) {
                const char *vname = (path_len == 8) ? "[vvar]" : "[vdso]";
                size_t prefix_len = (size_t)(path_start - line);
                maps_emit(&w, line, prefix_len);
                maps_emit(&w, vname, 6);
                maps_emit(&w, "\n", 1);
            } else {
                maps_emit(&w, line, line_len);
            }
            line_len = 0;
            if (eof) break;
        }
    }

    maps_flush(&w);
    raw_syscall(__NR_close, kfd, 0, 0, 0, 0, 0);
    if (w.rc >= 0) w.rc = raw_syscall(__NR_lseek, mfd, 0, 0, 0, 0, 0);
    if (w.rc < 0) {
        raw_syscall(__NR_close, mfd, 0, 0, 0, 0, 0);
        return w.rc;
    }
    return mfd;
}

static size_t append_str(char *dst, size_t cap, size_t pos, const char *s)
{
    while (*s && pos < cap)
        dst[pos++] = *s++;
    return pos;
}

static const char *proc_net_leaf(const char *guest)
{
    if (!guest || strncmp(guest, "/proc/", 6) != 0)
        return NULL;
    if (!strncmp(guest + 6, "net/", 4))
        return guest + 10;
    long self_pid = raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
    long pid = 0;
    const char *sub = parse_proc_pid_subpath(guest, self_pid, &pid);
    if (sub && !strncmp(sub, "/net/", 5))
        return sub + 5;
    return NULL;
}

static uint32_t g_proc_denied_mask;

/* Generic Linux /proc fallback when the host sandbox denies read access (-EACCES/-EPERM)
 * to standard global procfs nodes (/proc/version, /proc/uptime, /proc/loadavg, /proc/stat,
 * /proc/cmdline, /proc/modules, /proc/swaps, /proc/net/{tcp,tcp6,udp,udp6,unix,arp}).
 * On hosts where these nodes are readable, the real host fd is returned. */
long pb_proc_fallback(Bridge *b, int flags)
{
    int kind = 0;
    if (!strcmp(b->guest, "/proc/version")) kind = 1;
    else if (!strcmp(b->guest, "/proc/uptime")) kind = 2;
    else if (!strcmp(b->guest, "/proc/loadavg")) kind = 3;
    else if (!strcmp(b->guest, "/proc/stat")) kind = 4;
    else if (!strcmp(b->guest, "/proc/cmdline")) kind = 5;
    else if (!strcmp(b->guest, "/proc/modules")) kind = 6;
    else if (!strcmp(b->guest, "/proc/swaps")) kind = 7;
    else {
        const char *nl = proc_net_leaf(b->guest);
        if (nl) {
            if (!strcmp(nl, "tcp") || !strcmp(nl, "tcp6")) kind = 8;
            else if (!strcmp(nl, "udp") || !strcmp(nl, "udp6")) kind = 9;
            else if (!strcmp(nl, "unix")) kind = 10;
            else if (!strcmp(nl, "arp")) kind = 11;
        }
    }
    if (!kind)
        return -ENOENT;

    /* Explicit --proc-cmdline always takes precedence over host /proc/cmdline. */
    int skip_host = (kind == 5 && g_payload_config.proc_cmdline[0] != '\0');
    uint32_t kbit = 1u << (unsigned)kind;
    if (!skip_host && !(__atomic_load_n(&g_proc_denied_mask, __ATOMIC_ACQUIRE) & kbit)) {
        long hfd = raw_syscall(__NR_openat, AT_FDCWD, (long)b->host, flags, 0, 0, 0);
        if (hfd >= 0 || (hfd != -EACCES && hfd != -EPERM))
            return hfd;
        __atomic_fetch_or(&g_proc_denied_mask, kbit, __ATOMIC_RELEASE);
    }

    char buf[4096];
    size_t p = 0;
    const size_t cap = sizeof(buf);
    uint32_t ncpus = g_payload_config.cpu_mask ? popcount64(g_payload_config.cpu_mask) : 1;
    if (!ncpus) ncpus = 1;
    if (ncpus > 32) ncpus = 32;

    if (kind == 1) {
        struct { char sysname[65], nodename[65], release[65], version[65], machine[65], domain[65]; } u;
        memset(&u, 0, sizeof(u));
        raw_syscall(__NR_uname, (long)&u, 0, 0, 0, 0, 0);
        const char *sys = g_payload_config.kernel_sysname[0] ? g_payload_config.kernel_sysname
                          : (u.sysname[0] ? u.sysname : "Linux");
        const char *rel = g_payload_config.kernel_release[0] ? g_payload_config.kernel_release
                          : (u.release[0] ? u.release : "6.1.0");
        const char *ver = u.version[0] ? u.version : "#1 SMP PREEMPT";
        p = append_str(buf, cap, p, sys);
        p = append_str(buf, cap, p, " version ");
        p = append_str(buf, cap, p, rel);
        p = append_str(buf, cap, p, " (root@localhost) ");
        p = append_str(buf, cap, p, ver);
        p = append_str(buf, cap, p, "\n");
    } else if (kind == 2) {
        struct { long tv_sec; long tv_nsec; } ts = { 0, 0 };
        raw_syscall(__NR_clock_gettime, 7 /* CLOCK_BOOTTIME */, (long)&ts, 0, 0, 0, 0);
        uint64_t sec = ts.tv_sec > 0 ? (uint64_t)ts.tv_sec : 1;
        uint64_t cs = ts.tv_nsec >= 0 ? (uint64_t)(ts.tv_nsec / 10000000L) : 0;
        if (cs > 99) cs = 99;
        p = append_u64(buf, cap, p, sec);
        p = append_str(buf, cap, p, ".");
        if (cs < 10 && p < cap) buf[p++] = '0';
        p = append_u64(buf, cap, p, cs);
        p = append_str(buf, cap, p, " ");
        p = append_u64(buf, cap, p, sec * (uint64_t)ncpus);
        p = append_str(buf, cap, p, ".");
        if (cs < 10 && p < cap) buf[p++] = '0';
        p = append_u64(buf, cap, p, cs);
        p = append_str(buf, cap, p, "\n");
    } else if (kind == 3) {
        p = append_str(buf, cap, p, "0.10 0.08 0.05 1/64 1\n");
    } else if (kind == 4) {
        struct { long tv_sec; long tv_nsec; } rt = { 0, 0 }, bt = { 0, 0 };
        raw_syscall(__NR_clock_gettime, 0 /* CLOCK_REALTIME */, (long)&rt, 0, 0, 0, 0);
        raw_syscall(__NR_clock_gettime, 7 /* CLOCK_BOOTTIME */, (long)&bt, 0, 0, 0, 0);
        uint64_t btime = (rt.tv_sec > bt.tv_sec && rt.tv_sec > 0) ? (uint64_t)(rt.tv_sec - bt.tv_sec) : 1700000000ull;
        uint64_t total_cs = (bt.tv_sec > 0 ? (uint64_t)bt.tv_sec * 100ull : 100ull) +
                            (bt.tv_nsec >= 0 ? (uint64_t)(bt.tv_nsec / 10000000L) : 0ull);
        if (total_cs < 100ull) total_cs = 100ull;
        uint64_t sum_user = 0, sum_nice = 0, sum_sys = 0, sum_idle = 0, sum_iow = 0;
        for (uint32_t i = 0; i < ncpus; i++) {
            uint64_t u_i = (total_cs * (6ull + (i & 3u))) / 100ull;
            uint64_t n_i = total_cs / 200ull;
            uint64_t s_i = (total_cs * (3ull + (i & 1u))) / 100ull;
            uint64_t w_i = total_cs / 500ull;
            uint64_t id_i = (total_cs > u_i + n_i + s_i + w_i) ? (total_cs - u_i - n_i - s_i - w_i) : 1ull;
            sum_user += u_i; sum_nice += n_i; sum_sys += s_i; sum_idle += id_i; sum_iow += w_i;
        }
        p = append_str(buf, cap, p, "cpu  ");
        p = append_u64(buf, cap, p, sum_user); p = append_str(buf, cap, p, " ");
        p = append_u64(buf, cap, p, sum_nice); p = append_str(buf, cap, p, " ");
        p = append_u64(buf, cap, p, sum_sys);  p = append_str(buf, cap, p, " ");
        p = append_u64(buf, cap, p, sum_idle); p = append_str(buf, cap, p, " ");
        p = append_u64(buf, cap, p, sum_iow);  p = append_str(buf, cap, p, " 0 0 0 0 0\n");
        for (uint32_t i = 0; i < ncpus; i++) {
            uint64_t u_i = (total_cs * (6ull + (i & 3u))) / 100ull;
            uint64_t n_i = total_cs / 200ull;
            uint64_t s_i = (total_cs * (3ull + (i & 1u))) / 100ull;
            uint64_t w_i = total_cs / 500ull;
            uint64_t id_i = (total_cs > u_i + n_i + s_i + w_i) ? (total_cs - u_i - n_i - s_i - w_i) : 1ull;
            p = append_str(buf, cap, p, "cpu");
            p = append_u32(buf, cap, p, i);
            p = append_str(buf, cap, p, " ");
            p = append_u64(buf, cap, p, u_i);  p = append_str(buf, cap, p, " ");
            p = append_u64(buf, cap, p, n_i);  p = append_str(buf, cap, p, " ");
            p = append_u64(buf, cap, p, s_i);  p = append_str(buf, cap, p, " ");
            p = append_u64(buf, cap, p, id_i); p = append_str(buf, cap, p, " ");
            p = append_u64(buf, cap, p, w_i);  p = append_str(buf, cap, p, " 0 0 0 0 0\n");
        }
        p = append_str(buf, cap, p, "intr ");
        p = append_u64(buf, cap, p, total_cs * 47ull);
        p = append_str(buf, cap, p, "\nctxt ");
        p = append_u64(buf, cap, p, total_cs * 113ull);
        p = append_str(buf, cap, p, "\nbtime ");
        p = append_u64(buf, cap, p, btime);
        p = append_str(buf, cap, p, "\nprocesses ");
        p = append_u64(buf, cap, p, 64ull + (total_cs / 100ull));
        p = append_str(buf, cap, p, "\nprocs_running 1\nprocs_blocked 0\nsoftirq ");
        p = append_u64(buf, cap, p, total_cs * 19ull);
        p = append_str(buf, cap, p, " 0 ");
        p = append_u64(buf, cap, p, total_cs * 9ull);
        p = append_str(buf, cap, p, " 0 0 0 0 ");
        p = append_u64(buf, cap, p, total_cs * 5ull);
        p = append_str(buf, cap, p, " 0 ");
        p = append_u64(buf, cap, p, total_cs * 5ull);
        p = append_str(buf, cap, p, " 0\n");
    } else if (kind == 5) {
        const char *cmd = g_payload_config.proc_cmdline[0]
            ? g_payload_config.proc_cmdline
            : "console=ttyS0 root=/dev/root rw";
        p = append_str(buf, cap, p, cmd);
        p = append_str(buf, cap, p, "\n");
    } else if (kind == 6) {
        /* Empty readable /proc/modules */
    } else if (kind == 7) {
        p = append_str(buf, cap, p, "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n");
    } else if (kind == 8) {
        p = append_str(buf, cap, p,
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     \n");
    } else if (kind == 9) {
        p = append_str(buf, cap, p,
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops             \n");
    } else if (kind == 10) {
        p = append_str(buf, cap, p, "Num       RefCount Protocol Flags    Type St Inode Path\n");
    } else {
        p = append_str(buf, cap, p,
            "IP address       HW type     Flags       HW address            Mask     Device\n");
    }

    long mfd = raw_syscall(__NR_memfd_create, (long)"procfs",
                           (flags & O_CLOEXEC) ? 1 : 0, 0, 0, 0, 0);
    if (mfd < 0)
        return mfd;
    long rc = p > 0 ? write_all_fd((int)mfd, buf, p) : 0;
    if (rc >= 0) rc = raw_syscall(__NR_lseek, mfd, 0, 0, 0, 0, 0);
    if (rc < 0) {
        raw_syscall(__NR_close, mfd, 0, 0, 0, 0, 0);
        return rc;
    }
    return mfd;
}

/* ---- Virtualized procfs/sysfs memfd tracking ---- */
#define VFD_MAX 256u
struct vfd_slot {
    int fd;
    uint8_t is_procfs;
    char path[128];
};
static struct vfd_slot g_vfds[VFD_MAX];
static unsigned g_vfd_active;
static int g_vfd_lock;

static inline void vfd_lock(void)
{
    while (__atomic_test_and_set(&g_vfd_lock, __ATOMIC_ACQUIRE))
        raw_syscall(__NR_sched_yield, 0, 0, 0, 0, 0, 0);
}
static inline void vfd_unlock(void)
{
    __atomic_clear(&g_vfd_lock, __ATOMIC_RELEASE);
}

void pb_vfd_record(int fd, const char *guest_path)
{
    if (fd < 0 || !guest_path || !guest_path[0])
        return;
    char norm[128];
    if (!strncmp(guest_path, "/proc/self/", 11)) {
        format_proc(norm, current_id(__NR_getpid), 0);
        size_t bl = strlen(norm);
        size_t tl = strlen(guest_path + 10);
        if (bl + tl < sizeof(norm))
            memcpy(norm + bl, guest_path + 10, tl + 1);
    } else if (!strncmp(guest_path, "/proc/thread-self/", 18)) {
        format_proc(norm, current_id(__NR_getpid), current_id(__NR_gettid));
        size_t bl = strlen(norm);
        size_t tl = strlen(guest_path + 17);
        if (bl + tl < sizeof(norm))
            memcpy(norm + bl, guest_path + 17, tl + 1);
    } else {
        size_t l = strlen(guest_path);
        if (l >= sizeof(norm)) l = sizeof(norm) - 1;
        memcpy(norm, guest_path, l);
        norm[l] = '\0';
    }
    uint8_t is_proc = (!strncmp(norm, "/proc/", 6)) ? 1 : 0;

    vfd_lock();
    int free_idx = -1;
    for (unsigned i = 0; i < VFD_MAX; i++) {
        if (g_vfds[i].path[0] && g_vfds[i].fd == fd) {
            g_vfds[i].is_procfs = is_proc;
            strcpy(g_vfds[i].path, norm);
            vfd_unlock();
            return;
        }
        if (!g_vfds[i].path[0] && free_idx < 0)
            free_idx = (int)i;
    }
    if (free_idx >= 0) {
        g_vfds[free_idx].fd = fd;
        g_vfds[free_idx].is_procfs = is_proc;
        strcpy(g_vfds[free_idx].path, norm);
        __atomic_fetch_add(&g_vfd_active, 1u, __ATOMIC_RELEASE);
    }
    vfd_unlock();
}

void proot_vfd_close(int fd)
{
    if (fd < 0 || !__atomic_load_n(&g_vfd_active, __ATOMIC_ACQUIRE))
        return;
    vfd_lock();
    for (unsigned i = 0; i < VFD_MAX; i++) {
        if (g_vfds[i].path[0] && g_vfds[i].fd == fd) {
            g_vfds[i].path[0] = '\0';
            g_vfds[i].fd = -1;
            __atomic_fetch_sub(&g_vfd_active, 1u, __ATOMIC_RELEASE);
            break;
        }
    }
    vfd_unlock();
}

void proot_vfd_dup(int oldfd, int newfd)
{
    if (oldfd < 0 || newfd < 0 || oldfd == newfd)
        return;
    if (!__atomic_load_n(&g_vfd_active, __ATOMIC_ACQUIRE))
        return;
    char copy[128];
    copy[0] = '\0';
    vfd_lock();
    for (unsigned i = 0; i < VFD_MAX; i++) {
        if (g_vfds[i].path[0] && g_vfds[i].fd == oldfd) {
            strcpy(copy, g_vfds[i].path);
            break;
        }
    }
    vfd_unlock();
    if (copy[0])
        pb_vfd_record(newfd, copy);
    else
        proot_vfd_close(newfd);
}

int pb_vfd_guest_path(int fd, char *out, size_t cap)
{
    if (fd < 0 || !out || !cap || !__atomic_load_n(&g_vfd_active, __ATOMIC_ACQUIRE))
        return -1;
    vfd_lock();
    for (unsigned i = 0; i < VFD_MAX; i++) {
        if (g_vfds[i].path[0] && g_vfds[i].fd == fd) {
            size_t l = strlen(g_vfds[i].path);
            if (l >= cap) l = cap - 1;
            memcpy(out, g_vfds[i].path, l);
            out[l] = '\0';
            vfd_unlock();
            return 0;
        }
    }
    vfd_unlock();
    return -1;
}

void proot_vfd_fix_fstat(int fd, void *stat_buf)
{
    if (fd < 0 || !stat_buf || !__atomic_load_n(&g_vfd_active, __ATOMIC_ACQUIRE))
        return;
    int is_proc = 0;
    vfd_lock();
    for (unsigned i = 0; i < VFD_MAX; i++) {
        if (g_vfds[i].path[0] && g_vfds[i].fd == fd) {
            is_proc = g_vfds[i].is_procfs;
            break;
        }
    }
    vfd_unlock();
    if (!is_proc)
        return;
    struct stat *st = (struct stat *)stat_buf;
    st->st_mode = (st->st_mode & ~07777u) | 0444u;
    st->st_size = 0;
    st->st_blocks = 0;
}

int proot_vfd_is_procfs(int fd)
{
    if (fd < 0 || !__atomic_load_n(&g_vfd_active, __ATOMIC_ACQUIRE))
        return 0;
    int is_proc = 0;
    vfd_lock();
    for (unsigned i = 0; i < VFD_MAX; i++) {
        if (g_vfds[i].path[0] && g_vfds[i].fd == fd) {
            is_proc = g_vfds[i].is_procfs;
            break;
        }
    }
    vfd_unlock();
    return is_proc;
}

static int proc_pid_is_container(const char *pid_str, long self_pid, const char *loader, size_t loader_len)
{
    long pid = 0;
    for (const char *p = pid_str; *p; p++)
        pid = pid * 10 + (*p - '0');
    if (pid == self_pid)
        return 1;

    char path[64];
    size_t pl = strlen(pid_str);
    if (6 + pl + 9 >= sizeof(path))
        return 0;
    memcpy(path, "/proc/", 6);
    memcpy(path + 6, pid_str, pl);
    memcpy(path + 6 + pl, "/cmdline", 9);

    long cfd = raw_syscall(__NR_openat, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (cfd < 0)
        return 0;
    char cbuf[CONFIG_MAX_PATH + 4];
    size_t want = loader_len + 1;
    if (want > sizeof(cbuf)) want = sizeof(cbuf);
    long n = raw_syscall(__NR_read, cfd, (long)cbuf, (long)want, 0, 0, 0);
    raw_syscall(__NR_close, cfd, 0, 0, 0, 0, 0);
    return n >= (long)(loader_len + 1) && cbuf[loader_len] == '\0' &&
           !strncmp(cbuf, loader, loader_len);
}

/* Parse /proc/(self|thread-self|<pid>)(/task/<tid>)?/map_files(/<lo>-<hi>)?
 * Returns: 0 = not map_files, 1 = map_files dir itself, 2 = map_files/<entry>. */
static int parse_proc_map_files(const char *path, int *is_self_out,
                                int *has_range_out, uint64_t *lo_out, uint64_t *hi_out)
{
    if (!path || strncmp(path, "/proc/", 6) != 0)
        return 0;
    const char *cur = path + 6;
    long self_pid = current_id(__NR_getpid);
    long pid = 0;
    if (!strncmp(cur, "self/", 5)) {
        pid = self_pid;
        cur += 4;
    } else if (!strncmp(cur, "thread-self/", 12)) {
        pid = self_pid;
        cur += 11;
    } else {
        if (*cur < '1' || *cur > '9') return 0;
        while (*cur >= '0' && *cur <= '9') pid = pid * 10 + (*cur++ - '0');
    }
    if (!strncmp(cur, "/task/", 6)) {
        cur += 6;
        if (*cur < '1' || *cur > '9') return 0;
        while (*cur >= '0' && *cur <= '9') cur++;
    }
    if (strncmp(cur, "/map_files", 10) != 0)
        return 0;
    cur += 10;
    if (is_self_out) *is_self_out = (pid == self_pid);
    if (has_range_out) *has_range_out = 0;
    if (*cur == '\0' || (*cur == '/' && cur[1] == '\0'))
        return 1;
    if (*cur != '/')
        return 0;
    cur++;
    const char *end = cur + strlen(cur);
    const char *p = cur;
    uint64_t lo = 0, hi = 0;
    if (parse_hex_u64(&p, end, &lo) && p < end && *p == '-' &&
        (++p, parse_hex_u64(&p, end, &hi)) && p == end) {
        if (has_range_out) *has_range_out = 1;
        if (lo_out) *lo_out = lo;
        if (hi_out) *hi_out = hi;
    }
    return 2;
}

static int proc_map_files_capable(void)
{
    if (!g_payload_config.fake_ids)
        return 1;
    return fake_ids_capable(21 /* CAP_SYS_ADMIN */) ||
           fake_ids_capable(40 /* CAP_CHECKPOINT_RESTORE */);
}

/* Enforce Linux /proc/<pid>/map_files capability checks (CAP_SYS_ADMIN /
 * CAP_CHECKPOINT_RESTORE) and hide internal runtime mappings + translate
 * vma_track / host paths for privileged callers. */
int pb_proc_map_files_guard(Bridge *b, long number, long a[6], long *out_rc)
{
    int is_self = 0, has_range = 0;
    uint64_t lo = 0, hi = 0;
    int kind = parse_proc_map_files(b->guest, &is_self, &has_range, &lo, &hi);
    if (kind != 2)
        return 0;
    if (!proc_map_files_capable()) {
        *out_rc = -EPERM;
        return 1;
    }
    if (has_range && hi > lo) {
        int hidden = is_self
            ? hook_protected_overlap((uintptr_t)lo, (size_t)(hi - lo))
            : hook_fixed_runtime_overlap((uintptr_t)lo, (size_t)(hi - lo));
        if (hidden) {
            *out_rc = -ENOENT;
            return 1;
        }
    }
    if (number == __NR_readlinkat) {
        if (!a[2]) {
            *out_rc = -EFAULT;
            return 1;
        }
        struct vma_info vma;
        if (is_self && has_range && hi > lo &&
            vma_track_lookup((uintptr_t)lo, (uintptr_t)hi, &vma)) {
            const char *gpath = vma.path;
            if (!vma.is_guest_path) {
                size_t pl = strlen(vma.path);
                if (pl < sizeof(b->cwd)) {
                    memcpy(b->cwd, vma.path, pl + 1);
                    if (pb_guest_link_target(b, b->cwd) >= 0)
                        gpath = b->cwd;
                }
            }
            long count = (long)strlen(gpath);
            if ((unsigned long)a[3] < (unsigned long)count)
                count = (long)a[3];
            memcpy((void *)a[2], gpath, (size_t)count);
            *out_rc = count;
            return 1;
        }
        long count = pb_host_readlink(b, b->host, b->cwd, sizeof(b->cwd) - 1);
        if (count < 0) {
            *out_rc = count;
            return 1;
        }
        b->cwd[count] = '\0';
        if (path_is_internal_runtime(b->cwd, (size_t)count)) {
            *out_rc = -ENOENT;
            return 1;
        }
        if (translate_vdev_or_loop_memfd(b->cwd, (size_t)count, b->proc_candidate,
                                         sizeof(b->proc_candidate))) {
            strcpy(b->cwd, b->proc_candidate);
        } else {
            int rc = pb_guest_link_target(b, b->cwd);
            if (rc < 0) {
                *out_rc = rc;
                return 1;
            }
        }
        count = (long)strlen(b->cwd);
        if ((unsigned long)a[3] < (unsigned long)count)
            count = (long)a[3];
        memcpy((void *)a[2], b->cwd, (size_t)count);
        *out_rc = count;
        return 1;
    }
    /* For openat/stat/access on privileged map_files/<entry>: still hide internal runtime files. */
    long n = pb_host_readlink(b, b->host, b->cwd, sizeof(b->cwd) - 1);
    if (n > 0) {
        b->cwd[n] = '\0';
        if (path_is_internal_runtime(b->cwd, (size_t)n)) {
            *out_rc = -ENOENT;
            return 1;
        }
    }
    return 0;
}

/* Filter /proc root directory listings and /proc/<pid>/map_files in container mode:
 * - /proc: hide host/sibling non-container processes sharing the same host UID.
 * - /proc/<pid>/map_files: enforce CAP_SYS_ADMIN/CAP_CHECKPOINT_RESTORE (-EPERM)
 *   and omit internal runtime mappings for privileged callers. */
long proot_proc_filter_pids(int fd, void *buffer, long length)
{
    if (g_payload_config.mode != CONFIG_MODE_CONTAINER || !buffer || length <= 0)
        return length;

    unsigned long fs[16];
    if (raw_syscall(__NR_fstatfs, fd, (long)fs, 0, 0, 0, 0) ||
        (unsigned)fs[0] != 0x9fa0 /* PROC_SUPER_MAGIC */)
        return length;

    char fdlink[32];
    memcpy(fdlink, "/proc/self/fd/", 14);
    size_t fp = append_u32(fdlink, sizeof(fdlink) - 1, 14, (uint32_t)fd);
    fdlink[fp] = '\0';
    char target[96];
    long tlen = raw_syscall(__NR_readlinkat, AT_FDCWD, (long)fdlink,
                            (long)target, (long)(sizeof(target) - 1), 0, 0);
    if (tlen < 5)
        return length;
    target[tlen] = '\0';

    int is_self_mf = 0;
    if (parse_proc_map_files(target, &is_self_mf, NULL, NULL, NULL) == 1) {
        if (!proc_map_files_capable()) {
            memset(buffer, 0, (size_t)length);
            return -EPERM;
        }
        unsigned char *bytes = (unsigned char *)buffer;
        long kept = 0;
        for (long at = 0; at < length;) {
            unsigned short size;
            memcpy(&size, bytes + at + 16, sizeof(size));
            if (size < 20 || at + size > length)
                return length;
            const char *name = (const char *)bytes + at + 19;
            int keep = 1;
            if (strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
                const char *p = name;
                const char *end = name + strlen(name);
                uint64_t lo = 0, hi = 0;
                if (parse_hex_u64(&p, end, &lo) && p < end && *p == '-' &&
                    (++p, parse_hex_u64(&p, end, &hi)) && p == end && hi > lo) {
                    if (is_self_mf ? hook_protected_overlap((uintptr_t)lo, (size_t)(hi - lo))
                                   : hook_fixed_runtime_overlap((uintptr_t)lo, (size_t)(hi - lo)))
                        keep = 0;
                }
                if (keep) {
                    char lbuf[256];
                    long ln = raw_syscall(__NR_readlinkat, fd, (long)name,
                                          (long)lbuf, (long)(sizeof(lbuf) - 1), 0, 0);
                    if (ln > 0) {
                        lbuf[ln] = '\0';
                        if (path_is_internal_runtime(lbuf, (size_t)ln))
                            keep = 0;
                    }
                }
            }
            if (keep) {
                if (kept != at)
                    memmove(bytes + kept, bytes + at, size);
                kept += size;
            }
            at += size;
        }
        return kept;
    }

    if (!g_payload_config.loader_path[0] || tlen != 5 || strcmp(target, "/proc") != 0)
        return length;

    const char *loader = g_payload_config.loader_path;
    size_t loader_len = strlen(loader);
    long self_pid = current_id(__NR_getpid);

    unsigned char *bytes = (unsigned char *)buffer;
    long kept = 0;
    for (long at = 0; at < length;) {
        unsigned short size;
        memcpy(&size, bytes + at + 16, sizeof(size));
        if (size < 20 || at + size > length)
            return length;
        unsigned char type = bytes[at + 18];
        const char *name = (const char *)bytes + at + 19;
        int is_pid_dir = 0;
        if ((type == 4 /* DT_DIR */ || type == 0 /* DT_UNKNOWN */) &&
            name[0] >= '1' && name[0] <= '9') {
            is_pid_dir = 1;
            for (const char *p = name + 1; *p; p++) {
                if (*p < '0' || *p > '9') { is_pid_dir = 0; break; }
            }
        }
        int keep = 1;
        if (is_pid_dir)
            keep = proc_pid_is_container(name, self_pid, loader, loader_len);
        if (keep) {
            if (kept != at)
                memmove(bytes + kept, bytes + at, size);
            kept += size;
        }
        at += size;
    }
    return kept;
}
