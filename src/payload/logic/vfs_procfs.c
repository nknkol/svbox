/* SPDX-License-Identifier: MIT */
/* PRoot path backend, /proc: links of loader-run processes (exe, cwd,
 * fd), their cmdline, readlink of /proc names, and the mount tables
 * generated from the R4 table. */
#include "vfs_bridge_internal.h"
#include "hook_runtime.h"

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
        /* Not emulated, or a kept magic link: the kernel's own answer,
         * with an absolute target reported in guest terms. */
        *slash = '/';
        count = pb_host_readlink(b, b->host, b->cwd, sizeof(b->cwd) - 1);
        if (count < 0) return count;
        b->cwd[count] = 0;
        int rc = pb_guest_link_target(b, b->cwd);
        if (rc < 0) return rc;
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

    long rc = 0;
    size_t pos = 0;
    size_t span_start = 0;
    while (pos < total && rc >= 0) {
        size_t nl = pos;
        while (nl < total && b->proc_data[nl] != '\n') nl++;
        size_t line_len = (nl < total) ? (nl - pos + 1) : (nl - pos);
        int is_uid = (line_len >= 4 && !strncmp(b->proc_data + pos, "Uid:", 4));
        int is_gid = (!is_uid && line_len >= 4 && !strncmp(b->proc_data + pos, "Gid:", 4));
        int hide_sec = (g_payload_config.seccomp_backstop || g_payload_config.trap_sigsys);
        int is_seccomp = (!is_uid && !is_gid && hide_sec &&
                          line_len >= 8 && !strncmp(b->proc_data + pos, "Seccomp:", 8));
        int is_secfilt = (!is_uid && !is_gid && !is_seccomp && hide_sec &&
                          line_len >= 16 && !strncmp(b->proc_data + pos, "Seccomp_filters:", 16));
        if (is_uid || is_gid || is_seccomp || is_secfilt) {
            if (pos > span_start) {
                size_t wdone = 0, wlen = pos - span_start;
                while (wdone < wlen) {
                    long w = raw_syscall(__NR_write, mfd, (long)(b->proc_data + span_start + wdone),
                                         (long)(wlen - wdone), 0, 0, 0);
                    if (w <= 0) { rc = w ? w : -EIO; break; }
                    wdone += (size_t)w;
                }
            }
            if (rc >= 0) {
                char line[128];
                size_t llen = 0;
                if (is_uid || is_gid) {
                    llen = format_id_line(line, sizeof(line),
                                          is_uid ? "Uid:" : "Gid:",
                                          is_uid ? ids : (ids + 4));
                } else if (is_seccomp) {
                    const char *s = "Seccomp:\t0\n";
                    llen = strlen(s);
                    memcpy(line, s, llen);
                } else {
                    const char *s = "Seccomp_filters:\t0\n";
                    llen = strlen(s);
                    memcpy(line, s, llen);
                }
                size_t wdone = 0;
                while (wdone < llen) {
                    long w = raw_syscall(__NR_write, mfd, (long)(line + wdone),
                                         (long)(llen - wdone), 0, 0, 0);
                    if (w <= 0) { rc = w ? w : -EIO; break; }
                    wdone += (size_t)w;
                }
            }
            span_start = pos + line_len;
        }
        pos += line_len;
    }
    if (rc >= 0 && total > span_start) {
        size_t wdone = 0, wlen = total - span_start;
        while (wdone < wlen) {
            long w = raw_syscall(__NR_write, mfd, (long)(b->proc_data + span_start + wdone),
                                 (long)(wlen - wdone), 0, 0, 0);
            if (w <= 0) { rc = w ? w : -EIO; break; }
            wdone += (size_t)w;
        }
    }
    if (rc >= 0) rc = raw_syscall(__NR_lseek, mfd, 0, 0, 0, 0, 0);
    if (rc < 0) {
        raw_syscall(__NR_close, mfd, 0, 0, 0, 0, 0);
        return rc;
    }
    return mfd;
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
        "/.svbox_svc_cache", "/owner.db", "/memfd:mounts", "/memfd:mounts-ns"
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
    else return -ENOENT;

    int is_self = (pid == self_pid);
    long kfd = raw_syscall(__NR_openat, AT_FDCWD, (long)b->host, O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (kfd < 0) return kfd;

    long mfd = raw_syscall(__NR_memfd_create, (long)(is_smaps ? "smaps" : "maps"),
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
                if (!skip_smaps_body)
                    maps_emit(&w, line, line_len);
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

            if ((is_self && end > start && hook_protected_overlap((uintptr_t)start, (size_t)(end - start))) ||
                path_is_internal_runtime(path_start, path_len)) {
                skip_smaps_body = 1;
                line_len = 0;
                if (eof) break;
                continue;
            }
            skip_smaps_body = 0;

            struct vma_info vma;
            if (is_self &&
                (path_len == 0 || (path_len >= 7 && !strncmp(path_start, "/memfd:", 7))) &&
                vma_track_lookup((uintptr_t)start, (uintptr_t)end, &vma)) {
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
