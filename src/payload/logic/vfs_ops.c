/* SPDX-License-Identifier: MIT */
/* VFS syscall dispatch: path mutations, R5 ownership/mode emulation,
 * AF_UNIX/AF_INET socket address translation, and main pb_dispatch(). */
#include "vfs_bridge_internal.h"
#include "vdev.h"
#include "net_stack.h"

int proot_handles_syscall(long number)
{
    switch (number) {
    case __NR_mount:
    case __NR_umount2:
        return mounts_enabled();
    case __NR_setxattr: case __NR_lsetxattr:
    case __NR_getxattr: case __NR_lgetxattr:
    case __NR_listxattr: case __NR_llistxattr:
    case __NR_removexattr: case __NR_lremovexattr:
    case __NR_inotify_add_watch:
    case __NR_bind: case __NR_connect: case __NR_sendto: case __NR_sendmsg:
    case __NR_fchmodat:
    case __NR_fchownat:
    case __NR_utimensat:
    case __NR_fchmod:
    case __NR_fchown:
    case __NR_statfs:
    case __NR_fstatfs:
    case __NR_mknodat:
    case __NR_truncate:
    case __NR_ftruncate:
    case __NR_mkdirat:
    case __NR_unlinkat:
    case __NR_symlinkat:
    case __NR_linkat:
    case __NR_renameat:
    case __NR_renameat2:
    case __NR_openat:
    case __NR_newfstatat:
    case __NR_statx:
    case __NR_readlinkat:
    case __NR_chdir:
    case __NR_fchdir:
    case __NR_getcwd:
    case __NR_faccessat:
    case __NR_faccessat2:
        return 1;
    default:
        return 0;
    }
}

/* Identity-root fast check: --root "/" with zero binds, zero dynamic mounts,
 * no union, no guard, no owner DB, and a lexical absolute path outside /proc,
 * /dev, /sys. Such paths have guest == host identically. */
static inline bool is_special_prefix(const char *p)
{
    if (p[1] == 'p' && p[2] == 'r' && p[3] == 'o' && p[4] == 'c' && (!p[5] || p[5] == '/'))
        return true;
    if (p[1] == 'd' && p[2] == 'e' && p[3] == 'v' && (!p[4] || p[4] == '/'))
        return true;
    if (p[1] == 's' && p[2] == 'y' && p[3] == 's' && (!p[4] || p[4] == '/'))
        return true;
    return false;
}

static inline bool identity_fast_path(const Bridge *b, const char *path)
{
    return b->table.count == 0 && b->table.root[0] == '/' && b->table.root[1] == '\0' &&
           !b->union_on && g_payload_config.guard == GUARD_NONE && !owners_enabled() &&
           path && path[0] == '/' && path[1] != '\0' &&
           !is_special_prefix(path) && pb_lexical_path(path);
}

static bool contains_mount(Bridge *b, const char *guest)
{
    if (compare_paths("/", guest) == PATHS_ARE_EQUAL)
        return true;
    for (size_t i = 0; i < b->table.count; i++) {
        Comparison c = compare_paths(guest, b->table.entries[i].guest);
        if (c == PATHS_ARE_EQUAL || c == PATH1_IS_PREFIX)
            return true;
    }
    return false;
}

static long fake_chown(long ret)
{
    return ret == -EPERM && fake_ids_capable(0 /* CAP_CHOWN */) ? 0 : ret;
}

static long copy_link(Bridge *b, long error)
{
    struct stat st;
    if (raw_syscall(__NR_newfstatat, AT_FDCWD, (long)b->first_host, (long)&st,
                    AT_SYMLINK_NOFOLLOW, 0, 0) < 0)
        return error;
    if ((st.st_mode & S_IFMT) == S_IFLNK) {
        long n = raw_syscall(__NR_readlinkat, AT_FDCWD, (long)b->first_host,
                             (long)b->proc_data, sizeof(b->proc_data) - 1, 0, 0);
        if (n < 0 || n >= (long)sizeof(b->proc_data) - 1) return error;
        b->proc_data[n] = 0;
        return raw_syscall(__NR_symlinkat, (long)b->proc_data, AT_FDCWD, (long)b->host, 0, 0, 0) < 0 ?
            error : 0;
    }
    if ((st.st_mode & S_IFMT) != S_IFREG) return error;
    long in = raw_syscall(__NR_openat, AT_FDCWD, (long)b->first_host, O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (in < 0) return error;
    long out = raw_syscall(__NR_openat, AT_FDCWD, (long)b->host,
                           O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, st.st_mode & 07777, 0, 0);
    long ret = out < 0 ? out : 0;
    while (!ret) {
        long n = raw_syscall(__NR_read, in, (long)b->proc_data, sizeof(b->proc_data), 0, 0, 0);
        if (n <= 0) { ret = n < 0 ? n : 1; break; }
        for (long done = 0; done < n && !ret;) {
            long w = raw_syscall(__NR_write, out, (long)b->proc_data + done, n - done, 0, 0, 0);
            if (w <= 0) ret = w < 0 ? w : -EIO;
            else done += w;
        }
    }
    if (ret == 1) {
        struct { long sec, nsec; } times[2] = {{st.st_atime, st.st_atime_nsec},
                                               {st.st_mtime, st.st_mtime_nsec}};
        ret = raw_syscall(__NR_fchmod, out, st.st_mode & 07777, 0, 0, 0, 0);
        if (!ret) ret = raw_syscall(__NR_utimensat, out, 0, (long)times, 0, 0, 0);
    }
    raw_syscall(__NR_close, in, 0, 0, 0, 0, 0);
    if (out >= 0) raw_syscall(__NR_close, out, 0, 0, 0, 0, 0);
    if (ret < 0 && out >= 0) raw_syscall(__NR_unlinkat, AT_FDCWD, (long)b->host, 0, 0, 0, 0);
    return ret < 0 ? (out == -EEXIST ? -EEXIST : error) : 0;
}

static long host_stat(const char *host, bool follow, struct stat *st)
{
    return raw_syscall(__NR_newfstatat, AT_FDCWD, (long)host, (long)st,
                       follow ? 0 : AT_SYMLINK_NOFOLLOW, 0, 0);
}

static long owners_apply_mode(long fd, const char *host, const struct stat *st, unsigned mode)
{
    long rc = owners_may_chmod(st);
    if (rc < 0) return rc;
    unsigned wanted = owners_host_mode(st, mode);
    static const unsigned drops[] = {0, 06000, 07000};
    for (size_t i = 0; i < 3; i++) {
        unsigned applied = wanted & ~drops[i];
        rc = host ? raw_syscall(__NR_fchmodat, AT_FDCWD, (long)host, applied, 0, 0, 0) :
            raw_syscall(__NR_fchmod, fd, applied, 0, 0, 0, 0);
        if (rc == -EPERM && i < 2) continue;
        if (rc < 0) return rc;
        owners_chmod_done(st, mode, applied);
        return 0;
    }
    return rc;
}

static void owners_new_name(Bridge *b)
{
    struct stat st;
    if (owners_enabled() && !host_stat(b->host, false, &st))
        owners_created(&st);
}

static void owners_last_name(const struct stat *st, bool known)
{
    if (known && ((st->st_mode & S_IFMT) == S_IFDIR || st->st_nlink <= 1))
        owners_forget(st);
}

static long mutate(Bridge *b, long number, long a[6])
{
    long ret;
    if (number == __NR_symlinkat) {
        if (!a[0])
            return -EFAULT;
        ret = pb_resolve(b, (int)a[1], (const char *)a[2], false);
        if (ret < 0)
            return ret;
        ret = raw_syscall(number, a[0], AT_FDCWD, (long)b->host, 0, 0, 0);
        if (!ret) {
            if (b->union_on) vfs_upper_note_mutation();
            owners_new_name(b);
            return 0;
        }
        /* Generic fallback when host sandbox forbids symlink() with EACCES/EPERM:
         * materialize a mountpoint and bind-mount it in the container mount table. */
        if ((ret == -EACCES || ret == -EPERM) && mounts_enabled() &&
            strlen(b->guest) < CONFIG_MAX_PATH && strlen(b->host) < sizeof(b->first_host)) {
            strcpy(b->first_guest, b->guest);
            strcpy(b->first_host, b->host);
            if (pb_resolve(b, (int)a[1], (const char *)a[0], true) == 0 &&
                strlen(b->host) < CONFIG_MAX_PATH) {
                struct stat tst;
                if (raw_syscall(__NR_newfstatat, AT_FDCWD, (long)b->host, (long)&tst, 0, 0, 0) == 0) {
                    int is_dir = (tst.st_mode & S_IFMT) == S_IFDIR;
                    int is_reg = (tst.st_mode & S_IFMT) == S_IFREG;
                    if (is_dir || is_reg) {
                        long mk = is_dir
                            ? raw_syscall(__NR_mkdirat, AT_FDCWD, (long)b->first_host, 0755, 0, 0, 0)
                            : raw_syscall(__NR_openat, AT_FDCWD, (long)b->first_host,
                                          O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644, 0, 0);
                        if (!is_dir && mk >= 0) {
                            raw_syscall(__NR_close, mk, 0, 0, 0, 0, 0);
                            mk = 0;
                        }
                        if (mk == 0 || mk == -EEXIST) {
                            struct mount_entry me;
                            memset(&me, 0, sizeof(me));
                            strcpy(me.host, b->host);
                            strcpy(me.guest, b->first_guest);
                            me.kind = MOUNT_BIND;
                            me.access = 'w';
                            strcpy(me.source, "/dev/root");
                            strcpy(me.fstype, "bind");
                            if (mounts_add(&me) == 0)
                                return 0;
                        }
                    }
                }
            }
        }
        return ret;
    }
    if (number == __NR_mkdirat || number == __NR_unlinkat) {
        const char *upath = (const char *)a[1];
        if (identity_fast_path(b, upath))
            return raw_syscall(number, AT_FDCWD, a[1], a[2], 0, 0, 0);
        ret = pb_resolve(b, (int)a[0], upath, false);
        if (ret < 0)
            return ret;
        if (number == __NR_unlinkat && contains_mount(b, b->guest))
            return -EBUSY;
        if (number == __NR_unlinkat && b->union_layer >= 0)
            return union_remove(b->uv, b->union_rel, a[2] & AT_REMOVEDIR);
        struct stat old;
        bool known = number == __NR_unlinkat && owners_enabled() && !host_stat(b->host, false, &old);
        ret = raw_syscall(number, AT_FDCWD, (long)b->host, a[2], 0, 0, 0);
        if (!ret && b->union_on) vfs_upper_note_mutation();
        if (!ret && number == __NR_mkdirat && b->union_layer >= 0 && b->union_opaque)
            union_make_opaque(b->uv, b->union_rel);
        if (!ret && number == __NR_mkdirat) owners_new_name(b);
        if (!ret) owners_last_name(&old, known);
        return ret;
    }

    bool hardlink = number == __NR_linkat;
    if (hardlink) {
        if (a[4] & ~(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH))
            return -EINVAL;
        if (a[1] && !((const char *)a[1])[0] && (a[4] & AT_EMPTY_PATH))
            return -EOPNOTSUPP;
    }
    ret = pb_resolve(b, (int)a[0], (const char *)a[1],
                  hardlink && (a[4] & AT_SYMLINK_FOLLOW));
    if (ret < 0)
        return ret;
    strcpy(b->first_host, b->host);
    strcpy(b->first_guest, b->guest);
    b->first_union_layer = b->union_layer;
    b->first_uv = b->uv;
    if (b->union_layer >= 0) strcpy(b->first_union_rel, b->union_rel);
    size_t first_mount, second_mount;
    ret = binding_table_mount_id(&b->table, b->first_guest, &first_mount);
    if (ret < 0)
        return ret;
    if (hardlink && b->union_on) b->union_op = UOP_CREATE;
    ret = pb_resolve(b, (int)a[2], (const char *)a[3], false);
    if (ret < 0)
        return ret;
    ret = binding_table_mount_id(&b->table, b->guest, &second_mount);
    if (ret < 0)
        return ret;
    if (!hardlink && (contains_mount(b, b->first_guest) || contains_mount(b, b->guest)))
        return -EBUSY;
    if (first_mount != second_mount)
        return -EXDEV;
    if (!hardlink && b->first_union_layer >= 0 && b->union_layer >= 0 && b->first_uv != b->uv)
        return -EXDEV;
    if (!hardlink && b->first_union_layer >= 0 && b->union_layer >= 0)
        return union_rename(b->uv, b->first_union_rel, b->union_rel,
                            number == __NR_renameat2 ? (unsigned)a[4] : 0);
    if (!hardlink && (b->first_union_layer >= 0) != (b->union_layer >= 0))
        return -EXDEV;
    struct stat old, moved;
    bool known = !hardlink && owners_enabled() && !(a[4] & 2 /* RENAME_EXCHANGE */) &&
        !host_stat(b->host, false, &old) && !host_stat(b->first_host, false, &moved) &&
        (old.st_dev != moved.st_dev || old.st_ino != moved.st_ino);
    ret = raw_syscall(number, AT_FDCWD, (long)b->first_host,
                      AT_FDCWD, (long)b->host, a[4], 0);
    if (hardlink && g_payload_config.link_copy && (ret == -EPERM || ret == -EACCES)) {
        ret = copy_link(b, ret);
        if (!ret) owners_new_name(b);
    }
    if (!ret) {
        if (b->union_on) vfs_upper_note_mutation();
        owners_last_name(&old, known);
    }
    return ret;
}

static bool path_mutation(long number, long a[6])
{
    switch (number) {
    case __NR_faccessat: case __NR_faccessat2:
        return !!((unsigned int)a[2] & 2);
    case __NR_openat:
        if (a[2] & O_PATH) return false;
        return (a[2] & (O_ACCMODE | O_CREAT | O_TRUNC)) ||
               ((a[2] & O_TMPFILE) == O_TMPFILE);
    case __NR_setxattr: case __NR_lsetxattr:
    case __NR_removexattr: case __NR_lremovexattr:
    case __NR_mknodat: case __NR_mkdirat: case __NR_unlinkat: case __NR_symlinkat:
    case __NR_linkat: case __NR_renameat: case __NR_renameat2:
    case __NR_fchmodat: case __NR_fchownat: case __NR_utimensat: case __NR_truncate:
    case __NR_bind:
        return true;
    default: return false;
    }
}

static bool path_traversal(long number, long a[6])
{
    switch (number) {
    case __NR_newfstatat: case __NR_statx: case __NR_statfs: case __NR_chdir:
        return true;
    case __NR_faccessat: case __NR_faccessat2:
        return !((unsigned int)a[2] & 2);
    case __NR_openat:
        if (a[2] & O_PATH) return true;
        return (a[2] & O_DIRECTORY) && (a[2] & O_TMPFILE) != O_TMPFILE &&
               !(a[2] & (O_ACCMODE | O_CREAT | O_TRUNC));
    default: return false;
    }
}

static long socket_address(Bridge *b, long number, long a[6])
{
    int sending = number == __NR_sendto, message = number == __NR_sendmsg;
    const void *name;
    unsigned long length;
    if (message) {
        if (!a[1]) return raw_syscall(number, a[0], a[1], a[2], 0, 0, 0);
        memcpy(&b->message, (const void *)a[1], sizeof(b->message));
        name = b->message.name;
        length = (unsigned int)b->message.name_length;
    } else {
        name = (const void *)a[sending ? 4 : 1];
        length = (unsigned int)a[sending ? 5 : 2];
    }
    uint16_t family = 0;
    if (name && length >= 2) memcpy(&family, name, 2);
    if (number == __NR_bind && family == 16 /* AF_NETLINK */ && platform_is_harmonyos()) {
        long rc = raw_syscall(__NR_bind, a[0], a[1], a[2], 0, 0, 0);
        if (rc == -EAFNOSUPPORT || rc == -EINVAL || rc == -EACCES || rc == -EPERM)
            return 0;
        return rc;
    }
    if (net_enabled() && (family == AF_INET || family == AF_INET6)) {
        unsigned char moved[128];
        unsigned moved_length;
        long rc = net_address(number, a[0], name, (unsigned)length, moved, &moved_length);
        if (rc < 0) return rc;
        if (message) {
            b->message.name = moved;
            b->message.name_length = (int)moved_length;
            return raw_syscall(number, a[0], (long)&b->message, a[2], 0, 0, 0);
        }
        if (sending) return raw_syscall(number, a[0], a[1], a[2], a[3], (long)moved, moved_length);
        long done = raw_syscall(number, a[0], (long)moved, moved_length, 0, 0, 0);
        return done == -EADDRINUSE && rc == 1 ? net_v6only_aside(a[0], done) : done;
    }
    size_t prefix = offsetof(struct sockaddr_un, sun_path);
    if (!name || length <= prefix || length > sizeof(b->address))
        return raw_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
    memset(&b->address, 0, sizeof(b->address));
    memcpy(&b->address, name, length);
    if (b->address.sun_family != AF_UNIX || !b->address.sun_path[0])
        return raw_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
    char path[sizeof(b->address.sun_path) + 1];
    size_t size = strnlen(b->address.sun_path, length - prefix);
    memcpy(path, b->address.sun_path, size);
    path[size] = 0;
    long ret = pb_resolve(b, AT_FDCWD, path, number != __NR_bind);
    if (ret < 0) return ret;
    if (g_payload_config.isolate) {
        if (sending || message) return -EPERM;
        return raw_syscall(number == __NR_bind ? BROKER_BIND_PATH : BROKER_CONNECT_PATH,
                           a[0], (long)b->host, 0, 0, 0, 0);
    }
    long directory = -1;
    size_t host = strlen(b->host);
    memset(&b->address, 0, sizeof(b->address));
    b->address.sun_family = AF_UNIX;
    if (host < sizeof(b->address.sun_path)) {
        memcpy(b->address.sun_path, b->host, host + 1);
    } else {
        size_t slash = host;
        while (slash && b->host[slash - 1] != '/') slash--;
        if (!slash) return -ENAMETOOLONG;
        char *base = b->host + slash;
        b->host[slash - 1] = 0;
        directory = raw_syscall(__NR_openat, AT_FDCWD, (long)(slash == 1 ? "/" : b->host),
                                O_PATH | O_DIRECTORY | O_CLOEXEC, 0, 0, 0);
        if (directory < 0) return directory;
        char *out = b->address.sun_path, *end = out + sizeof(b->address.sun_path) - 1;
        const char *proc = "/proc/self/fd/";
        while (*proc && out < end) *out++ = *proc++;
        char digits[16];
        size_t count = 0;
        unsigned long value = (unsigned long)directory;
        do { digits[count++] = '0' + value % 10; value /= 10; } while (value);
        while (count && out < end) *out++ = digits[--count];
        if (out < end) *out++ = '/';
        size_t left = strlen(base);
        if (count || out + left >= end) {
            raw_syscall(__NR_close, directory, 0, 0, 0, 0, 0);
            return -ENAMETOOLONG;
        }
        memcpy(out, base, left + 1);
    }
    long address_length = (long)(prefix + strlen(b->address.sun_path) + 1);
    if (message) {
        b->message.name = &b->address;
        b->message.name_length = (int)address_length;
        ret = raw_syscall(number, a[0], (long)&b->message, a[2], 0, 0, 0);
    } else if (sending) {
        ret = raw_syscall(number, a[0], a[1], a[2], a[3], (long)&b->address, address_length);
    } else {
        ret = raw_syscall(number, a[0], (long)&b->address, address_length, 0, 0, 0);
    }
    if (directory >= 0) raw_syscall(__NR_close, directory, 0, 0, 0, 0, 0);
    return ret;
}

long pb_dispatch(Bridge *b, long number, long a[6], struct proot_open_origin *origin)
{
    if (number == __NR_faccessat || number == __NR_faccessat2) {
        a[2] = (int)a[2];
        if ((unsigned int)a[2] & ~7u) return -EINVAL;
        if (number == __NR_faccessat2) {
            a[3] = (int)a[3];
            if ((unsigned int)a[3] & ~(AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH))
                return -EINVAL;
        }
    }
    b->mutation = path_mutation(number, a);
    b->attributes = number == __NR_fchmodat || number == __NR_fchownat ||
        number == __NR_utimensat || number == __NR_truncate || number == __NR_setxattr ||
        number == __NR_lsetxattr || number == __NR_removexattr || number == __NR_lremovexattr;
    b->creates = number == __NR_mkdirat || number == __NR_mknodat || number == __NR_symlinkat ||
        number == __NR_bind;
    b->traverse = path_traversal(number, a);
    b->union_op = UOP_READ;
    b->union_opaque = false;
    if (b->union_on) switch (number) {
    case __NR_setxattr: case __NR_lsetxattr: case __NR_removexattr: case __NR_lremovexattr:
    case __NR_truncate: case __NR_utimensat: case __NR_linkat:
        b->union_op = UOP_COPY; break;
    case __NR_fchownat: case __NR_fchmodat:
        b->union_op = owners_enabled() ? UOP_RECORD : UOP_COPY; break;
    case __NR_mkdirat: case __NR_mknodat: case __NR_symlinkat: case __NR_bind:
        b->union_op = UOP_CREATE; break;
    case __NR_openat:
        if (!(a[2] & O_PATH)) { b->union_op = UOP_OPEN; b->open_flags = a[2]; }
        break;
    }
    if (number == __NR_mount)
        return pb_mount_call(b, a);
    if (number == __NR_umount2)
        return pb_umount_call(b, a);
    if (number == __NR_bind || number == __NR_connect ||
        number == __NR_sendto || number == __NR_sendmsg)
        return socket_address(b, number, a);

    b->secure = g_payload_config.guard >= GUARD_PATHS && !g_payload_config.isolate;
    long ret;
    switch (number) {
    case __NR_setxattr: case __NR_getxattr:
    case __NR_listxattr: case __NR_removexattr:
    case __NR_lsetxattr: case __NR_lgetxattr:
    case __NR_llistxattr: case __NR_lremovexattr: {
        bool follow = number != __NR_lsetxattr && number != __NR_lgetxattr &&
                      number != __NR_llistxattr && number != __NR_lremovexattr;
        ret = pb_resolve(b, AT_FDCWD, (const char *)a[0], follow);
        if (ret < 0) return ret;
        ret = raw_syscall(number, (long)b->host, a[1], a[2], a[3], a[4], a[5]);
        if ((number == __NR_setxattr || number == __NR_lsetxattr) &&
            (ret == -EACCES || ret == -EPERM || ret == -EOPNOTSUPP) &&
            g_payload_config.mode == CONFIG_MODE_CONTAINER && a[1] &&
            !strncmp((const char *)a[1], "security.", 9))
            return 0;
        return ret;
    }
    }
    if (number == __NR_inotify_add_watch) {
        if (!a[1]) return -EFAULT;
        ret = pb_resolve(b, AT_FDCWD, (const char *)a[1], !(a[2] & IN_DONT_FOLLOW));
        if (ret < 0) return ret;
        ret = pb_watch_hides_child(b, b->guest);
        if (ret < 0) return ret;
        return raw_syscall(number, a[0], (long)b->host, a[2], 0, 0, 0);
    }
    if (number == __NR_fchmod || number == __NR_fchown) {
        /* Linux open(2): fchmod/fchown on an O_PATH fd must fail with -EBADF so
         * callers (e.g. libc fchmodat(..., AT_SYMLINK_NOFOLLOW)) can fall back
         * to /proc/self/fd/<fd> consistently across host kernels/LSMs. */
        long fl = raw_syscall(__NR_fcntl, a[0], F_GETFL, 0, 0, 0, 0);
        if (fl >= 0 && (fl & O_PATH))
            return -EBADF;
    }
    if (b->union_on && (number == __NR_fchmod || (number == __NR_utimensat && !a[1]))) {
        ret = pb_union_fd(b, (int)a[0]);
        if (ret < 0) return ret;
        if (ret > 0 && number == __NR_fchmod && owners_enabled()) {
            struct stat st;
            ret = raw_syscall(__NR_fstat, a[0], (long)&st, 0, 0, 0, 0);
            if (ret < 0) return ret;
            ret = owners_may_chmod(&st);
            if (ret < 0) return ret;
            owners_chmod_done(&st, (unsigned)a[1], st.st_mode & 07777);
            return 0;
        }
        if (ret > 0) {
            ret = union_copy_up(b->uv, b->union_rel, true);
            if (ret < 0) return ret;
            size_t n = b->uv->length[0];
            if (n + strlen(b->union_rel) >= PATH_MAX) return -ENAMETOOLONG;
            memcpy(b->host, b->uv->layer[0], n);
            strcpy(b->host + n, b->union_rel);
            if (number == __NR_fchmod)
                return raw_syscall(__NR_fchmodat, AT_FDCWD, (long)b->host, a[1], 0, 0, 0);
            return raw_syscall(__NR_utimensat, AT_FDCWD, (long)b->host, a[2], AT_SYMLINK_NOFOLLOW, 0, 0);
        }
    }
    if ((number == __NR_fchown || number == __NR_fchmod) && owners_enabled()) {
        struct stat st;
        ret = raw_syscall(__NR_fstat, a[0], (long)&st, 0, 0, 0, 0);
        if (ret < 0) return ret;
        return number == __NR_fchown ? owners_chown(&st, (int)a[1], (int)a[2]) :
            owners_apply_mode(a[0], NULL, &st, (unsigned)a[1]);
    }
    if (number == __NR_fchown)
        return fake_chown(raw_syscall(number, a[0], a[1], a[2], 0, 0, 0));
    if (number == __NR_fchmod || number == __NR_fstatfs || number == __NR_ftruncate)
        return raw_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
    if (number == __NR_statfs || number == __NR_truncate) {
        if (!a[0]) return -EFAULT;
        ret = pb_resolve(b, AT_FDCWD, (const char *)a[0], true);
        if (ret < 0) return ret;
        return raw_syscall(number, (long)b->host, a[1], a[2], a[3], a[4], a[5]);
    }
    if (number == __NR_fchownat || number == __NR_utimensat) {
        long flags = a[number == __NR_fchownat ? 4 : 3];
        long allowed = AT_SYMLINK_NOFOLLOW;
        if (number == __NR_fchownat) allowed |= AT_EMPTY_PATH;
        if (flags & ~allowed) return -EINVAL;
        if (number == __NR_utimensat && !a[1])
            return raw_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
        if (!a[1]) return -EFAULT;
        const char *path = (const char *)a[1];
        if (number == __NR_fchownat && owners_enabled()) {
            struct stat st;
            if (!*path && (flags & AT_EMPTY_PATH)) {
                ret = a[0] == AT_FDCWD ? host_stat(".", true, &st) :
                    raw_syscall(__NR_fstat, a[0], (long)&st, 0, 0, 0, 0);
            } else {
                ret = pb_resolve(b, (int)a[0], path, !(flags & AT_SYMLINK_NOFOLLOW));
                if (ret < 0) return ret;
                ret = host_stat(b->host, !(flags & AT_SYMLINK_NOFOLLOW), &st);
            }
            return ret < 0 ? ret : owners_chown(&st, (int)a[2], (int)a[3]);
        }
        if (!*path && number == __NR_fchownat && (flags & AT_EMPTY_PATH))
            ret = raw_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
        else {
            ret = pb_resolve(b, (int)a[0], path, !(flags & AT_SYMLINK_NOFOLLOW));
            if (ret < 0) return ret;
            ret = raw_syscall(number, AT_FDCWD, (long)b->host, a[2], a[3], a[4], a[5]);
        }
        return number == __NR_fchownat ? fake_chown(ret) : ret;
    }
    if (number == __NR_mkdirat || number == __NR_unlinkat || number == __NR_symlinkat ||
        number == __NR_linkat || number == __NR_renameat || number == __NR_renameat2)
        return mutate(b, number, a);
    if (number == __NR_fchmodat && owners_enabled()) {
        if (!a[1]) return -EFAULT;
        ret = pb_resolve(b, (int)a[0], (const char *)a[1], true);
        if (ret < 0) return ret;
        struct stat st;
        ret = host_stat(b->host, true, &st);
        if (ret < 0) return ret;
        if (b->union_layer > 0) {
            ret = owners_may_chmod(&st);
            if (ret < 0) return ret;
            owners_chmod_done(&st, (unsigned)a[2], st.st_mode & 07777);
            return 0;
        }
        return owners_apply_mode(-1, b->host, &st, (unsigned)a[2]);
    }
    if (number == __NR_getcwd) {
        ret = pb_guest_cwd(b);
        if (ret < 0)
            return ret;
        size_t size = strlen(b->cwd) + 1;
        if ((unsigned long)a[1] < size)
            return -ERANGE;
        if (!a[0])
            return -EFAULT;
        memcpy((void *)a[0], b->cwd, size);
        return (long)size;
    }
    if (number == __NR_fchdir) {
        ret = pb_host_fd(b, (int)a[0], b->guest);
        if (ret < 0)
            return ret;
        ret = pb_path_visibility(b, b->guest);
        if (ret < 0) return ret;
        if (ret == FS_HIDDEN) return -EACCES;
        ret = raw_syscall(__NR_fchdir, a[0], 0, 0, 0, 0, 0);
        if (ret >= 0 && origin) *origin = b->anchor;
        return ret;
    }
    if (number == __NR_chdir) {
        ret = pb_resolve(b, AT_FDCWD, (const char *)a[0], true);
        if (ret < 0)
            return ret;
        bool known = origin && (((const char *)a[0])[0] == '/' || b->anchor.known);
        size_t id = 0;
        if (known) {
            ret = binding_table_mount_id(&b->table, b->guest, &id);
            if (ret < 0) return ret;
        }
        ret = raw_syscall(__NR_chdir, (long)b->host, 0, 0, 0, 0, 0);
        if (ret >= 0 && known) *origin = (struct proot_open_origin){id, true};
        return ret;
    }

    const char *path = (const char *)a[1];
    if (!path)
        return -EFAULT;
    bool follow = true;
    if (number == __NR_mknodat) {
        follow = false;
    } else if (number == __NR_openat) {
        int flags = (int)a[2];
        follow = !(flags & O_NOFOLLOW) && !((flags & O_CREAT) && (flags & O_EXCL));
    } else if (number == __NR_readlinkat) {
        follow = false;
        if (a[3] <= 0)
            return -EINVAL;
    } else if (number == __NR_newfstatat || number == __NR_faccessat2 || number == __NR_statx) {
        long flags = number == __NR_statx ? a[2] : a[3];
        follow = !(flags & AT_SYMLINK_NOFOLLOW);
        if (!path[0] && (flags & AT_EMPTY_PATH)) {
            if (number == __NR_newfstatat) {
                if (flags & ~(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT))
                    return -EINVAL;
                if (a[0] != AT_FDCWD)
                    return raw_syscall(__NR_fstat, a[0], a[2], 0, 0, 0, 0);
                return raw_syscall(number, AT_FDCWD, (long)".", a[2],
                                   flags & ~AT_EMPTY_PATH, 0, 0);
            }
            if (number == __NR_statx) {
                return raw_syscall(number, a[0], a[1], flags | AT_SYMLINK_NOFOLLOW,
                                   a[3], a[4], a[5]);
            }
            return raw_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
        }
    }
    if (number == __NR_readlinkat && !path[0])
        return raw_syscall(number, a[0], a[1], a[2], a[3], 0, 0);

    /* Fast path for bare/identity root ("/") with no binds, union, or guards:
     * skip per-component host_lookup walk when guest path == host path. */
    if (!origin && identity_fast_path(b, path) &&
        (number == __NR_newfstatat || number == __NR_statx ||
         number == __NR_faccessat || number == __NR_faccessat2 ||
         number == __NR_readlinkat || number == __NR_openat))
        return raw_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);

    bool observed_open = number == __NR_openat && origin &&
        (path[0] == '/' || b->anchor.known);
    size_t length = strnlen(path, PATH_MAX);
    b->defer_final = number == __NR_openat && follow && !(a[2] & O_PATH) &&
        length && length < PATH_MAX && path[length - 1] != '/';
    bool deferred = b->defer_final;

    if (vdev_enabled() && path[0] == '/') {
        int vd = vdev_match_path(path);
        if (vd != -1) {
            b->defer_final = false;
            return vdev_path_call(number, a, vd);
        }
    }
    if (mounts_enabled() && path[0] == '/') {
        int dev = pb_loop_device(path);
        if (dev != -1) {
            b->defer_final = false;
            return pb_loop_path_call(number, a, dev);
        }
    }
    if (net_stack_enabled() && path[0] == '/' &&
        (number == __NR_openat || number == __NR_newfstatat || number == __NR_statx ||
         number == __NR_faccessat || number == __NR_faccessat2)) {
        long nrc = net_stack_proc_call(number, a, path);
        if (nrc != -ENOENT) {
            b->defer_final = false;
            return nrc;
        }
    }
    if (number == __NR_openat && !(a[2] & (O_ACCMODE | O_PATH | O_CREAT)) &&
        path[0] == '/' && (path[1] == 'p' || path[1] == 's')) {
        if (g_payload_config.cpu_mask &&
            (!strcmp(path, "/proc/cpuinfo") ||
             !strcmp(path, "/sys/devices/system/cpu/online") ||
             !strcmp(path, "/sys/devices/system/cpu/present") ||
             !strcmp(path, "/sys/devices/system/cpu/possible"))) {
            strcpy(b->guest, path);
            b->defer_final = false;
            return pb_proc_cpuinfo(b, (int)a[2]);
        }
        if (g_payload_config.mem_limit_mb && !strcmp(path, "/proc/meminfo")) {
            strcpy(b->guest, path);
            b->defer_final = false;
            return pb_proc_meminfo(b, (int)a[2]);
        }
    }

    ret = pb_resolve(b, (int)a[0], path, follow);
    b->defer_final = false;
    if (ret < 0)
        return ret;
    if (vdev_enabled()) {
        int vd = vdev_match_path(b->guest);
        if (vd != -1) return vdev_path_call(number, a, vd);
    }
    if (mounts_enabled()) {
        int device = pb_loop_device(b->guest);
        if (device != -1) return pb_loop_path_call(number, a, device);
    }
    if (number == __NR_readlinkat) {
        Comparison c = compare_paths("/proc", b->guest);
        if (c == PATH1_IS_PREFIX)
            return pb_proc_readlink(b, a);
    }
    size_t mount_id = 0;
    if (observed_open) {
        ret = binding_table_mount_id(&b->table, b->guest, &mount_id);
        if (ret < 0) return ret;
    }
    if ((number == __NR_newfstatat || number == __NR_statx || number == __NR_faccessat ||
         number == __NR_faccessat2) && pb_glue_ancestor(b, b->guest)) {
        struct stat probe;
        if (raw_syscall(__NR_newfstatat, AT_FDCWD, (long)b->host, (long)&probe,
                        AT_SYMLINK_NOFOLLOW, 0, 0) == -ENOENT)
            strcpy(b->host, b->table.root);
    }
    bool fresh = false;
    if (number == __NR_openat && owners_enabled() && ((a[2] & O_CREAT) || (a[2] & O_TMPFILE) == O_TMPFILE)) {
        struct stat probe;
        fresh = (a[2] & O_EXCL) || (a[2] & O_TMPFILE) == O_TMPFILE || host_stat(b->host, true, &probe) == -ENOENT;
    }
    if (number == __NR_openat && !(a[2] & (O_ACCMODE | O_PATH | O_CREAT)) &&
        b->guest[0] == '/' && (b->guest[1] == 'p' || b->guest[1] == 's')) {
        ret = pb_proc_cmdline(b, (int)a[2]);
        if (ret == -ENOENT && mounts_enabled())
            ret = pb_proc_mounts(b, (int)a[2]);
        if (ret == -ENOENT && mounts_enabled())
            ret = pb_proc_filesystems(b, (int)a[2]);
        if (ret == -ENOENT && g_payload_config.mode == CONFIG_MODE_CONTAINER)
            ret = pb_proc_status(b, (int)a[2]);
        if (ret == -ENOENT && g_payload_config.mode == CONFIG_MODE_CONTAINER)
            ret = pb_proc_maps(b, (int)a[2]);
        if (ret == -ENOENT && g_payload_config.cpu_mask)
            ret = pb_proc_cpuinfo(b, (int)a[2]);
        if (ret == -ENOENT && g_payload_config.mem_limit_mb)
            ret = pb_proc_meminfo(b, (int)a[2]);
    } else ret = -ENOENT;

    if (ret == -ENOENT && number == __NR_newfstatat && follow && b->final_match) {
        struct { const void *base; size_t length; } local = {&b->final_stat, sizeof(b->final_stat)},
            remote = {(void *)a[2], sizeof(b->final_stat)};
        long pid = raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
        long n = raw_syscall(__NR_process_vm_writev, pid, (long)&local, 1, (long)&remote, 1, 0);
        if (n == (long)sizeof(b->final_stat)) return 0;
        if (n == -EFAULT) return n;
    }
    if (ret == -ENOENT && deferred) {
        ret = raw_syscall(number, AT_FDCWD, (long)b->host, a[2] | O_NOFOLLOW, a[3], 0, 0);
        if (ret != -ELOOP) goto opened;
        ret = pb_resolve(b, (int)a[0], path, follow);
        if (ret < 0) return ret;
        if (observed_open) {
            ret = binding_table_mount_id(&b->table, b->guest, &mount_id);
            if (ret < 0) return ret;
        }
        ret = -ENOENT;
    }
    if (ret == -ENOENT) {
        long arg2 = a[2];
        if ((number == __NR_faccessat || number == __NR_faccessat2) &&
            owners_enabled() && (arg2 & 7L)) {
            struct stat ast;
            int follow_acc = (number == __NR_faccessat2) ? !(a[3] & AT_SYMLINK_NOFOLLOW) : 1;
            long sret = host_stat(b->host, follow_acc, &ast);
            if (sret < 0)
                return sret;
            int use_eff = (number == __NR_faccessat2) && (a[3] & AT_EACCESS);
            return owners_check_access(&ast, (unsigned)arg2, use_eff);
        }
        if ((number == __NR_faccessat || number == __NR_faccessat2) &&
            g_payload_config.isolate && b->union_on && b->union_layer > 0 &&
            (arg2 & 2) && b->uv && b->uv->layer[0] && b->uv->layer[0][0]) {
            long up = raw_syscall(__NR_faccessat, AT_FDCWD, (long)b->uv->layer[0], 2, 0, 0, 0);
            if (up < 0)
                return up;
            arg2 &= ~2L;
        }
        ret = raw_syscall(number, AT_FDCWD, (long)b->host, arg2, a[3], a[4], a[5]);
    }
 opened:
    if (ret >= 0 && b->union_on && b->mutation)
        vfs_upper_note_mutation();
    if (ret >= 0 && observed_open)
        *origin = (struct proot_open_origin){mount_id, true};
    if (ret >= 0 && fresh) {
        struct stat st;
        if (!raw_syscall(__NR_fstat, ret, (long)&st, 0, 0, 0, 0))
            owners_created(&st);
    }
    if (!ret && number == __NR_mknodat)
        owners_new_name(b);
    return ret;
}
