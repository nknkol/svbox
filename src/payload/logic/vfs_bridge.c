/* SPDX-License-Identifier: MIT */
/* PRoot path backend lifecycle: Bridge pool, mount/binding/view table caching,
 * isolation optimistic retry loop, getdents visibility filter, and public
 * proot_* entry points (see vfs_bridge_internal.h for sibling modules). */
#include "vfs_bridge_internal.h"

size_t proot_bridge_scratch_size(void) { return sizeof(Bridge); }

/* A free or hidden mount slot: a prefix no path has. */
const char pb_unmounted[] = "/\001elf-unmounted";

/* ---- Bridge Pool & Table Caching ---- */

#define BRIDGE_POOL 4
static Bridge *bridge_pool[BRIDGE_POOL];
static int bridge_used[BRIDGE_POOL];

static long bridge_acquire(void)
{
    if (g_payload_config.guard != GUARD_NONE && !fd_runtime_shared_scratch())
        return proot_scratch_alloc(sizeof(Bridge));
    for (int i = 0; i < BRIDGE_POOL; i++) {
        int free_slot = 0;
        if (!__atomic_compare_exchange_n(&bridge_used[i], &free_slot, 1, 0,
                                         __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            continue;
        Bridge *b = __atomic_load_n(&bridge_pool[i], __ATOMIC_ACQUIRE);
        if (!b) {
            long mem = proot_scratch_alloc(sizeof(Bridge));
            if ((unsigned long)mem >= (unsigned long)-4095) {
                __atomic_store_n(&bridge_used[i], 0, __ATOMIC_RELEASE);
                return mem;
            }
            b = (void *)mem;
            __atomic_store_n(&bridge_pool[i], b, __ATOMIC_RELEASE);
        }
        return (long)b;
    }
    return proot_scratch_alloc(sizeof(Bridge));
}

static void bridge_release(Bridge *b)
{
    for (int i = 0; i < b->walk_count; i++)
        raw_syscall(__NR_close, b->walk_fd[i], 0, 0, 0, 0, 0);
    b->walk_count = 0;
    for (int i = 0; i < BRIDGE_POOL; i++)
        if (__atomic_load_n(&bridge_pool[i], __ATOMIC_ACQUIRE) == b) {
            __atomic_store_n(&bridge_used[i], 0, __ATOMIC_RELEASE);
            return;
        }
    if (b->deep_frames)
        raw_syscall(__NR_munmap, (long)b->deep_frames, DEEP_FRAMES_SIZE, 0, 0, 0, 0);
    proot_scratch_free(b, sizeof(Bridge));
}

static long bridge_create(Bridge **out)
{
    payload_config_t *cfg = &g_payload_config;
    if (cfg->bind_count < 0 || cfg->bind_count > CONFIG_MAX_BINDS)
        return -EINVAL;
    long mem = bridge_acquire();
    if ((unsigned long)mem >= (unsigned long)-4095)
        return mem;
    Bridge *b = (void *)mem;
    b->context = NULL;
    b->follow_final = true;
    b->mutation = false;
    b->attributes = false;
    b->creates = false;
    b->final_match = false;
    b->secure = false;
    b->walk_count = 0;
    b->defer_final = false;
    b->final_valid = false;
    b->last_map_valid = false;
    b->traverse = false;
    b->optimistic_allowed = b->optimistic = b->optimistic_used = b->force_full = false;
    b->hints = NULL;
    b->uv = b->first_uv = NULL;
    b->map_view = b->final_view = NULL;
    b->union_op = UOP_READ;
    b->union_layer = b->first_union_layer = -1;
    b->umemo.valid = false;
    b->anchor_fd = AT_FDCWD;
    b->anchor = (struct proot_open_origin){0, false};

    /* Reuse validated binding/mount/view tables across calls when the container
     * mount table version has not changed (and read-guard access policy is off). */
    bool m_on = mounts_enabled() != 0;
    uint64_t mver = m_on ? mounts_version() : 0;
    if (b->table_ready && cfg->guard != GUARD_READS && (!m_on || (!(mver & 1ULL) && mver == b->cached_mount_ver))) {
        *out = b;
        return 0;
    }

    b->view_count = 0;
    b->union_on = false;
    size_t count = (size_t)cfg->bind_count;
    b->mount_count = m_on ? mounts_snapshot(b->mounts, CONFIG_MAX_MOUNTS) : 0;
    /* Re-read mount version after snapshot so a concurrent write is never cached. */
    uint64_t mver_after = m_on ? mounts_version() : 0;
    for (int i = 0; i < cfg->bind_count; i++)
        b->bindings[i] = b->mount_count && mounts_bind_hidden(b->mounts, b->mount_count, cfg->binds[i].src) ?
            (PathBinding){UNMOUNTED, UNMOUNTED} : (PathBinding){cfg->binds[i].src, cfg->binds[i].dst};
    for (int i = 0; i < b->mount_count; i++)
        b->bindings[count++] = mounts_hidden(b->mounts, b->mount_count, i) ?
            (PathBinding){UNMOUNTED, UNMOUNTED} : (PathBinding){b->mounts[i].guest, b->mounts[i].host};
    b->table = (BindingTable){cfg->root[0] ? cfg->root : "/", b->bindings, count};
    if (union_enabled())
        b->view_count = union_views(b->views, 1 + MOUNT_OVERLAYS, b->overlay_lowers, b->mounts, b->mount_count);
    b->union_on = b->view_count > 0;
    b->root_union = b->union_on && cfg->lower_count > 0 && cfg->root[0];
    long ret = binding_table_validate(&b->table);
    b->reads = false;
    if (ret >= 0 && cfg->guard == GUARD_READS) {
        size_t mcnt;
        ret = fd_runtime_mount_access(b->access, &mcnt);
        b->policy = (struct fs_policy){b->access, mcnt};
        b->exposed_count = 0;
        for (size_t i = 0; ret >= 0 && i < b->table.count; i++) {
            size_t id;
            ret = binding_table_mount_id(&b->table, b->bindings[i].guest, &id);
            if (ret >= 0 && id == i + 1 && b->access[id] != FS_DENY && b->bindings[i].guest != UNMOUNTED)
                b->exposed[b->exposed_count++] = b->bindings[i].guest;
        }
        b->reads = ret >= 0;
    }
    if (ret < 0) {
        b->table_ready = false;
        bridge_release(b);
        return ret;
    }
    if (cfg->guard != GUARD_READS && (!m_on || (!(mver_after & 1ULL) && mver_after == mver))) {
        b->cached_mount_ver = mver_after;
        b->table_ready = true;
    } else {
        b->table_ready = false;
    }
    *out = b;
    return 0;
}

/* ---- Mount Revalidation & FD Introspection ---- */

static int unique_mount(Bridge *b, const char *host, size_t *selected)
{
    size_t matches = 0;
    if (pb_glue_guest(host, b->guest)) {
        int visibility = pb_path_visibility(b, b->guest);
        if (visibility < 0) return visibility;
        if (visibility == FS_HIDDEN) return -EXDEV;
        *selected = 0;
        return 0;
    }
    for (size_t id = 0; id <= b->table.count; id++) {
        b->anchor = (struct proot_open_origin){id, true};
        if (pb_observed_guest_path(b, host, b->guest)) continue;
        int visibility = pb_path_visibility(b, b->guest);
        if (visibility < 0) return visibility;
        if (visibility == FS_HIDDEN) continue;
        *selected = id;
        matches++;
    }
    return matches == 1 ? 0 : -EXDEV;
}

int proot_fd_guest_path(int fd, char *guest, size_t capacity)
{
    if (!guest || !capacity) return -EINVAL;
    Bridge *b;
    long ret = bridge_create(&b);
    if (ret < 0) return (int)ret;
    char link[32];
    strcpy(link, "/proc/self/fd/");
    size_t at = strlen(link);
    unsigned value = (unsigned)fd;
    char digits[16];
    int count = 0;
    do { digits[count++] = '0' + value % 10; value /= 10; } while (value);
    while (count) link[at++] = digits[--count];
    link[at] = 0;
    ret = pb_host_readlink(b, link, b->proc_host, sizeof(b->proc_host) - 1);
    if (ret >= 0) {
        b->proc_host[ret] = 0;
        size_t length = (size_t)ret;
        if (b->proc_host[0] != '/' ||
            (length >= 10 && !strcmp(b->proc_host + length - 10, " (deleted)")))
            ret = -EOPNOTSUPP;
        else if (pb_preferred_guest_path(b, b->proc_host, b->proc_guest) < 0)
            ret = -EACCES;
        else if (strlen(b->proc_guest) >= capacity)
            ret = -ENAMETOOLONG;
        else {
            strcpy(guest, b->proc_guest);
            ret = 0;
        }
    }
    bridge_release(b);
    return (int)ret;
}

void proot_socket_name(long number, long fd, void *address, unsigned *length,
                       unsigned capacity)
{
    size_t prefix = offsetof(struct sockaddr_un, sun_path);
    if (!address || !length || *length <= prefix + 1 || *length > sizeof(struct sockaddr_un))
        return;
    Bridge *b;
    if (bridge_create(&b) < 0) return;
    if (*length > capacity) {
        unsigned full = sizeof(b->address);
        long query = number == __NR_getsockname ? __NR_getsockname : __NR_getpeername;
        if (raw_syscall(query, fd, (long)&b->address, (long)&full, 0, 0, 0) < 0 ||
            full != *length) {
            bridge_release(b);
            return;
        }
    } else memcpy(&b->address, address, *length);
    if (b->address.sun_family == AF_UNIX && b->address.sun_path[0]) {
        size_t size = strnlen(b->address.sun_path, *length - prefix);
        memcpy(b->proc_host, b->address.sun_path, size);
        b->proc_host[size] = 0;
        int rc = pb_preferred_guest_path(b, b->proc_host, b->proc_guest);
        if (rc < 0 && g_payload_config.guard == GUARD_READS) {
            *length = (unsigned)sizeof(b->address.sun_family);
            bridge_release(b);
            return;
        }
        size_t guest = strlen(b->proc_guest);
        if (!rc && guest < sizeof(b->address.sun_path)) {
            memset(b->address.sun_path, 0, sizeof(b->address.sun_path));
            memcpy(b->address.sun_path, b->proc_guest, guest + 1);
            unsigned full = (unsigned)(prefix + guest + 1);
            memcpy(address, &b->address, full < capacity ? full : capacity);
            *length = full;
        }
    }
    bridge_release(b);
}

int proot_revalidate_cwd(struct proot_open_origin *origin)
{
    if (!origin) return -EINVAL;
    *origin = (struct proot_open_origin){0, false};
    Bridge *b;
    long ret = bridge_create(&b);
    if (ret < 0) return (int)ret;
    ret = raw_syscall(__NR_getcwd, (long)b->first_host, sizeof(b->first_host), 0, 0, 0, 0);
    if (ret >= 0) {
        size_t selected;
        ret = unique_mount(b, b->first_host, &selected);
        if (!ret) *origin = (struct proot_open_origin){selected, true};
    }
    bridge_release(b);
    return (int)ret;
}

int proot_revalidate_regular_fd(int fd, struct proot_open_origin *origin)
{
    if (!origin) return -EINVAL;
    *origin = (struct proot_open_origin){0, false};
    struct stat live, named, again;
    long ret = raw_syscall(__NR_fstat, fd, (long)&live, 0, 0, 0, 0);
    if (ret < 0) return (int)ret;
    if ((live.st_mode & S_IFMT) != S_IFREG || !live.st_nlink) return -EOPNOTSUPP;
    Bridge *b;
    ret = bridge_create(&b);
    if (ret < 0) return (int)ret;
    char link[64] = "/proc/self/fd/", digits[16];
    unsigned value = (unsigned)fd;
    size_t count = 0, pos = strlen(link);
    do { digits[count++] = '0' + value % 10; value /= 10; } while (value);
    while (count) link[pos++] = digits[--count];
    link[pos] = 0;
    ret = pb_host_readlink(b, link, b->first_host, sizeof(b->first_host));
    if (ret < 0) goto done;
    if (ret >= PATH_MAX) { ret = -ENAMETOOLONG; goto done; }
    b->first_host[ret] = 0;
    if (!ret || b->first_host[0] != '/' ||
        (ret >= 10 && !strcmp(b->first_host + ret - 10, " (deleted)"))) {
        ret = -EXDEV;
        goto done;
    }
    ret = raw_syscall(__NR_newfstatat, AT_FDCWD, (long)b->first_host, (long)&named,
                      AT_SYMLINK_NOFOLLOW, 0, 0);
    if (ret < 0) goto done;
    if ((named.st_mode & S_IFMT) != S_IFREG || named.st_dev != live.st_dev || named.st_ino != live.st_ino) {
        ret = -ESTALE;
        goto done;
    }
    size_t selected;
    ret = unique_mount(b, b->first_host, &selected);
    if (ret < 0) goto done;
    ret = raw_syscall(__NR_fstat, fd, (long)&again, 0, 0, 0, 0);
    if (ret < 0) goto done;
    if (again.st_dev != live.st_dev || again.st_ino != live.st_ino || !again.st_nlink) {
        ret = -ESTALE;
        goto done;
    }
    *origin = (struct proot_open_origin){selected, true};
    ret = 0;
done:
    bridge_release(b);
    return (int)ret;
}

/* ---- getdents64 Visibility Filter ---- */

#define DIRENT_OFFSET 8
#define DIRENT_RECLEN 16
#define DIRENT_NAME 19
#define DIR_NAMES 4
static struct dir_name {
    long pid;
    int fd;
    unsigned long dev, ino;
    char guest[PATH_MAX];
} dir_names[DIR_NAMES];
static int dir_names_lock, dir_names_next;

static void dir_names_take(void)
{
    while (__atomic_exchange_n(&dir_names_lock, 1, __ATOMIC_ACQUIRE))
        raw_syscall(__NR_sched_yield, 0, 0, 0, 0, 0, 0);
}
static void dir_names_drop(void) { __atomic_store_n(&dir_names_lock, 0, __ATOMIC_RELEASE); }

static int cached_dir_name(int fd, char *guest, struct stat *st, bool store)
{
    long pid = raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
    int found = 0;
    dir_names_take();
    for (int i = 0; i < DIR_NAMES && !store; i++) {
        struct dir_name *d = &dir_names[i];
        if (d->pid == pid && d->fd == fd && d->dev == st->st_dev && d->ino == st->st_ino) {
            strcpy(guest, d->guest);
            found = 1;
            break;
        }
    }
    if (store) {
        struct dir_name *d = &dir_names[dir_names_next++ % DIR_NAMES];
        *d = (struct dir_name){pid, fd, st->st_dev, st->st_ino, ""};
        strcpy(d->guest, guest);
    }
    dir_names_drop();
    return found;
}

long proot_getdents_visible(int fd, void *buffer, unsigned long count,
                            const struct proot_open_origin *anchor)
{
    if (!anchor) return -EINVAL;
    Bridge *b;
    long ret = bridge_create(&b);
    if (ret < 0) return ret;
    b->anchor = *anchor;
    b->anchor_fd = fd;
    struct stat dir;
    bool cacheable = g_payload_config.isolate &&
        !raw_syscall(__NR_fstat, fd, (long)&dir, 0, 0, 0, 0) && (dir.st_mode & S_IFMT) == S_IFDIR;
    if (cacheable && cached_dir_name(fd, b->first_guest, &dir, false))
        ret = 0;
    else {
        ret = pb_host_fd(b, fd, b->first_guest);
        if (ret >= 0 && cacheable && strlen(b->first_guest) < PATH_MAX)
            cached_dir_name(fd, b->first_guest, &dir, true);
    }
    if (ret == -ENOTDIR) {
        ret = raw_syscall(__NR_getdents64, fd, (long)buffer, (long)count, 0, 0, 0);
        goto done;
    }
    if (ret == -EXDEV) ret = -EACCES;
    if (ret < 0) goto done;
    ret = pb_path_visibility(b, b->first_guest);
    if (ret == FS_HIDDEN) ret = -EACCES;
    if (ret < 0) goto done;
    if (!buffer) { ret = -EFAULT; goto done; }
    size_t base = strlen(b->first_guest);
    for (;;) {
        long position = raw_syscall(__NR_lseek, fd, 0, 1 /* SEEK_CUR */, 0, 0, 0);
        if (position < 0) { ret = position; goto done; }
        ret = raw_syscall(__NR_getdents64, fd, (long)b->dirents, sizeof(b->dirents), 0, 0, 0);
        if (ret <= 0) goto done;
        unsigned char *bytes = b->dirents;
        size_t kept = 0;
        for (size_t offset = 0; offset < (size_t)ret;) {
            unsigned short length;
            long next;
            memcpy(&length, bytes + offset + DIRENT_RECLEN, sizeof(length));
            if (length < DIRENT_NAME + 1 || offset + length > (size_t)ret) { ret = -EIO; goto done; }
            memcpy(&next, bytes + offset + DIRENT_OFFSET, sizeof(next));
            const char *name = (const char *)bytes + offset + DIRENT_NAME;
            bool keep = !strcmp(name, ".") || !strcmp(name, "..");
            if (!keep) {
                size_t size = strnlen(name, length - DIRENT_NAME);
                if (base + 1 + size >= PATH_MAX) { ret = -ENAMETOOLONG; goto done; }
                memcpy(b->guest, b->first_guest, base);
                size_t at = base;
                if (base != 1) b->guest[at++] = '/';
                memcpy(b->guest + at, name, size);
                b->guest[at + size] = 0;
                int visibility = pb_path_visibility(b, b->guest);
                if (visibility < 0) { ret = visibility; goto done; }
                keep = visibility != FS_HIDDEN;
            }
            if (keep) {
                if (kept + length > count) {
                    long sought = raw_syscall(__NR_lseek, fd, position, 0 /* SEEK_SET */, 0, 0, 0);
                    ret = sought < 0 ? sought : kept ? (long)kept : -EINVAL;
                    goto done;
                }
                memcpy((unsigned char *)buffer + kept, bytes + offset, length);
                kept += length;
            }
            position = next;
            offset += length;
        }
        if (kept) { ret = (long)kept; goto done; }
    }
done:
    bridge_release(b);
    return ret;
}

/* ---- Isolation Optimistic Execution & Public Entry Points ---- */

static bool climbing_target(const char *target)
{
    const char *p = target;
    while (p[0] == '.' && p[1] == '.' && (p[2] == '/' || !p[2]))
        for (p += 2; *p == '/'; p++)
            ;
    return pb_lexical_path(p);
}

struct optimism {
    bool on;
    struct link_hints *hints;
};

static void optimism_begin(Bridge *b, struct optimism *o)
{
    b->optimistic_allowed = o->on;
    b->hints = o->hints;
}

static bool optimism_retry(Bridge *b, struct optimism *o, long ret)
{
    if (!b->optimistic_used)
        return false;
    broker_strict(0);
    if (ret != -ELOOP)
        return false;
    if (!o->hints) {
        long mem = raw_syscall(__NR_mmap, 0, sizeof(*o->hints), 3, 0x22, -1, 0);
        o->hints = (unsigned long)mem >= (unsigned long)-4095 ? NULL : (void *)mem;
        if (o->hints) o->hints->count = 0;
    }
    struct link_hints *h = o->hints;
    o->on = !b->force_full && h && h->count < LINK_HINTS &&
        broker_link_report(h->path[h->count], h->target[h->count]) &&
        climbing_target(h->target[h->count]);
    if (o->on) h->count++;
    return true;
}

static void optimism_end(struct optimism *o)
{
    if (o->hints) raw_syscall(__NR_munmap, (long)o->hints, sizeof(*o->hints), 0, 0, 0, 0);
}

static long bridge_run(long number, long args[6], const struct proot_open_origin *anchor,
                       struct proot_open_origin *origin, const struct proot_path_context *context)
{
    long saved[6];
    memcpy(saved, args, sizeof(saved));
    struct optimism o = {g_payload_config.isolate && !union_enabled(), NULL};
    for (;;) {
        Bridge *b;
        long ret = bridge_create(&b);
        if (ret < 0) {
            optimism_end(&o);
            return ret;
        }
        b->context = context;
        if (anchor) {
            b->anchor = *anchor;
            b->anchor_fd = (number == __NR_chdir || number == __NR_getcwd) ? AT_FDCWD : (int)args[0];
        }
        optimism_begin(b, &o);
        ret = pb_dispatch(b, number, args, origin);
        if (g_payload_config.guard == GUARD_READS && number == __NR_openat && ret >= 0 &&
            g_payload_config.isolate && b->guest[0] == '/') {
            struct stat dir;
            if (!raw_syscall(__NR_fstat, ret, (long)&dir, 0, 0, 0, 0) && (dir.st_mode & S_IFMT) == S_IFDIR)
                cached_dir_name((int)ret, b->guest, &dir, true);
        }
        bool again = optimism_retry(b, &o, ret);
        bridge_release(b);
        if (!again) {
            optimism_end(&o);
            return ret;
        }
        memcpy(args, saved, sizeof(saved));
    }
}

static long bridge_syscall(long number, long args[6], const struct proot_open_origin *anchor,
                           struct proot_open_origin *origin)
{
    if (!proot_handles_syscall(number))
        return -ENOSYS;
    return bridge_run(number, args, anchor, origin, NULL);
}

long proot_syscall(long number, long args[6])
{
    return bridge_syscall(number, args, NULL, NULL);
}

long proot_openat(long args[6], const struct proot_open_origin *anchor,
                  struct proot_open_origin *origin)
{
    if (!origin) return -EINVAL;
    *origin = (struct proot_open_origin){0, false};
    return bridge_syscall(__NR_openat, args, anchor, origin);
}

long proot_cwd(long number, long args[6], const struct proot_open_origin *anchor,
               struct proot_open_origin *origin)
{
    if (!origin || (number != __NR_chdir && number != __NR_fchdir && number != __NR_getcwd))
        return -EINVAL;
    *origin = (struct proot_open_origin){0, false};
    return bridge_syscall(number, args, anchor, origin);
}

long proot_context_syscall(long number, long args[6], const struct proot_path_context *context)
{
    if (!context || !proot_handles_syscall(number)) return -EINVAL;
    return bridge_run(number, args, NULL, NULL, context);
}

int proot_resolve_exec_path(int dirfd, const char *path, bool follow,
                            char *guest, char *host, size_t capacity,
                            const struct proot_path_context *context)
{
    if (!guest || !host || !capacity)
        return -EINVAL;
    Bridge *b;
    long ret = bridge_create(&b);
    if (ret < 0)
        return (int)ret;
    b->context = context;
    ret = pb_resolve(b, dirfd, path, follow);
    if (!ret) {
        if (strlen(b->guest) >= capacity || strlen(b->host) >= capacity)
            ret = -ENAMETOOLONG;
        else {
            strcpy(guest, b->guest);
            strcpy(host, b->host);
            ret = union_lazy_fill(b->final_view, b->host);
        }
    }
    bridge_release(b);
    return (int)ret;
}

long proot_open_exec_path(int dirfd, const char *path, bool follow,
                          char *guest, char *host, size_t capacity,
                          const struct proot_path_context *context)
{
    if (!guest || !host || !capacity)
        return -EINVAL;
    struct optimism o = {true, NULL};
    for (;;) {
        Bridge *b;
        long ret = bridge_create(&b);
        if (ret < 0) {
            optimism_end(&o);
            return ret;
        }
        b->context = context;
        optimism_begin(b, &o);
        ret = pb_resolve(b, dirfd, path, follow);
        if (!ret && (strlen(b->guest) >= capacity || strlen(b->host) >= capacity))
            ret = -ENAMETOOLONG;
        if (!ret) {
            strcpy(guest, b->guest);
            strcpy(host, b->host);
            ret = union_lazy_fill(b->final_view, b->host);
            if (!ret)
                ret = raw_syscall(__NR_openat, AT_FDCWD, (long)b->host, O_RDONLY | (follow ? 0 : O_NOFOLLOW),
                                  0, 0, 0);
        }
        bool again = optimism_retry(b, &o, ret);
        bridge_release(b);
        if (!again) {
            optimism_end(&o);
            return ret;
        }
    }
}

long proot_open_beneath(int dirfd, const char *path, unsigned long flags,
                        const struct proot_open_origin *hint, struct proot_open_origin *origin)
{
    if (!origin) return -EINVAL;
    *origin = (struct proot_open_origin){0, false};
    if (!path) return -EFAULT;
    char name[PATH_MAX];
    size_t length = strnlen(path, sizeof(name));
    if (length == sizeof(name)) return -ENAMETOOLONG;
    memcpy(name, path, length + 1);
    if (!length) return -ENOENT;
    if (name[0] == '/' || !strcmp(name, "..")) return -EXDEV;
    int trailing = name[length - 1] == '/';
    if (trailing) {
        if (!(flags & O_DIRECTORY)) return -EOPNOTSUPP;
        while (length && name[length - 1] == '/') name[--length] = 0;
        if (!strcmp(name, "..")) return -EXDEV;
    }
    if (strchr(name, '/')) return -EOPNOTSUPP;
    Bridge *b;
    long ret = bridge_create(&b);
    if (ret < 0) return ret;
    long anchor = dirfd;
    if (dirfd == AT_FDCWD) {
        anchor = raw_syscall(__NR_openat, AT_FDCWD, (long)".",
                             O_PATH | O_DIRECTORY | O_CLOEXEC, 0, 0, 0);
        if (anchor < 0) { ret = anchor; goto out; }
    }
    if (hint) { b->anchor = *hint; b->anchor_fd = (int)anchor; }
    b->traverse = true;
    ret = pb_host_fd(b, (int)anchor, b->first_guest);
    if (ret < 0) goto close_anchor;
    size_t base_mount, target_mount;
    ret = binding_table_mount_id(&b->table, b->first_guest, &base_mount);
    if (ret < 0) goto close_anchor;
    ret = pb_resolve(b, (int)anchor, name, false);
    if (ret < 0) goto close_anchor;
    ret = binding_table_mount_id(&b->table, b->guest, &target_mount);
    if (ret < 0) goto close_anchor;
    if (base_mount != target_mount) { ret = -EOPNOTSUPP; goto close_anchor; }
    ret = raw_syscall(__NR_openat, anchor, (long)name, flags, 0, 0, 0);
    if (trailing && ret == -ENOTDIR) ret = -EOPNOTSUPP;
    if (ret >= 0 && b->anchor.known)
        *origin = (struct proot_open_origin){target_mount, true};
close_anchor:
    if (dirfd == AT_FDCWD) raw_syscall(__NR_close, anchor, 0, 0, 0, 0, 0);
out:
    bridge_release(b);
    return ret;
}
