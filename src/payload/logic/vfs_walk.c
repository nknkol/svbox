/* SPDX-License-Identifier: MIT */
/* VFS path resolution, merged-view lookup, reverse mapping, guarded mount
 * root walking, and union copy-up/create preparation. */
#include "vfs_bridge_internal.h"

/* The view holding a host path (union_find), NULL if none. */
static const struct union_view *bridge_view(Bridge *b, const char *host, int *layer, const char **rel)
{
    int v = union_find(b->views, b->view_count, host, layer, rel);
    return v < 0 ? NULL : &b->views[v];
}

int pb_bridge_alias(Bridge *b, const char *host, char *out)
{
    return b->root_union ? union_alias(&b->views[0], host, out) : 0;
}

/* The view whose upper holds host (the longest), NULL if none. */
static const struct union_view *upper_view(Bridge *b, const char *host)
{
    const struct union_view *best = NULL;
    for (int v = 0; v < b->view_count; v++) {
        const struct union_view *u = &b->views[v];
        size_t n = u->length[0];
        if (!strncmp(host, u->layer[0], n) && (host[n] == 0 || host[n] == '/') &&
            (!best || n > best->length[0]))
            best = u;
    }
    return best;
}

static void respell(void *opaque, char *path)
{
    Bridge *b = opaque;
    for (size_t i = 0; i < b->table.count && i < (size_t)g_payload_config.bind_count; i++) {
        const PathBinding *e = &b->table.entries[i];
        uint32_t fold = g_payload_config.binds[i].fold;
        if (!fold || e->guest == UNMOUNTED) continue;
        size_t from = fold - 1, n = strlen(e->guest), k = from;
        if (strncmp(path, e->guest, from)) continue;
        for (; k < n; k++) {
            char x = path[k], y = e->guest[k];
            if (x >= 'A' && x <= 'Z') x |= 0x20;
            if (y >= 'A' && y <= 'Z') y |= 0x20;
            if (x != y) break;
        }
        if (k == n && (path[n] == '\0' || path[n] == '/'))
            memcpy(path + from, e->guest + from, n - from);
    }
}

static PathFrame *deep_frames(void *opaque)
{
    Bridge *b = opaque;
    if (!b->deep_frames) {
        long mem = raw_syscall(__NR_mmap, 0, DEEP_FRAMES_SIZE, 3, 0x22, -1, 0);
        if ((unsigned long)mem >= (unsigned long)-4095)
            return NULL;
        b->deep_frames = (PathFrame *)mem;
    }
    return b->deep_frames;
}

static int host_map_hit(Bridge *b, const char *guest, char *host, struct union_hit *hit_out)
{
    if (!hit_out && b->last_map_valid && !strcmp(guest, b->last_map_guest)) {
        strcpy(host, b->last_map_host);
        b->map_view = b->last_map_view;
        return 0;
    }
    int rc = binding_table_map(&b->table, GUEST, guest, host);
    if (rc >= 0 && b->union_on) {
        pb_bridge_alias(b, host, host);
        const struct union_view *view = upper_view(b, host);
        b->map_view = view;
        if (view) {
            int u = union_map(view, host, hit_out, &b->umemo);
            if (u < 0) return u;
        } else if (hit_out) {
            hit_out->layer = -1;
            hit_out->has_stat = false;
            hit_out->dirs = 0;
        }
    } else if (hit_out) {
        hit_out->layer = -1;
        hit_out->has_stat = false;
        hit_out->dirs = 0;
    }
    if (rc >= 0 && strlen(guest) < PATH_MAX && strlen(host) < PATH_MAX) {
        strcpy(b->last_map_guest, guest);
        strcpy(b->last_map_host, host);
        b->last_map_view = b->map_view;
        b->last_map_valid = true;
    }
    return rc;
}

int pb_host_map(void *opaque, const char *guest, char *host)
{
    return host_map_hit(opaque, guest, host, NULL);
}

/* Lexical decision for a canonical guest path, before any host lookup. */
int pb_path_visibility(Bridge *b, const char *guest)
{
    if (!b->reads) return FS_VISIBLE;
    size_t length = strnlen(guest, PATH_MAX);
    if (length == PATH_MAX) return -ENAMETOOLONG;
    memcpy(b->classified, guest, length + 1);
    for (;;) {
        if (length > 1 && b->classified[length - 1] == '/') b->classified[--length] = 0;
        else if (length > 2 && !strcmp(b->classified + length - 2, "/."))
            b->classified[length -= 2] = 0;
        else break;
    }
    if (!length || !strcmp(b->classified, "/.")) strcpy(b->classified, "/");
    size_t mount;
    int rc = binding_table_mount_id(&b->table, b->classified, &mount);
    if (rc < 0) return rc;
    return fs_policy_visibility(&b->policy, mount, b->classified, b->exposed, b->exposed_count);
}

int pb_watch_hides_child(Bridge *b, const char *guest)
{
    size_t length = strlen(guest);
    for (size_t i = 0; b->reads && i < b->table.count; i++) {
        const char *child = b->table.entries[i].guest;
        size_t parent = 0;
        for (size_t j = 1; child[j]; j++)
            if (child[j] == '/') parent = j;
        if (!parent) parent = 1; /* Direct child of "/". */
        if (parent != length || strncmp(child, guest, length)) continue;
        int visibility = pb_path_visibility(b, child);
        if (visibility < 0) return visibility;
        if (visibility == FS_HIDDEN) return -EACCES;
    }
    return 0;
}

static int host_lookup(void *opaque, Finality finality, unsigned int depth,
                       const char *guest, char *host)
{
    (void)depth;
    Bridge *b = opaque;
    int visibility = pb_path_visibility(b, guest);
    if (visibility < 0) return visibility;
    if (visibility == FS_HIDDEN) return -EACCES;

    struct union_hit hit;
    hit.layer = -1;
    hit.has_stat = false;
    hit.dirs = 0;
    int rc = host_map_hit(b, guest, host, b->union_on ? &hit : NULL);
    if (rc < 0)
        return rc;

    if (b->optimistic && (!strcmp(guest, "/") || !pb_glue_ancestor(b, guest))) {
        for (int i = 0; b->hints && i < b->hints->count; i++)
            if (!strcmp(b->hints->path[i], host))
                return 1;
        return 0;
    }

    /* If union_map already gave us the stat of a final symlink during a
     * deferred open, report it immediately so openat skips the wasted ELOOP. */
    if (finality == FINAL_NORMAL && b->defer_final && b->follow_final &&
        hit.has_stat && (hit.st.st_mode & S_IFMT) == S_IFLNK)
        return 1;

    if (finality == FINAL_NORMAL && (!b->follow_final || b->defer_final))
        return 0;
    if (!strcmp(guest, "/"))
        return 0;
    for (size_t i = 0; i < b->table.count; i++)
        if (!strcmp(guest, b->table.entries[i].guest))
            return 0;

    struct stat st;
    if (b->union_on && b->map_view) {
        if (hit.has_stat) {
            st = hit.st;
            goto have_stat;
        }
        if (hit.layer == -1 && hit.dirs == 0) {
            if (pb_glue_ancestor(b, guest))
                return 0;
            return IS_FINAL(finality) ? 0 : -ENOENT;
        }
    }

    long ret = raw_syscall(__NR_newfstatat, AT_FDCWD, (long)host, (long)&st,
                          AT_SYMLINK_NOFOLLOW, 0, 0);
    if (ret == -ENOENT && pb_glue_ancestor(b, guest))
        return 0;
    if (ret == -EACCES) {
        char probe[1];
        long link = raw_syscall(__NR_readlinkat, AT_FDCWD, (long)host, (long)probe, 1, 0, 0);
        if (link >= 0)
            return 1;
        if (link == -EINVAL)
            return 0;
    }
    if (ret < 0)
        return IS_FINAL(finality) ? 0 : (int)ret;

have_stat:;
    unsigned int type = st.st_mode & S_IFMT;
    if (!IS_FINAL(finality) && type != S_IFDIR && type != S_IFLNK)
        return -ENOTDIR;
    if (IS_FINAL(finality) && type != S_IFLNK && strlen(host) < PATH_MAX) {
        b->final_stat = st;
        strcpy(b->final_host, host);
        b->final_valid = true;
    }
    return type == S_IFLNK;
}

int pb_host_readlink(void *opaque, const char *path, char *out, size_t size)
{
    const Bridge *b = opaque;
    for (int i = 0; b->optimistic && b->hints && i < b->hints->count; i++)
        if (!strcmp(b->hints->path[i], path)) {
            size_t n = strlen(b->hints->target[i]);
            if (n > size) n = size;
            memcpy(out, b->hints->target[i], n);
            return (int)n;
        }
    if (b->root_union && !g_payload_config.isolate) {
        int cached = vfs_ro_readlink(path, out, size);
        if (cached != -EAGAIN)
            return cached;
    }
    return (int)raw_syscall(__NR_readlinkat, AT_FDCWD, (long)path, (long)out,
                           size, 0, 0);
}

int pb_guest_link_target(Bridge *b, char *target)
{
    if (target[0] != '/') return 0;
    int guarded = g_payload_config.guard == GUARD_READS;
    int rc = pb_preferred_guest_path(b, target, b->proc_guest);
    if (rc < 0) return guarded ? -EACCES : 0;
    rc = pb_path_visibility(b, b->proc_guest);
    if (rc < 0) return rc;
    if (rc == FS_HIDDEN) return -EACCES;
    strcpy(target, b->proc_guest);
    return 0;
}

static int ordinary_link(void *opaque, char *path, const char *referrer)
{
    Bridge *b = opaque;
    if (binding_table_map(&b->table, GUEST, "/proc", b->proc_link_host) < 0)
        return 0;
    Comparison c = compare_paths(b->proc_link_host, referrer);
    if (c != PATH1_IS_PREFIX) return 0;
    return pb_guest_link_target(b, path);
}

static bool union_same(Bridge *b, const char *named, const char *mapped)
{
    if (!b->union_on) return false;
    const char *rel;
    const struct union_view *u = b->map_view;
    if (!u || union_layer_of(u, mapped, &rel) < 0) return false;
    size_t n = u->length[0];
    return !strncmp(named, u->layer[0], n) && !strcmp(named + n, rel);
}

static int visible_guest_path(Bridge *b, const char *host, char *guest)
{
    char *mapped = b->mapped;
    if (pb_glue_guest(host, guest)) return 0;
    const char *alias = NULL;
    if (b->union_on && pb_bridge_alias(b, host, b->union_named))
        alias = b->union_named;
    if (binding_table_map(&b->table, HOST, host, guest) >= 0 &&
        pb_host_map(b, guest, mapped) >= 0 &&
        (!strcmp(host, mapped) || (alias && union_same(b, alias, mapped))))
        return 0;
    const char *named = alias ? alias : host;
    int rc = binding_table_map(&b->table, HOST, named, guest);
    if (rc < 0) return rc;
    rc = pb_host_map(b, guest, mapped);
    if (rc < 0) return rc;
    return strcmp(host, mapped) && !union_same(b, named, mapped) ? -EXDEV : 0;
}

static int observed_guest_path_len(Bridge *b, const char *host, char *guest, size_t *matched_out)
{
    int rc;
    if (pb_glue_guest(host, guest)) {
        if (matched_out) *matched_out = 0;
        return 0;
    }
    size_t id = b->anchor.mount_id, mapped_id;
    if (id > b->table.count) return -EXDEV;
    const char *host_prefix = id ? b->table.entries[id-1].host : b->table.root;
    const char *guest_prefix = id ? b->table.entries[id-1].guest : "/";
    const char *named = host;
    bool aliased = false;
    Comparison prefix_match = compare_paths(host_prefix, named);
    if (prefix_match != PATHS_ARE_EQUAL && prefix_match != PATH1_IS_PREFIX) {
        if (b->union_on && pb_bridge_alias(b, host, b->union_named)) {
            named = b->union_named;
            aliased = true;
            prefix_match = compare_paths(host_prefix, named);
        }
    }
    if (prefix_match != PATHS_ARE_EQUAL && prefix_match != PATH1_IS_PREFIX)
        return -EXDEV;
    strcpy(guest, named);
    rc = binding_replace_core(guest, host_prefix, guest_prefix);
    if (rc < 0) return rc;
    rc = binding_table_mount_id(&b->table, guest, &mapped_id);
    if (rc < 0) return rc;
    if (mapped_id != id) return -EXDEV;
    char *mapped = b->mapped;
    rc = pb_host_map(b, guest, mapped);
    if (rc < 0) return rc;
    if (strcmp(host, mapped)) {
        const char *upper_form = aliased ? named : host;
        if (!aliased && b->union_on && pb_bridge_alias(b, host, b->union_named))
            upper_form = b->union_named;
        if (!union_same(b, upper_form, mapped))
            return -EXDEV;
    }
    if (matched_out) {
        size_t plen = strlen(host_prefix);
        if (aliased && b->root_union) {
            const char *rel = NULL;
            int layer = union_layer_of(&b->views[0], host, &rel);
            if (layer > 0) {
                size_t ulen = b->views[0].length[0];
                size_t llen = b->views[0].length[layer];
                plen = (plen >= ulen) ? (llen + (plen - ulen)) : llen;
            }
        }
        *matched_out = plen;
    }
    return 0;
}

int pb_observed_guest_path(Bridge *b, const char *host, char *guest)
{
    return observed_guest_path_len(b, host, guest, NULL);
}

int pb_preferred_guest_path(Bridge *b, const char *host, char *guest)
{
    struct proot_open_origin saved = b->anchor;
    size_t best = 0;
    int found = 0;
    for (size_t id = 0; id <= b->table.count; id++) {
        b->anchor = (struct proot_open_origin){id, true};
        size_t matched = 0;
        if (observed_guest_path_len(b, host, b->proc_candidate, &matched)) continue;
        if (found && matched <= best) continue;
        if (pb_path_visibility(b, b->proc_candidate) == FS_HIDDEN) continue;
        strcpy(guest, b->proc_candidate);
        best = matched;
        found = 1;
    }
    b->anchor = saved;
    return found ? 0 : -EXDEV;
}

static void select_anchor(Bridge *b, int fd)
{
    if (!b->context) return;
    b->anchor_fd = fd;
    b->anchor = (struct proot_open_origin){0, false};
    if (fd == AT_FDCWD) b->anchor = b->context->cwd;
    else for (size_t i = 0; i < 2; i++)
        if (b->context->fd[i] == fd) { b->anchor = b->context->directory[i]; break; }
}

int pb_host_fd(void *opaque, int fd, char *guest)
{
    Bridge *b = opaque;
    select_anchor(b, fd);
    struct stat st;
    long ret = raw_syscall(__NR_fstat, fd, (long)&st, 0, 0, 0, 0);
    if (ret < 0)
        return (int)ret;
    if ((st.st_mode & S_IFMT) != S_IFDIR)
        return -ENOTDIR;

    char link[64] = "/proc/self/fd/", digits[16], *host = b->fd_host;
    unsigned int value = (unsigned int)fd;
    size_t count = 0, pos = strlen(link);
    do {
        digits[count++] = '0' + value % 10;
        value /= 10;
    } while (value);
    while (count)
        link[pos++] = digits[--count];
    link[pos] = 0;

    int rc = pb_host_readlink(opaque, link, host, PATH_MAX);
    if (rc < 0)
        return rc;
    if (rc >= PATH_MAX)
        return -ENAMETOOLONG;
    host[rc] = 0;
    if (b->anchor.known && fd == b->anchor_fd)
        return pb_observed_guest_path(b, host, guest);
    return visible_guest_path(b, host, guest);
}

long pb_guest_cwd(Bridge *b)
{
    select_anchor(b, AT_FDCWD);
    long ret = raw_syscall(__NR_getcwd, (long)b->host, sizeof(b->host), 0, 0, 0, 0);
    if (ret < 0)
        return ret;
    if (b->anchor.known && b->anchor_fd == AT_FDCWD)
        return pb_observed_guest_path(b, b->host, b->cwd);
    return visible_guest_path(b, b->host, b->cwd);
}

static int resolve_once(Bridge *b, int dirfd, const char *path, bool follow);

#define RACED 1
static long mount_root_fd[CONFIG_MOUNT_IDS];
static unsigned long mount_root_dev[CONFIG_MOUNT_IDS], mount_root_ino[CONFIG_MOUNT_IDS];
static uint32_t mount_root_tag[CONFIG_MOUNT_IDS];

static long mount_root(Bridge *b, size_t mount, const char *prefix, size_t plen)
{
    if (mount >= CONFIG_MOUNT_IDS) return -EINVAL;
    size_t slot = mount - 1 - (size_t)g_payload_config.bind_count;
    uint32_t tag = mount > (size_t)g_payload_config.bind_count && slot < (size_t)b->mount_count ?
        b->mounts[slot].id : 0;
    long fd = __atomic_load_n(&mount_root_fd[mount], __ATOMIC_ACQUIRE) - 1;
    struct stat st;
    if (fd >= 0 && __atomic_load_n(&mount_root_tag[mount], __ATOMIC_ACQUIRE) == tag &&
        !raw_syscall(__NR_fstat, fd, (long)&st, 0, 0, 0, 0) &&
        st.st_dev == __atomic_load_n(&mount_root_dev[mount], __ATOMIC_ACQUIRE) &&
        st.st_ino == __atomic_load_n(&mount_root_ino[mount], __ATOMIC_ACQUIRE) &&
        (st.st_mode & S_IFMT) == S_IFDIR)
        return fd;
    memcpy(b->mapped, plen ? prefix : "/", plen ? plen : 1);
    b->mapped[plen ? plen : 1] = 0;
    long opened = raw_syscall(__NR_openat, AT_FDCWD, (long)b->mapped,
                              O_PATH | O_DIRECTORY | O_CLOEXEC, 0, 0, 0);
    if (opened < 0) return opened;
    long high = raw_syscall(__NR_fcntl, opened, F_DUPFD_CLOEXEC, 512, 0, 0, 0);
    if (high >= 0) { raw_syscall(__NR_close, opened, 0, 0, 0, 0, 0); opened = high; }
    if (raw_syscall(__NR_fstat, opened, (long)&st, 0, 0, 0, 0) < 0) return opened;
    __atomic_store_n(&mount_root_tag[mount], tag, __ATOMIC_RELEASE);
    __atomic_store_n(&mount_root_dev[mount], st.st_dev, __ATOMIC_RELEASE);
    __atomic_store_n(&mount_root_ino[mount], st.st_ino, __ATOMIC_RELEASE);
    __atomic_store_n(&mount_root_fd[mount], opened + 1, __ATOMIC_RELEASE);
    return opened;
}

static int secure_host(Bridge *b)
{
    if (!b->secure) return 0;
    if (b->walk_count >= 4) return -ENFILE;
    size_t mount;
    if (binding_table_mount_id(&b->table, b->guest, &mount) < 0) return 0;
    const char *prefix = mount ? b->table.entries[mount - 1].host : b->table.root;
    size_t plen = strlen(prefix);
    while (plen > 1 && prefix[plen - 1] == '/') plen--;
    if (!strncmp(prefix, "/proc", 5) && (plen == 5 || prefix[5] == '/')) return 0;
    if (plen == 1) plen = 0;
    if (strncmp(b->host, prefix, plen) || (b->host[plen] && b->host[plen] != '/'))
        return 0;
    const char *rest = b->host + plen;
    size_t end = strlen(rest);
    while (end && rest[end - 1] == '/') end--;
    if (!end) return 0;
    size_t base = end;
    while (base && rest[base - 1] != '/') base--;
    if (plen >= PATH_MAX) return -ENAMETOOLONG;
    long root = mount_root(b, mount, prefix, plen);
    if (root < 0) return (int)root;
    long dir = root;
    for (size_t at = 0; at < base;) {
        while (at < base && rest[at] == '/') at++;
        size_t next = at;
        while (next < base && rest[next] != '/') next++;
        if (next == at) break;
        memcpy(b->mapped, rest + at, next - at);
        b->mapped[next - at] = 0;
        long child = raw_syscall(__NR_openat, dir, (long)b->mapped,
                                 O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0, 0, 0);
        if (dir != root) raw_syscall(__NR_close, dir, 0, 0, 0, 0, 0);
        if (child < 0) return child == -ELOOP || child == -ENOTDIR ? RACED : (int)child;
        dir = child;
        at = next;
    }
    if (dir == root) {
        dir = raw_syscall(__NR_fcntl, root, F_DUPFD_CLOEXEC, 256, 0, 0, 0);
        if (dir < 0) return (int)dir;
    }
    bool whole = b->follow_final && !b->defer_final;
    if (whole) {
        memcpy(b->mapped, rest + base, end - base);
        b->mapped[end - base] = 0;
        long node = raw_syscall(__NR_openat, dir, (long)b->mapped, O_PATH | O_NOFOLLOW | O_CLOEXEC,
                                0, 0, 0);
        raw_syscall(__NR_close, dir, 0, 0, 0, 0, 0);
        if (node < 0) return (int)node;
        struct stat now;
        if (raw_syscall(__NR_fstat, node, (long)&now, 0, 0, 0, 0) < 0 ||
            (now.st_mode & S_IFMT) == S_IFLNK ||
            (b->final_valid && (now.st_dev != b->final_stat.st_dev ||
                                now.st_ino != b->final_stat.st_ino))) {
            raw_syscall(__NR_close, node, 0, 0, 0, 0, 0);
            return RACED;
        }
        dir = node;
    }
    long high = raw_syscall(__NR_fcntl, dir, F_DUPFD_CLOEXEC, 256, 0, 0, 0);
    if (high >= 0) {
        raw_syscall(__NR_close, dir, 0, 0, 0, 0, 0);
        dir = high;
    }
    char name[40] = "/proc/self/fd/";
    size_t n = strlen(name);
    char digits[12];
    int count = 0;
    unsigned long v = (unsigned long)dir;
    do { digits[count++] = '0' + v % 10; v /= 10; } while (v);
    while (count) name[n++] = digits[--count];
    if (whole) {
        name[n] = 0;
        strcpy(b->host, name);
        b->walk_fd[b->walk_count++] = (int)dir;
        return 0;
    }
    name[n++] = '/';
    size_t tail = strlen(rest + base);
    if (n + tail >= PATH_MAX) { raw_syscall(__NR_close, dir, 0, 0, 0, 0, 0); return -ENAMETOOLONG; }
    memmove(b->host + n, rest + base, tail + 1);
    memcpy(b->host, name, n);
    b->walk_fd[b->walk_count++] = (int)dir;
    return 0;
}

bool pb_lexical_path(const char *path)
{
    for (const char *p = path; *p;) {
        while (*p == '/') p++;
        if (p[0] == '.' && p[1] == '.' && (!p[2] || p[2] == '/')) return false;
        while (*p && *p != '/') p++;
    }
    return true;
}

static int union_prepare(Bridge *b)
{
    const char *rel = "";
    b->uv = b->final_view;
    int layer = b->uv ? union_layer_of(b->uv, b->host, &rel) : -1;
    if (layer < 0) b->uv = NULL;
    b->union_layer = layer;
    if (layer < 0) return 0;
    if (strlen(rel) >= PATH_MAX) return -ENAMETOOLONG;
    strcpy(b->union_rel, rel);
    long rc = 0;
    switch (b->union_op) {
    case UOP_OPEN: {
        long f = b->open_flags;
        bool tmpfile = (f & O_TMPFILE) == O_TMPFILE;
        bool writes = (f & O_ACCMODE) != O_RDONLY || (f & O_TRUNC) || tmpfile;
        if (layer > 0) {
            if (!writes) return (int)union_lazy_fill(b->uv, b->host);
            if ((f & O_CREAT) && (f & O_EXCL)) return -EEXIST;
            rc = union_copy_up(b->uv, b->union_rel, !(f & O_TRUNC) || tmpfile);
            break;
        }
        struct stat st;
        if (!(f & O_CREAT) || tmpfile ||
            !raw_syscall(__NR_newfstatat, AT_FDCWD, (long)b->host, (long)&st, AT_SYMLINK_NOFOLLOW, 0, 0))
            return 0;
        bool opaque;
        rc = union_prepare_create(b->uv, b->union_rel, &opaque);
        if (rc == -EEXIST) rc = 0;
        break;
    }
    case UOP_COPY:
        if (layer == 0) return 0;
        rc = union_copy_up(b->uv, b->union_rel, true);
        break;
    case UOP_CREATE:
        if (layer > 0) return -EEXIST;
        rc = union_prepare_create(b->uv, b->union_rel, &b->union_opaque);
        if (rc == -EEXIST) rc = 0;
        break;
    default:
        return 0;
    }
    if (rc < 0) return (int)rc;
    b->umemo.valid = false;
    b->last_map_valid = false;
    if (layer > 0) {
        size_t n = b->uv->length[0];
        if (n + strlen(b->union_rel) >= PATH_MAX) return -ENAMETOOLONG;
        memcpy(b->host, b->uv->layer[0], n);
        strcpy(b->host + n, b->union_rel);
        b->union_layer = 0;
        b->final_valid = false;
    }
    return 0;
}

int pb_union_fd(Bridge *b, int fd)
{
    char link[32] = "/proc/self/fd/", digits[12];
    size_t at = strlen(link);
    int count = 0;
    unsigned v = (unsigned)fd;
    do { digits[count++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (count) link[at++] = digits[--count];
    link[at] = 0;
    int n = pb_host_readlink(b, link, b->fd_host, PATH_MAX - 1);
    if (n < 0) return n == -ENOENT ? -EBADF : n;
    b->fd_host[n] = 0;
    const char *rel;
    int layer = -1;
    b->uv = bridge_view(b, b->fd_host, &layer, &rel);
    if (layer > 0) strcpy(b->union_rel, rel);
    return layer;
}

int pb_resolve(Bridge *b, int dirfd, const char *path, bool follow)
{
    b->optimistic = b->optimistic_allowed && path && pb_lexical_path(path);
    if (b->optimistic && !b->optimistic_used) {
        b->optimistic_used = true;
        broker_strict(1);
    }
    int rc = resolve_once(b, dirfd, path, follow);
    Comparison proc = rc >= 0 && b->optimistic ? compare_paths("/proc", b->guest) : PATHS_ARE_NOT_COMPARABLE;
    if (proc == PATHS_ARE_EQUAL || proc == PATH1_IS_PREFIX) {
        b->force_full = true;
        return -ELOOP;
    }
    if (rc < 0 && b->defer_final) {
        b->defer_final = false;
        rc = resolve_once(b, dirfd, path, follow);
    }
    b->final_match = rc >= 0 && b->final_valid && !strcmp(b->final_host, b->host);
    for (int attempt = 0; rc >= 0 && attempt < 2; attempt++) {
        int s = secure_host(b);
        if (s != RACED) return s < 0 ? s : rc;
        if (attempt) return -ELOOP;
        rc = resolve_once(b, dirfd, path, follow);
        b->final_match = rc >= 0 && b->final_valid && !strcmp(b->final_host, b->host);
    }
    return rc;
}

static int resolve_once(Bridge *b, int dirfd, const char *path, bool follow)
{
    if (!path)
        return -EFAULT;
    b->umemo.valid = false;
    b->last_map_valid = false;
    b->union_layer = -1;
    strcpy(b->cwd, "/");
    if (path[0] != '/' && dirfd == AT_FDCWD) {
        long ret = pb_guest_cwd(b);
        if (ret < 0)
            return (int)ret;
    }
    PathOps ops;
    ops.lookup = host_lookup;
    ops.readlink = pb_host_readlink;
    ops.detranslate = ordinary_link;
    ops.proc_link = pb_proc_link;
    ops.respell = respell;
    PathResolver resolver = {{b, &ops, b->path_frames, BRIDGE_FRAMES, deep_frames}, b->cwd,
                             pb_host_fd, pb_host_map, b->resolve_scratch};
    b->follow_final = follow;
    b->final_valid = false;
    b->map_view = NULL;
    int rc = resolve_path_core(&resolver, dirfd, path, follow, b->guest, b->host);
    b->final_view = b->map_view;
    if (rc >= 0) {
        int glue = pb_glue_host(b);
        if (glue < 0) return glue;
        if (glue && b->mutation) {
            struct stat st;
            if (b->attributes) return -EPERM;
            if (!b->creates || raw_syscall(__NR_newfstatat, AT_FDCWD, (long)b->host, (long)&st,
                                           AT_SYMLINK_NOFOLLOW, 0, 0) < 0)
                return -EACCES;
        }
    }
    if (rc >= 0 && b->reads) {
        int visibility = pb_path_visibility(b, b->guest);
        if (visibility < 0) return visibility;
        if (visibility == FS_HIDDEN || (visibility == FS_TRAVERSE && !b->traverse))
            return -EACCES;
    }
    if (rc >= 0 && b->mutation && g_payload_config.guard >= GUARD_PATHS &&
        !(mounts_enabled() && pb_loop_device(b->guest) != -1)) {
        size_t mount;
        rc = binding_table_mount_id(&b->table, b->guest, &mount);
        if (rc < 0) return rc;
        rc = fd_runtime_check_path_mutation(mount, path[0] == '/' || b->anchor.known);
        struct stat st;
        if (rc == -EROFS && b->creates &&
            !raw_syscall(__NR_newfstatat, AT_FDCWD, (long)b->host, (long)&st,
                         AT_SYMLINK_NOFOLLOW, 0, 0))
            rc = -EEXIST;
    }
    if (rc >= 0 && b->union_on) {
        int u = union_prepare(b);
        if (u < 0) return u;
    }
    return rc;
}
