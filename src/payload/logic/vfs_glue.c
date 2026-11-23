/* SPDX-License-Identifier: MIT */
/* Synthetic bind-mount parent glue tree (PRoot "glue"): a guest directory
 * missing from the host root that leads to a bind destination is served from
 * a shared private read-only mirror tree so it can be opened, listed and
 * entered without writing into the host root. */
#include "vfs_bridge_internal.h"

/* PRoot "glue": a guest directory that does not exist on the host but leads
 * to a bind destination (component-wise strict ancestor of one). */
bool pb_glue_ancestor(const Bridge *b, const char *guest)
{
    size_t length = strlen(guest);
    for (size_t i = 0; i < b->table.count; i++) {
        const char *target = b->table.entries[i].guest;
        if (length == 1 && guest[0] == '/') {
            if (target[1]) return true;
            continue;
        }
        if (!strncmp(target, guest, length) && target[length] == '/' && target[length + 1])
            return true;
    }
    return false;
}

static char glue_name[PATH_MAX];
static int glue_named, glue_state, glue_scanned;
static unsigned short glue_missing[CONFIG_MAX_BINDS];

static const char *glue_tree(void)
{
    const payload_config_t *cfg = &g_payload_config;
    if (__atomic_load_n(&glue_named, __ATOMIC_ACQUIRE))
        return glue_named > 0 ? glue_name : NULL;
    unsigned long long hash = 0xcbf29ce484222325ULL;
    long uid = raw_syscall(__NR_getuid, 0, 0, 0, 0, 0, 0);
    for (int i = -2; i < cfg->bind_count; i++) {
        const unsigned char *p = (const unsigned char *)(i == -2 ? "" : i == -1 ? cfg->root :
                                                         cfg->binds[i].src);
        for (int pass = 0; pass < 2; pass++) {
            for (; *p; p++) hash = (hash ^ *p) * 0x100000001b3ULL;
            hash = (hash ^ (pass ? 0 : 0xff)) * 0x100000001b3ULL;
            if (i < 0) break;
            p = (const unsigned char *)cfg->binds[i].dst;
        }
    }
    hash = (hash ^ (unsigned long long)uid) * 0x100000001b3ULL;
    size_t length = strlen(cfg->glue_dir);
    int named = -1;
    if (cfg->glue_dir[0] == '/' && length + 32 < PATH_MAX) {
        memcpy(glue_name, cfg->glue_dir, length);
        while (length > 1 && glue_name[length - 1] == '/') length--;
        memcpy(glue_name + length, "/proot-glue-", 12);
        length += 12;
        for (int shift = 60; shift >= 0; shift -= 4)
            glue_name[length++] = "0123456789abcdef"[(hash >> shift) & 15];
        glue_name[length] = 0;
        named = 1;
    }
    __atomic_store_n(&glue_named, named, __ATOMIC_RELEASE);
    return named > 0 ? glue_name : NULL;
}

/* Per bind, the length of its shallowest ancestor missing from the root
 * mount (0 if none), scanned once per process. */
static void glue_scan(Bridge *b)
{
    if (__atomic_load_n(&glue_scanned, __ATOMIC_ACQUIRE)) return;
    for (size_t i = 0; i < b->table.count; i++) {
        const char *dst = b->table.entries[i].guest;
        unsigned short missing = 0;
        for (size_t j = 1; dst[j] && !missing; j++) {
            if (dst[j] != '/') continue;
            memcpy(b->proc_guest, dst, j);
            b->proc_guest[j] = 0;
            size_t mount;
            struct stat st;
            if (binding_table_mount_id(&b->table, b->proc_guest, &mount) < 0 || mount) continue;
            if (pb_host_map(b, b->proc_guest, b->proc_host) < 0) break;
            long ret = raw_syscall(__NR_newfstatat, AT_FDCWD, (long)b->proc_host, (long)&st, 0, 0, 0);
            if (ret == -ENOENT) missing = (unsigned short)j;
        }
        glue_missing[i] = missing;
    }
    __atomic_store_n(&glue_scanned, 1, __ATOMIC_RELEASE);
}

/* Whether the first length bytes of guest name a glue directory missing from
 * the root (a root-mount strict ancestor of a bind below its missing point). */
static bool glue_missing_dir(Bridge *b, const char *guest, size_t length)
{
    if (length <= 1) return false;
    glue_scan(b);
    for (size_t i = 0; i < b->table.count; i++) {
        const char *dst = b->table.entries[i].guest;
        if (glue_missing[i] && length >= glue_missing[i] && !strncmp(dst, guest, length) &&
            dst[length] == '/')
            return true;
    }
    return false;
}

/* Walks the tree's directories of every bind, op 0 creating (mode 0755),
 * 1 sealing (0555), 2 unsealing (0700) top-down, 3 removing bottom-up. */
static int glue_walk(Bridge *b, const char *base, int op)
{
    size_t base_length = strlen(base);
    char *path = b->proc_link_host;
    for (size_t i = 0; i < b->table.count; i++) {
        const char *dst = b->table.entries[i].guest;
        size_t length = strlen(dst);
        if (length <= 1 || base_length + length >= PATH_MAX) continue;
        memcpy(path, base, base_length);
        memcpy(path + base_length, dst, length + 1);
        /* The leaf mirrors the bind source's type. */
        struct stat st;
        bool directory = raw_syscall(__NR_newfstatat, AT_FDCWD, (long)b->table.entries[i].host,
                                     (long)&st, 0, 0, 0) < 0 || (st.st_mode & S_IFMT) == S_IFDIR;
        size_t end = base_length + length;
        for (size_t j = op == 3 ? end : base_length + 1; op == 3 ? j > base_length : j <= end;
             op == 3 ? j-- : j++) {
            if (j != end && path[j] != '/') continue;
            char saved = path[j];
            path[j] = 0;
            bool leaf = j == end;
            long ret = 0;
            if (op == 0) {
                if (leaf && !directory) {
                    ret = raw_syscall(__NR_openat, AT_FDCWD, (long)path,
                                      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0444, 0, 0);
                    if (ret >= 0) ret = raw_syscall(__NR_close, ret, 0, 0, 0, 0, 0);
                } else {
                    ret = raw_syscall(__NR_mkdirat, AT_FDCWD, (long)path, 0755, 0, 0, 0);
                }
                if (ret == -EEXIST) ret = 0;
            } else if (op == 3) {
                raw_syscall(__NR_unlinkat, AT_FDCWD, (long)path,
                            leaf && !directory ? 0 : AT_REMOVEDIR, 0, 0, 0);
            } else if (!leaf || directory) {
                ret = raw_syscall(__NR_fchmodat, AT_FDCWD, (long)path, op == 1 ? 0555 : 0700, 0, 0, 0);
            }
            path[j] = saved;
            if (ret < 0) return (int)ret;
        }
    }
    return 0;
}

static bool glue_valid(const char *path, long owner)
{
    struct stat st;
    return !raw_syscall(__NR_newfstatat, AT_FDCWD, (long)path, (long)&st, AT_SYMLINK_NOFOLLOW, 0, 0) &&
           (st.st_mode & S_IFMT) == S_IFDIR && !(st.st_mode & 022) && (long)st.st_uid == owner;
}

static int glue_ready(Bridge *b)
{
    int state = __atomic_load_n(&glue_state, __ATOMIC_ACQUIRE);
    if (state) return state;
    const char *name = glue_tree();
    if (!name) return -1;
    if (glue_valid(name, raw_syscall(__NR_getuid, 0, 0, 0, 0, 0, 0))) {
        __atomic_store_n(&glue_state, 1, __ATOMIC_RELEASE);
        return 1;
    }
    char *temp = b->proc_host;
    size_t length = strlen(name);
    if (length + 34 >= PATH_MAX) return -1;
    memcpy(temp, name, length);
    temp[length++] = '.';
    for (int pass = 0; pass < 2; pass++) {
        unsigned long value = (unsigned long)raw_syscall(pass ? __NR_gettid : __NR_getpid,
                                                         0, 0, 0, 0, 0, 0);
        do { temp[length++] = '0' + value % 10; value /= 10; } while (value);
        temp[length++] = pass ? 0 : '.';
    }
    state = -1;
    if (raw_syscall(__NR_mkdirat, AT_FDCWD, (long)temp, 0700, 0, 0, 0) < 0) {
        __atomic_store_n(&glue_state, state, __ATOMIC_RELEASE);
        return state;
    }
    struct stat st;
    long owner = raw_syscall(__NR_newfstatat, AT_FDCWD, (long)temp, (long)&st,
                             AT_SYMLINK_NOFOLLOW, 0, 0) ? -1 : (long)st.st_uid;
    if (glue_valid(name, owner)) {
        raw_syscall(__NR_unlinkat, AT_FDCWD, (long)temp, AT_REMOVEDIR, 0, 0, 0);
        __atomic_store_n(&glue_state, 1, __ATOMIC_RELEASE);
        return 1;
    }
    if (!glue_walk(b, temp, 0) && !glue_walk(b, temp, 1) &&
        !raw_syscall(__NR_fchmodat, AT_FDCWD, (long)temp, 0555, 0, 0, 0)) {
        if (!raw_syscall(__NR_renameat2, AT_FDCWD, (long)temp, AT_FDCWD, (long)name, 0, 0))
            state = 1;
        else if (glue_valid(name, owner))
            state = 1;
    }
    if (glue_valid(temp, owner) || state < 0) {
        raw_syscall(__NR_fchmodat, AT_FDCWD, (long)temp, 0700, 0, 0, 0);
        glue_walk(b, temp, 2);
        glue_walk(b, temp, 3);
        raw_syscall(__NR_unlinkat, AT_FDCWD, (long)temp, AT_REMOVEDIR, 0, 0, 0);
    }
    __atomic_store_n(&glue_state, state, __ATOMIC_RELEASE);
    return state;
}

/* Serves a resolved root-mount guest path that is, or is directly inside, a
 * missing glue directory from the tree. Returns 1 when b->host was replaced. */
int pb_glue_host(Bridge *b)
{
    if (!b->table.count) return 0;
    size_t length = strlen(b->guest);
    for (;;) {
        if (length > 1 && b->guest[length - 1] == '/') length--;
        else if (length > 2 && b->guest[length - 1] == '.' && b->guest[length - 2] == '/')
            length -= 2;
        else break;
    }
    if (length <= 1) return 0;
    size_t parent = length - 1;
    while (parent && b->guest[parent] != '/') parent--;
    if (!glue_missing_dir(b, b->guest, length) && !glue_missing_dir(b, b->guest, parent))
        return 0;
    size_t mount;
    if (binding_table_mount_id(&b->table, b->guest, &mount) < 0 || mount) return 0;
    if (glue_ready(b) < 0) return 0;
    size_t base = strlen(glue_name), total = strlen(b->guest);
    if (base + total >= PATH_MAX) return -ENAMETOOLONG;
    memcpy(b->host, glue_name, base);
    memcpy(b->host + base, b->guest, total + 1);
    return 1;
}

/* Reverse of pb_glue_host for kernel-reported paths (cwd, FD links). */
bool pb_glue_guest(const char *host, char *guest)
{
    const char *name = glue_tree();
    if (!name) return false;
    size_t length = strlen(name);
    if (strncmp(host, name, length) || (host[length] && host[length] != '/')) return false;
    strcpy(guest, host[length] ? host + length : "/");
    return true;
}
