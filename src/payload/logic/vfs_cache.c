/* SPDX-License-Identifier: MIT */
/* Coherent per-process cache for immutable read-only --lower directories. */
#include <asm/stat.h>
#include <asm/unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "config.h"
#include "host_syscall.h"
#include "vfs_cache.h"

extern long raw_syscall(long number, long a1, long a2, long a3, long a4, long a5, long a6);

#define AT_FDCWD_           (-100)
#define AT_SYMLINK_NOFOLLOW_ 0x100
#define O_RDONLY_           0
#define O_DIRECTORY_        040000
#define O_NOFOLLOW_         0100000
#define O_CLOEXEC_          02000000
#define S_IFMT_             0170000
#define S_IFDIR_            0040000
#define PROT_RW_            3
#define MAP_PRIV_ANON_      0x22

#define RO_STAT_SLOTS       1024u
#define RO_STAT_PATH_MAX    256u
#define RO_LINK_SLOTS       128u
#define RO_LINK_PATH_MAX    256u
#define UPPER_DIR_SLOTS     64u

struct upper_dir_entry {
    uint8_t  state;       /* 0=empty, 1=warming (waiting for stability), 2=cached */
    uint8_t  stable_hits; /* consecutive probes at same signature before scanning */
    uint32_t mut_gen;
    uint64_t dev;
    uint64_t ino;
    long     mtime;
    long     mtime_nsec;
    long     ctime;
    long     ctime_nsec;
    long     size;
    unsigned int nlink;
    struct vfs_upper_dir_info info;
};

struct ro_stat_entry {
    uint64_t hash;
    uint16_t rel_len;
    uint8_t  layer;
    uint8_t  state;        /* 0=empty, 1=exists, 2=enoent */
    uint8_t  empty_dir;    /* 0=no, 1=yes (for S_IFDIR) */
    int8_t   opaque_state; /* -1=unknown, 0=no, 1=yes */
    int8_t   wh_state;     /* -1=unknown, 0=no, 1=yes */
    uint8_t  _pad;
    char     rel[RO_STAT_PATH_MAX];
    struct stat st;
};

struct ro_link_entry {
    uint64_t hash;
    uint16_t path_len;
    uint16_t target_len;
    int32_t  err; /* 0 = valid target, < 0 = cached negative errno */
    char     path[RO_LINK_PATH_MAX];
    char     target[RO_LINK_PATH_MAX];
};

struct ro_cache_pool {
    struct ro_stat_entry   stats[RO_STAT_SLOTS];
    struct ro_link_entry   links[RO_LINK_SLOTS];
    struct upper_dir_entry upper_dirs[UPPER_DIR_SLOTS];
};

static struct ro_cache_pool *g_ro_pool = NULL;
static volatile int g_ro_lock = 0;
static volatile uint32_t g_upper_mut_gen = 1u;

static void ro_lock(void)
{
    while (__sync_lock_test_and_set(&g_ro_lock, 1))
        __asm__ volatile("yield" ::: "memory");
}

static void ro_unlock(void)
{
    __sync_lock_release(&g_ro_lock);
}

static struct ro_cache_pool *ro_pool_get(void)
{
    struct ro_cache_pool *p = __atomic_load_n(&g_ro_pool, __ATOMIC_ACQUIRE);
    if (p)
        return p;
    size_t sz = (sizeof(struct ro_cache_pool) + 4095u) & ~(size_t)4095u;
    long mem = raw_syscall(__NR_mmap, 0, (long)sz, PROT_RW_, MAP_PRIV_ANON_, -1, 0);
    if ((unsigned long)mem >= (unsigned long)-4095)
        return NULL;
    struct ro_cache_pool *np = (struct ro_cache_pool *)mem;
    struct ro_cache_pool *expected = NULL;
    if (!__atomic_compare_exchange_n(&g_ro_pool, &expected, np, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        raw_syscall(__NR_munmap, mem, (long)sz, 0, 0, 0, 0);
        return expected;
    }
    return np;
}

static inline bool bytes_eq(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i])
            return false;
    }
    return true;
}

static uint64_t fnv1a_bytes(uint64_t seed, const char *s, size_t n)
{
    uint64_t h = seed;
    for (size_t i = 0; i < n; i++) {
        h ^= (unsigned char)s[i];
        h *= 0x100000001b3ULL;
    }
    return h ? h : 1ULL;
}

static bool probe_dir_empty(const char *host_path, const struct stat *st)
{
    /* A directory with nlink > 2 has subdirectories on standard filesystems;
     * still check getdents64 when nlink <= 2 (or on FUSE/hmdfs where nlink may be 1). */
    if (st->st_nlink > 2)
        return false;
    long fd = host_syscall(__NR_openat, AT_FDCWD_, (long)host_path,
                           O_RDONLY_ | O_DIRECTORY_ | O_NOFOLLOW_ | O_CLOEXEC_, 0, 0, 0);
    if (fd < 0)
        return false;
    unsigned char buf[1024];
    bool empty = true;
    for (;;) {
        long n = raw_syscall(__NR_getdents64, fd, (long)buf, sizeof(buf), 0, 0, 0);
        if (n < 0) {
            empty = false;
            break;
        }
        if (n == 0)
            break;
        size_t off = 0;
        while (off < (size_t)n) {
            unsigned short reclen = 0;
            memcpy(&reclen, buf + off + 16, sizeof(reclen));
            if (reclen < 20 || off + reclen > (size_t)n) {
                empty = false;
                break;
            }
            const char *name = (const char *)(buf + off + 19);
            if (!(name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0)))) {
                empty = false;
                break;
            }
            off += reclen;
        }
        if (!empty)
            break;
    }
    raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
    return empty;
}

int vfs_ro_lookup(int layer, const char *host_path, const char *rel, size_t rel_len,
                  bool check_opaque, const char *opaque_path,
                  bool check_wh, const char *wh_path,
                  struct stat *st_out, bool *is_empty_dir_out,
                  bool *is_opaque_out, bool *has_wh_out)
{
    if (is_empty_dir_out) *is_empty_dir_out = false;
    if (is_opaque_out) *is_opaque_out = false;
    if (has_wh_out) *has_wh_out = false;

    bool cacheable = (layer > 0 && layer <= CONFIG_MAX_LOWERS && rel_len < RO_STAT_PATH_MAX);
    struct ro_cache_pool *pool = cacheable ? ro_pool_get() : NULL;
    uint64_t h = 0;
    uint32_t slot_idx = 0;

    if (pool) {
        h = fnv1a_bytes(0xcbf29ce484222325ULL ^ ((uint64_t)layer * 0x9e3779b97f4a7c15ULL), rel, rel_len);
        slot_idx = (uint32_t)(h & (RO_STAT_SLOTS - 1u));
        ro_lock();
        struct ro_stat_entry *e = &pool->stats[slot_idx];
        if (e->state != 0 && e->hash == h && e->layer == (uint8_t)layer &&
            e->rel_len == (uint16_t)rel_len && bytes_eq(e->rel, rel, rel_len)) {
            uint8_t st_state = e->state;
            struct stat st_copy = e->st;
            uint8_t empty_dir = e->empty_dir;
            int8_t opq = e->opaque_state;
            int8_t wh = e->wh_state;
            ro_unlock();

            if (st_state == 1) {
                if (st_out) *st_out = st_copy;
                if (is_empty_dir_out) *is_empty_dir_out = (empty_dir != 0);
                if (check_opaque && opaque_path && ((st_copy.st_mode & S_IFMT_) == S_IFDIR_)) {
                    if (opq < 0) {
                        struct stat tmp;
                        opq = (host_syscall(__NR_newfstatat, AT_FDCWD_, (long)opaque_path,
                                            (long)&tmp, AT_SYMLINK_NOFOLLOW_, 0, 0) == 0) ? 1 : 0;
                        ro_lock();
                        if (e->state == 1 && e->hash == h && e->layer == (uint8_t)layer &&
                            e->rel_len == (uint16_t)rel_len && bytes_eq(e->rel, rel, rel_len))
                            e->opaque_state = opq;
                        ro_unlock();
                    }
                    if (is_opaque_out) *is_opaque_out = (opq > 0);
                }
                return 1;
            }
            /* Cached ENOENT */
            if (check_wh && wh_path) {
                if (wh < 0) {
                    struct stat tmp;
                    wh = (host_syscall(__NR_newfstatat, AT_FDCWD_, (long)wh_path,
                                       (long)&tmp, AT_SYMLINK_NOFOLLOW_, 0, 0) == 0) ? 1 : 0;
                    ro_lock();
                    if (e->state == 2 && e->hash == h && e->layer == (uint8_t)layer &&
                        e->rel_len == (uint16_t)rel_len && bytes_eq(e->rel, rel, rel_len))
                        e->wh_state = wh;
                    ro_unlock();
                }
                if (has_wh_out) *has_wh_out = (wh > 0);
            }
            return 0;
        }
        ro_unlock();
    }

    /* Cache miss: perform host lstat */
    struct stat st;
    long rc = host_syscall(__NR_newfstatat, AT_FDCWD_, (long)host_path,
                           (long)&st, AT_SYMLINK_NOFOLLOW_, 0, 0);
    if (rc == 0) {
        bool is_dir = (st.st_mode & S_IFMT_) == S_IFDIR_;
        bool empty_dir = is_dir ? probe_dir_empty(host_path, &st) : false;
        int8_t opq = -1;
        if (is_dir && check_opaque && opaque_path) {
            struct stat tmp;
            opq = (host_syscall(__NR_newfstatat, AT_FDCWD_, (long)opaque_path,
                                (long)&tmp, AT_SYMLINK_NOFOLLOW_, 0, 0) == 0) ? 1 : 0;
        }
        if (pool) {
            ro_lock();
            struct ro_stat_entry *e = &pool->stats[slot_idx];
            e->hash = h;
            e->rel_len = (uint16_t)rel_len;
            e->layer = (uint8_t)layer;
            e->state = 1;
            e->empty_dir = empty_dir ? 1 : 0;
            e->opaque_state = opq;
            e->wh_state = -1;
            memcpy(e->rel, rel, rel_len);
            e->rel[rel_len] = 0;
            e->st = st;
            ro_unlock();
        }
        if (st_out) *st_out = st;
        if (is_empty_dir_out) *is_empty_dir_out = empty_dir;
        if (is_opaque_out) *is_opaque_out = (opq > 0);
        return 1;
    }

    int8_t wh = -1;
    if (check_wh && wh_path) {
        struct stat tmp;
        wh = (host_syscall(__NR_newfstatat, AT_FDCWD_, (long)wh_path,
                           (long)&tmp, AT_SYMLINK_NOFOLLOW_, 0, 0) == 0) ? 1 : 0;
    }
    if (pool && (rc == -ENOENT || rc == -ENOTDIR)) {
        ro_lock();
        struct ro_stat_entry *e = &pool->stats[slot_idx];
        e->hash = h;
        e->rel_len = (uint16_t)rel_len;
        e->layer = (uint8_t)layer;
        e->state = 2;
        e->empty_dir = 0;
        e->opaque_state = -1;
        e->wh_state = wh;
        memcpy(e->rel, rel, rel_len);
        e->rel[rel_len] = 0;
        ro_unlock();
    }
    if (has_wh_out) *has_wh_out = (wh > 0);
    return 0;
}

static bool host_in_ro_lower(const char *host_path)
{
    const payload_config_t *cfg = &g_payload_config;
    if (cfg->isolate || cfg->lower_count <= 0)
        return false;
    for (int i = 0; i < cfg->lower_count && i < CONFIG_MAX_LOWERS; i++) {
        if (cfg->lower_image[i][0])
            continue;
        const char *l = cfg->lower[i];
        size_t n = strlen(l);
        while (n > 1 && l[n - 1] == '/') n--;
        if (n > 1 && strncmp(host_path, l, n) == 0 && (host_path[n] == '/' || host_path[n] == 0))
            return true;
    }
    return false;
}

int vfs_ro_readlink(const char *host_path, char *out, size_t size)
{
    if (!host_path || !host_in_ro_lower(host_path))
        return -EAGAIN;
    size_t plen = strlen(host_path);
    if (plen >= RO_LINK_PATH_MAX)
        return -EAGAIN;
    struct ro_cache_pool *pool = ro_pool_get();
    if (!pool)
        return -EAGAIN;

    uint64_t h = fnv1a_bytes(0xcbf29ce484222325ULL, host_path, plen);
    uint32_t idx = (uint32_t)(h & (RO_LINK_SLOTS - 1u));

    ro_lock();
    struct ro_link_entry *e = &pool->links[idx];
    if (e->hash == h && e->path_len == (uint16_t)plen && bytes_eq(e->path, host_path, plen)) {
        if (e->err < 0) {
            int err = e->err;
            ro_unlock();
            return err;
        }
        size_t n = e->target_len < size ? e->target_len : size;
        memcpy(out, e->target, n);
        ro_unlock();
        return (int)n;
    }
    ro_unlock();

    char tmp[RO_LINK_PATH_MAX];
    long r = host_syscall(__NR_readlinkat, AT_FDCWD_, (long)host_path, (long)tmp, sizeof(tmp), 0, 0);
    if (r >= 0 && (size_t)r < sizeof(tmp)) {
        ro_lock();
        e = &pool->links[idx];
        e->hash = h;
        e->path_len = (uint16_t)plen;
        e->target_len = (uint16_t)r;
        e->err = 0;
        memcpy(e->path, host_path, plen + 1);
        memcpy(e->target, tmp, (size_t)r);
        e->target[r] = 0;
        ro_unlock();
        size_t n = (size_t)r < size ? (size_t)r : size;
        memcpy(out, tmp, n);
        return (int)n;
    }
    if (r < 0 && (r == -EINVAL || r == -ENOENT)) {
        ro_lock();
        e = &pool->links[idx];
        e->hash = h;
        e->path_len = (uint16_t)plen;
        e->target_len = 0;
        e->err = (int32_t)r;
        memcpy(e->path, host_path, plen + 1);
        ro_unlock();
        return (int)r;
    }
    /* Longer than RO_LINK_PATH_MAX or transient error: fall through to raw readlinkat. */
    return -EAGAIN;
}

void vfs_upper_note_mutation(void)
{
    __atomic_add_fetch(&g_upper_mut_gen, 1u, __ATOMIC_RELEASE);
}

static inline void bloom_add(uint64_t bloom[4], const char *name, size_t len)
{
    uint64_t h1 = fnv1a_bytes(0xcbf29ce484222325ULL, name, len);
    uint64_t h2 = (h1 >> 32) ^ (h1 * 0x9e3779b97f4a7c15ULL);
    uint32_t b1 = (uint32_t)(h1 & 255u);
    uint32_t b2 = (uint32_t)(h2 & 255u);
    bloom[b1 >> 6] |= 1ULL << (b1 & 63u);
    bloom[b2 >> 6] |= 1ULL << (b2 & 63u);
}

bool vfs_upper_bloom_may_contain(const struct vfs_upper_dir_info *info,
                                 const char *name, size_t len)
{
    if (!info || !info->bloom_valid)
        return true;
    uint64_t h1 = fnv1a_bytes(0xcbf29ce484222325ULL, name, len);
    uint64_t h2 = (h1 >> 32) ^ (h1 * 0x9e3779b97f4a7c15ULL);
    uint32_t b1 = (uint32_t)(h1 & 255u);
    uint32_t b2 = (uint32_t)(h2 & 255u);
    return ((info->bloom[b1 >> 6] >> (b1 & 63u)) & 1ULL) &&
           ((info->bloom[b2 >> 6] >> (b2 & 63u)) & 1ULL);
}

bool vfs_upper_dir_probe(const char *host_dir, const struct stat *dir_st,
                         struct vfs_upper_dir_info *out)
{
    if (!host_dir || !dir_st || !out)
        return false;
    struct ro_cache_pool *pool = ro_pool_get();
    if (!pool)
        return false;

    uint32_t cur_gen = __atomic_load_n(&g_upper_mut_gen, __ATOMIC_ACQUIRE);
    uint64_t key = (uint64_t)dir_st->st_ino * 0x9e3779b97f4a7c15ULL ^
                   (uint64_t)dir_st->st_dev * 0xc2b2ae3d27d4eb4fULL;
    uint32_t slot = (uint32_t)((key ^ (key >> 16)) & (UPPER_DIR_SLOTS - 1u));

    ro_lock();
    struct upper_dir_entry *e = &pool->upper_dirs[slot];
    bool sig_match = (e->state != 0 && e->mut_gen == cur_gen &&
                      e->dev == (uint64_t)dir_st->st_dev && e->ino == (uint64_t)dir_st->st_ino &&
                      e->mtime == dir_st->st_mtime && e->mtime_nsec == dir_st->st_mtime_nsec &&
                      e->ctime == dir_st->st_ctime && e->ctime_nsec == dir_st->st_ctime_nsec &&
                      e->size == dir_st->st_size && e->nlink == dir_st->st_nlink);
    if (sig_match && e->state == 2) {
        *out = e->info;
        ro_unlock();
        return true;
    }
    if (!sig_match) {
        /* Stability gate: require 8 consecutive probes without mutation before
         * scanning with getdents64, so rapid create/unlink bursts (e.g. /tmp)
         * never pay O(N^2) directory scans. */
        e->state = 1;
        e->stable_hits = 1;
        e->mut_gen = cur_gen;
        e->dev = (uint64_t)dir_st->st_dev;
        e->ino = (uint64_t)dir_st->st_ino;
        e->mtime = dir_st->st_mtime;
        e->mtime_nsec = dir_st->st_mtime_nsec;
        e->ctime = dir_st->st_ctime;
        e->ctime_nsec = dir_st->st_ctime_nsec;
        e->size = dir_st->st_size;
        e->nlink = dir_st->st_nlink;
        ro_unlock();
        return false;
    }
    if (e->state == 1 && e->stable_hits < 8) {
        e->stable_hits++;
        ro_unlock();
        return false;
    }
    ro_unlock();

    /* Cache miss or directory changed: scan directory entries once and close immediately. */
    long fd = host_syscall(__NR_openat, AT_FDCWD_, (long)host_dir,
                           O_RDONLY_ | O_DIRECTORY_ | O_NOFOLLOW_ | O_CLOEXEC_, 0, 0, 0);
    if (fd < 0)
        return false;

    struct vfs_upper_dir_info info;
    memset(&info, 0, sizeof(info));
    info.bloom_valid = true;

    unsigned char buf[2048];
    int count = 0;
    bool ok = true;
    for (;;) {
        long n = raw_syscall(__NR_getdents64, fd, (long)buf, sizeof(buf), 0, 0, 0);
        if (n < 0) {
            ok = false;
            break;
        }
        if (n == 0)
            break;
        size_t off = 0;
        while (off < (size_t)n) {
            unsigned short reclen = 0;
            memcpy(&reclen, buf + off + 16, sizeof(reclen));
            if (reclen < 20 || off + reclen > (size_t)n) {
                ok = false;
                break;
            }
            const char *name = (const char *)(buf + off + 19);
            if (!(name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0)))) {
                size_t nlen = strlen(name);
                if (name[0] == '.' && name[1] == 'w' && name[2] == 'h' && name[3] == '.') {
                    info.has_any_wh = true;
                    if (strcmp(name, ".wh..wh..opq") == 0)
                        info.has_opaque = true;
                } else {
                    count++;
                    if (count <= 128)
                        bloom_add(info.bloom, name, nlen);
                    else
                        info.bloom_valid = false;
                }
            }
            off += reclen;
        }
        if (!ok)
            break;
    }
    raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
    if (!ok)
        return false;

    uint32_t gen_after = __atomic_load_n(&g_upper_mut_gen, __ATOMIC_ACQUIRE);
    if (gen_after == cur_gen) {
        ro_lock();
        e = &pool->upper_dirs[slot];
        e->state = 2;
        e->mut_gen = cur_gen;
        e->dev = (uint64_t)dir_st->st_dev;
        e->ino = (uint64_t)dir_st->st_ino;
        e->mtime = dir_st->st_mtime;
        e->mtime_nsec = dir_st->st_mtime_nsec;
        e->ctime = dir_st->st_ctime;
        e->ctime_nsec = dir_st->st_ctime_nsec;
        e->size = dir_st->st_size;
        e->nlink = dir_st->st_nlink;
        e->info = info;
        ro_unlock();
    }
    *out = info;
    return true;
}
