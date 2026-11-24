/* SPDX-License-Identifier: MIT */
/* Cross-process shared SVC-site scan cache backed by a 1 MiB MAP_SHARED file
 * in mount_scratch. Keyed by (dev, ino, file_size, mtime, file_off, map_len)
 * with per-slot lock-free seqlocks so concurrent or crashed writers never
 * block or corrupt readers.
 *
 * The includer defines:
 *   long svc_cache_openat(const char *path, int flags, int mode);
 *   long svc_cache_fstat(int fd, void *st_buf);
 *   long svc_cache_ftruncate(int fd, long len);
 *   long svc_cache_mmap_shared(int fd, size_t len);
 *   long svc_cache_munmap(void *addr, size_t len);
 *   long svc_cache_close(int fd);
 *   int  svc_cache_note_protected(uintptr_t base, size_t len);
 */
#ifndef SVC_CACHE_H
#define SVC_CACHE_H

#include <stddef.h>
#include <stdint.h>

#define SVC_CACHE_MAGIC      0x53564332u /* "SVC2" */
#define SVC_CACHE_VERSION    1u
#define SVC_CACHE_SLOTS      2048u
#define SVC_CACHE_PROBE      4u
#define SVC_CACHE_MAX_SITES  4096u
#define SVC_CACHE_BYTES      (1024u * 1024u) /* 1 MiB */

struct svc_cache_hdr {
    uint32_t magic;
    uint32_t version;
    uint32_t pool_used;
    uint32_t _pad[13];
};

struct svc_cache_slot {
    uint32_t seq;        /* 0=empty, odd=writing, even!=0=valid */
    uint32_t count;      /* 0=zero-svc, 1..SVC_CACHE_MAX_SITES=cached offsets */
    uint64_t dev;
    uint64_t ino;
    uint64_t file_size;
    int64_t  mtime_sec;
    int64_t  mtime_nsec;
    uint64_t file_off;
    uint32_t map_len;
    uint32_t pool_off;
};

#define SVC_CACHE_POOL_WORDS \
    ((SVC_CACHE_BYTES - sizeof(struct svc_cache_hdr) - SVC_CACHE_SLOTS * sizeof(struct svc_cache_slot)) / sizeof(uint32_t))

struct svc_cache_map {
    struct svc_cache_hdr  hdr;
    struct svc_cache_slot slots[SVC_CACHE_SLOTS];
    uint32_t              pool[SVC_CACHE_POOL_WORDS];
};

struct svc_cache_key {
    uint64_t dev;
    uint64_t ino;
    uint64_t file_size;
    int64_t  mtime_sec;
    int64_t  mtime_nsec;
    uint64_t file_off;
    uint32_t map_len;
};

static struct svc_cache_map *g_svc_cache_ptr = NULL;
static int g_svc_cache_state = 0; /* 0=uninit, 1=ready, -1=disabled */

/* Extract key fields from an AArch64 Linux struct stat (128 bytes):
 * st_dev@0(8), st_ino@8(8), st_mode@16(4), st_size@48(8),
 * st_mtime@88(8), st_mtime_nsec@96(8). */
static inline int svc_cache_key_from_fd(int fd, uint64_t file_off, size_t map_len,
                                        struct svc_cache_key *out)
{
    if (fd < 0 || !map_len || map_len > 0xffffffffu)
        return -1;
    unsigned char st[128];
    if (svc_cache_fstat(fd, st) < 0)
        return -1;
    uint32_t mode = 0;
    __builtin_memcpy(&mode, st + 16, 4);
    if ((mode & 0170000u) != 0100000u) /* regular file only */
        return -1;
    __builtin_memcpy(&out->dev, st + 0, 8);
    __builtin_memcpy(&out->ino, st + 8, 8);
    __builtin_memcpy(&out->file_size, st + 48, 8);
    __builtin_memcpy(&out->mtime_sec, st + 88, 8);
    __builtin_memcpy(&out->mtime_nsec, st + 96, 8);
    out->file_off = file_off;
    out->map_len = (uint32_t)map_len;
    return 0;
}

static inline uint32_t svc_cache_hash(const struct svc_cache_key *k)
{
    uint64_t h = k->ino * 0x9e3779b97f4a7c15ULL;
    h ^= k->dev * 0xc2b2ae3d27d4eb4fULL;
    h ^= (k->file_off + 1ULL) * 0x165667b19e3779f9ULL;
    h ^= (uint64_t)k->map_len * 0x85ebca77c2b2ae63ULL;
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    return (uint32_t)(h & (SVC_CACHE_SLOTS - 1u));
}

static inline struct svc_cache_map *svc_cache_get(const char *scratch_dir)
{
    int st = __atomic_load_n(&g_svc_cache_state, __ATOMIC_ACQUIRE);
    if (st == 1)
        return __atomic_load_n(&g_svc_cache_ptr, __ATOMIC_ACQUIRE);
    if (st < 0)
        return NULL;
    if (!scratch_dir || !scratch_dir[0]) {
        __atomic_store_n(&g_svc_cache_state, -1, __ATOMIC_RELEASE);
        return NULL;
    }

    char path[320];
    size_t n = 0;
    while (scratch_dir[n] && n < 280) {
        path[n] = scratch_dir[n];
        n++;
    }
    const char *suf = "/.svbox_svc_cache";
    for (size_t i = 0; suf[i]; i++)
        path[n++] = suf[i];
    path[n] = '\0';

    long fd = svc_cache_openat(path, 02 /* O_RDWR */ | 0100 /* O_CREAT */ | 02000000 /* O_CLOEXEC */, 0600);
    if (fd < 0) {
        __atomic_store_n(&g_svc_cache_state, -1, __ATOMIC_RELEASE);
        return NULL;
    }
    unsigned char fbuf[128];
    uint64_t fsz = 0;
    if (svc_cache_fstat((int)fd, fbuf) == 0)
        __builtin_memcpy(&fsz, fbuf + 48, 8);
    if (fsz < SVC_CACHE_BYTES) {
        if (svc_cache_ftruncate((int)fd, SVC_CACHE_BYTES) < 0) {
            svc_cache_close((int)fd);
            __atomic_store_n(&g_svc_cache_state, -1, __ATOMIC_RELEASE);
            return NULL;
        }
    }
    long mem = svc_cache_mmap_shared((int)fd, SVC_CACHE_BYTES);
    svc_cache_close((int)fd);
    if (mem < 0 && mem > -4096) {
        __atomic_store_n(&g_svc_cache_state, -1, __ATOMIC_RELEASE);
        return NULL;
    }
    if (svc_cache_note_protected((uintptr_t)mem, SVC_CACHE_BYTES) != 0) {
        svc_cache_munmap((void *)mem, SVC_CACHE_BYTES);
        __atomic_store_n(&g_svc_cache_state, -1, __ATOMIC_RELEASE);
        return NULL;
    }
    struct svc_cache_map *m = (struct svc_cache_map *)mem;
    if (__atomic_load_n(&m->hdr.magic, __ATOMIC_ACQUIRE) != SVC_CACHE_MAGIC ||
        __atomic_load_n(&m->hdr.version, __ATOMIC_ACQUIRE) != SVC_CACHE_VERSION) {
        /* Safe idempotent header init (fresh ftruncate zeroed slots/pool). */
        __atomic_store_n(&m->hdr.version, SVC_CACHE_VERSION, __ATOMIC_RELEASE);
        __atomic_store_n(&m->hdr.magic, SVC_CACHE_MAGIC, __ATOMIC_RELEASE);
    }

    struct svc_cache_map *expected = NULL;
    if (!__atomic_compare_exchange_n(&g_svc_cache_ptr, &expected, m, 0,
                                     __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        /* Another thread initialized concurrently; keep theirs (ours stays protected). */
        return expected;
    }
    __atomic_store_n(&g_svc_cache_state, 1, __ATOMIC_RELEASE);
    return m;
}

/* Lookup key in cache.
 * Returns:
 *   1 on hit: *count_out set (0 = verified zero-svc; >0 = offsets copied to out_buf if count <= cap).
 *   0 on miss (or if count > cap). */
static inline int svc_cache_lookup(struct svc_cache_map *m, const struct svc_cache_key *k,
                                   uint32_t *out_buf, size_t out_cap, uint32_t *count_out)
{
    if (!m || !k)
        return 0;
    if (__atomic_load_n(&m->hdr.magic, __ATOMIC_ACQUIRE) != SVC_CACHE_MAGIC)
        return 0;
    uint32_t h = svc_cache_hash(k);
    for (uint32_t p = 0; p < SVC_CACHE_PROBE; p++) {
        struct svc_cache_slot *s = &m->slots[(h + p) & (SVC_CACHE_SLOTS - 1u)];
        uint32_t seq1 = __atomic_load_n(&s->seq, __ATOMIC_ACQUIRE);
        if (seq1 == 0 || (seq1 & 1u))
            continue;
        struct svc_cache_slot snap = *s;
        __atomic_thread_fence(__ATOMIC_ACQUIRE);
        uint32_t seq2 = __atomic_load_n(&s->seq, __ATOMIC_ACQUIRE);
        if (seq1 != seq2)
            continue;
        if (snap.dev == k->dev && snap.ino == k->ino &&
            snap.file_size == k->file_size &&
            snap.mtime_sec == k->mtime_sec && snap.mtime_nsec == k->mtime_nsec &&
            snap.file_off == k->file_off && snap.map_len == k->map_len) {
            if (snap.count == 0) {
                *count_out = 0;
                return 1;
            }
            if (snap.count > SVC_CACHE_MAX_SITES || snap.count > out_cap ||
                (uint64_t)snap.pool_off + (uint64_t)snap.count > SVC_CACHE_POOL_WORDS)
                return 0;
            /* Pool entries are write-once (monotonic bump allocator), safe to copy. */
            for (uint32_t i = 0; i < snap.count; i++)
                out_buf[i] = m->pool[snap.pool_off + i];
            *count_out = snap.count;
            return 1;
        }
    }
    return 0;
}

static inline void svc_cache_store(struct svc_cache_map *m, const struct svc_cache_key *k,
                                   const uint32_t *sites, size_t count)
{
    if (!m || !k || count > SVC_CACHE_MAX_SITES)
        return;
    if (__atomic_load_n(&m->hdr.magic, __ATOMIC_ACQUIRE) != SVC_CACHE_MAGIC)
        return;

    uint32_t h = svc_cache_hash(k);
    struct svc_cache_slot *target = NULL;
    uint32_t cur_seq = 0;

    /* Prefer matching slot or empty slot; fallback to first non-locked slot in probe window. */
    for (uint32_t p = 0; p < SVC_CACHE_PROBE; p++) {
        struct svc_cache_slot *s = &m->slots[(h + p) & (SVC_CACHE_SLOTS - 1u)];
        uint32_t seq = __atomic_load_n(&s->seq, __ATOMIC_ACQUIRE);
        if (seq & 1u) continue;
        if (seq == 0) {
            target = s;
            cur_seq = 0;
            break;
        }
        if (s->dev == k->dev && s->ino == k->ino && s->file_off == k->file_off && s->map_len == k->map_len) {
            if (s->file_size == k->file_size && s->mtime_sec == k->mtime_sec && s->mtime_nsec == k->mtime_nsec)
                return; /* Already cached with identical version. */
            target = s;
            cur_seq = seq;
            break;
        }
        if (!target) {
            target = s;
            cur_seq = seq;
        }
    }
    if (!target)
        return;

    uint32_t pool_off = 0;
    if (count > 0) {
        /* Atomically reserve count words from the append-only pool. */
        uint32_t cur = __atomic_load_n(&m->hdr.pool_used, __ATOMIC_RELAXED);
        for (;;) {
            if ((uint64_t)cur + (uint64_t)count > SVC_CACHE_POOL_WORDS)
                return; /* Pool full: skip caching rather than corrupting active readers. */
            if (__atomic_compare_exchange_n(&m->hdr.pool_used, &cur, cur + (uint32_t)count,
                                            0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
                pool_off = cur;
                break;
            }
        }
        for (size_t i = 0; i < count; i++)
            m->pool[pool_off + i] = sites[i];
        __atomic_thread_fence(__ATOMIC_RELEASE);
    }

    uint32_t next_odd = cur_seq + 1u;
    if (next_odd == 0 || (next_odd & 1u) == 0) next_odd = 1u;
    if (!__atomic_compare_exchange_n(&target->seq, &cur_seq, next_odd,
                                     0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
        return;

    target->count = (uint32_t)count;
    target->dev = k->dev;
    target->ino = k->ino;
    target->file_size = k->file_size;
    target->mtime_sec = k->mtime_sec;
    target->mtime_nsec = k->mtime_nsec;
    target->file_off = k->file_off;
    target->map_len = k->map_len;
    target->pool_off = pool_off;
    __atomic_store_n(&target->seq, next_odd + 1u, __ATOMIC_RELEASE);
}

#endif /* SVC_CACHE_H */
