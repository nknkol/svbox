/* SPDX-License-Identifier: MIT */
/* Generic userspace Linux bpf(2) map & object emulation (--emulate-bpf).
 * Pure freestanding C (no libc heap, no memcmp); zero platform- or
 * guest-distro-specific paths or assumptions. */
#include "bpf_emu.h"
#include "config.h"
#include "syscall_nums.h"
#include "vfs_bridge.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

extern long raw_syscall(long number, long a1, long a2, long a3, long a4, long a5, long a6);

/* Standard Linux UAPI <linux/bpf.h> command & flag constants. */
enum {
    SV_BPF_MAP_CREATE         = 0,
    SV_BPF_MAP_LOOKUP_ELEM    = 1,
    SV_BPF_MAP_UPDATE_ELEM    = 2,
    SV_BPF_MAP_DELETE_ELEM    = 3,
    SV_BPF_MAP_GET_NEXT_KEY   = 4,
    SV_BPF_PROG_LOAD          = 5,
    SV_BPF_OBJ_PIN            = 6,
    SV_BPF_OBJ_GET            = 7,
    SV_BPF_PROG_ATTACH        = 8,
    SV_BPF_PROG_DETACH        = 9,
    SV_BPF_OBJ_GET_INFO_BY_FD = 15,
};

enum {
    SV_BPF_MAP_TYPE_HASH    = 1,
    SV_BPF_MAP_TYPE_ARRAY   = 2,
    SV_BPF_MAP_TYPE_RINGBUF = 27,
};

enum {
    SV_BPF_ANY     = 0,
    SV_BPF_NOEXIST = 1,
    SV_BPF_EXIST   = 2,
};

#define SV_EFD_CLOEXEC 02000000
#define SV_BPF_MAX_MAPS 128
#define SV_BPF_MAX_FDS  256
#define SV_BPF_PATH_MAX 256
#define SV_BPF_MAX_KEY  128
#define SV_BPF_MAX_VAL  256
#define SV_BPF_SLOT_CAP 256

/* Standard Linux struct bpf_map_info prefix (matches kernel UAPI layout). */
struct sv_bpf_map_info {
    uint32_t type;
    uint32_t id;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    char     name[16];
    uint32_t ifindex;
    uint32_t btf_vmlinux_value_type_id;
    uint64_t netns_dev;
    uint64_t netns_ino;
    uint32_t btf_id;
    uint32_t btf_key_type_id;
    uint32_t btf_value_type_id;
    uint32_t pad;
    uint64_t map_extra;
};

struct sv_bpf_prog_info {
    uint32_t type;
    uint32_t id;
    uint8_t  tag[8];
    uint32_t jited_prog_len;
    uint32_t xlated_prog_len;
    uint64_t jited_prog_insns;
    uint64_t xlated_prog_insns;
    uint64_t load_time;
    uint32_t created_by_uid;
    uint32_t nr_map_ids;
    uint64_t map_ids;
    char     name[16];
};

struct bpf_map_slot {
    uint32_t used;
    uint32_t id;
    uint32_t is_prog;
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    char     path[SV_BPF_PATH_MAX];
    char     name[16];
    /* Backing store (lazy mmap): slot_cap entries of stride bytes. */
    uint8_t *store;
    size_t   store_bytes;
    uint32_t slot_cap;
    uint32_t stride; /* 8-byte aligned: [uint8_t occupied, key..., val...] */
};

struct bpf_fd_entry {
    int32_t fd;
    int32_t map_idx;
};

struct bpf_emu_state {
    uint32_t next_id;
    struct bpf_map_slot maps[SV_BPF_MAX_MAPS];
    struct bpf_fd_entry fds[SV_BPF_MAX_FDS];
};

static volatile int g_bpf_lock = 0;
static struct bpf_emu_state *g_state = NULL;
static volatile int g_bpf_fd_count = 0;

static void bpf_lock(void)
{
    while (__atomic_test_and_set(&g_bpf_lock, __ATOMIC_ACQUIRE)) {
        __asm__ volatile("yield" ::: "memory");
    }
}

static void bpf_unlock(void)
{
    __atomic_clear(&g_bpf_lock, __ATOMIC_RELEASE);
}

static int bytes_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

static void *anon_alloc(size_t size)
{
    size_t pages = (size + 4095u) & ~4095u;
    if (!pages) pages = 4096u;
    long p = raw_syscall(__NR_mmap, 0, (long)pages, 3 /* RW */, 0x22 /* PRIV|ANON */, -1, 0);
    if ((unsigned long)p >= (unsigned long)-4095) return NULL;
    return (void *)p;
}

static struct bpf_emu_state *ensure_state(void)
{
    if (!g_state) {
        struct bpf_emu_state *s = (struct bpf_emu_state *)anon_alloc(sizeof(*s));
        if (!s) return NULL;
        s->next_id = 1;
        for (int i = 0; i < SV_BPF_MAX_FDS; i++) {
            s->fds[i].fd = -1;
            s->fds[i].map_idx = -1;
        }
        g_state = s;
    }
    return g_state;
}

static int ensure_map_store(struct bpf_map_slot *m)
{
    if (m->store) return 0;
    if (m->is_prog || m->type == SV_BPF_MAP_TYPE_RINGBUF) return 0;
    if (m->key_size == 0 || m->key_size > SV_BPF_MAX_KEY ||
        m->value_size > SV_BPF_MAX_VAL)
        return -EINVAL;
    uint32_t cap = m->max_entries;
    if (cap == 0) cap = 64;
    if (cap > SV_BPF_SLOT_CAP) cap = SV_BPF_SLOT_CAP;
    uint32_t stride = (1u + m->key_size + m->value_size + 7u) & ~7u;
    size_t bytes = (size_t)cap * (size_t)stride;
    uint8_t *mem = (uint8_t *)anon_alloc(bytes);
    if (!mem) return -ENOMEM;
    m->store = mem;
    m->store_bytes = bytes;
    m->slot_cap = cap;
    m->stride = stride;
    return 0;
}

static int find_fd_map(struct bpf_emu_state *s, int fd)
{
    if (!s || fd < 0) return -1;
    for (int i = 0; i < SV_BPF_MAX_FDS; i++) {
        if (s->fds[i].fd == fd)
            return s->fds[i].map_idx;
    }
    return -1;
}

static long alloc_handle_fd(struct bpf_emu_state *s, int map_idx)
{
    int slot = -1;
    for (int i = 0; i < SV_BPF_MAX_FDS; i++) {
        if (s->fds[i].fd < 0) {
            slot = i;
            break;
        }
    }
    if (slot < 0) return -EMFILE;
    long fd = raw_syscall(__NR_eventfd2, 0, SV_EFD_CLOEXEC, 0, 0, 0, 0);
    if (fd < 0) return fd;
    s->fds[slot].fd = (int32_t)fd;
    s->fds[slot].map_idx = map_idx;
    __atomic_add_fetch(&g_bpf_fd_count, 1, __ATOMIC_RELAXED);
    return fd;
}

static void drop_fd_locked(struct bpf_emu_state *s, int fd)
{
    if (!s || fd < 0) return;
    for (int i = 0; i < SV_BPF_MAX_FDS; i++) {
        if (s->fds[i].fd == fd) {
            s->fds[i].fd = -1;
            s->fds[i].map_idx = -1;
            __atomic_sub_fetch(&g_bpf_fd_count, 1, __ATOMIC_RELAXED);
        }
    }
}

static uint32_t parse_u32_field(const char *buf, const char *key, uint32_t defval)
{
    size_t klen = strlen(key);
    const char *p = buf;
    while (*p) {
        if (!strncmp(p, key, klen)) {
            p += klen;
            uint32_t v = 0;
            int any = 0;
            while (*p >= '0' && *p <= '9') {
                v = v * 10u + (uint32_t)(*p - '0');
                p++;
                any = 1;
            }
            return any ? v : defval;
        }
        p++;
    }
    return defval;
}

static void copy_basename(const char *path, char out[16])
{
    const char *base = path;
    for (const char *p = path; *p; p++) {
        if (*p == '/') base = p + 1;
    }
    size_t i = 0;
    while (i < 15 && base[i]) {
        out[i] = base[i];
        i++;
    }
    out[i] = '\0';
}

/* Parse a generic pinned-object metadata file:
 *   "bpf-map type=<N> key=<K> value=<V> max=<M> [flags=<F>]\n"
 *   "bpf-prog type=<N>\n"
 * Empty files default to a 4-byte/4-byte hash map with 64 entries. */
static void parse_meta(const char *buf, const char *path, struct bpf_map_slot *m)
{
    if (!strncmp(buf, "bpf-prog", 8)) {
        m->is_prog = 1;
        m->type = parse_u32_field(buf, "type=", 3);
        m->key_size = 0;
        m->value_size = 0;
        m->max_entries = 0;
        m->map_flags = 0;
    } else {
        m->is_prog = 0;
        m->type = parse_u32_field(buf, "type=", SV_BPF_MAP_TYPE_HASH);
        m->key_size = parse_u32_field(buf, "key=", 4);
        m->value_size = parse_u32_field(buf, "value=", 4);
        m->max_entries = parse_u32_field(buf, "max=", 64);
        m->map_flags = parse_u32_field(buf, "flags=", 0);
    }
    copy_basename(path, m->name);
}

static long do_map_create(const uint8_t *attr, unsigned int size)
{
    if (!attr || size < 16) return -EINVAL;
    uint32_t mtype = 0, ksz = 0, vsz = 0, maxe = 0, mflags = 0;
    memcpy(&mtype, attr + 0, 4);
    memcpy(&ksz,   attr + 4, 4);
    memcpy(&vsz,   attr + 8, 4);
    memcpy(&maxe,  attr + 12, 4);
    if (size >= 20) memcpy(&mflags, attr + 16, 4);

    bpf_lock();
    struct bpf_emu_state *s = ensure_state();
    if (!s) { bpf_unlock(); return -ENOMEM; }
    int idx = -1;
    for (int i = 0; i < SV_BPF_MAX_MAPS; i++) {
        if (!s->maps[i].used) { idx = i; break; }
    }
    if (idx < 0) { bpf_unlock(); return -ENOSPC; }
    struct bpf_map_slot *m = &s->maps[idx];
    memset(m, 0, sizeof(*m));
    m->used = 1;
    m->id = s->next_id++;
    m->type = mtype;
    m->key_size = ksz;
    m->value_size = vsz;
    m->max_entries = maxe;
    m->map_flags = mflags;
    long fd = alloc_handle_fd(s, idx);
    if (fd < 0) m->used = 0;
    bpf_unlock();
    return fd;
}

static long do_obj_pin(const uint8_t *attr, unsigned int size)
{
    if (!attr || size < 12) return -EINVAL;
    uint64_t p_ptr = 0;
    uint32_t bpf_fd = 0;
    memcpy(&p_ptr, attr + 0, 8);
    memcpy(&bpf_fd, attr + 8, 4);
    const char *gpath = (const char *)(uintptr_t)p_ptr;
    if (!gpath || !gpath[0]) return -EFAULT;

    char guest[1024], host[1024];
    int rc = proot_resolve_exec_path(AT_FDCWD, gpath, true, guest, host, sizeof(host), NULL);
    const char *key_path = (rc >= 0) ? host : gpath;

    bpf_lock();
    struct bpf_emu_state *s = ensure_state();
    int idx = find_fd_map(s, (int)bpf_fd);
    if (idx < 0) { bpf_unlock(); return -EBADF; }
    struct bpf_map_slot *m = &s->maps[idx];
    size_t plen = strnlen(key_path, SV_BPF_PATH_MAX - 1);
    memcpy(m->path, key_path, plen);
    m->path[plen] = '\0';
    if (!m->name[0]) copy_basename(gpath, m->name);
    bpf_unlock();
    return 0;
}

static long do_obj_get(const uint8_t *attr, unsigned int size)
{
    if (!attr || size < 8) return -EINVAL;
    uint64_t p_ptr = 0;
    memcpy(&p_ptr, attr + 0, 8);
    const char *gpath = (const char *)(uintptr_t)p_ptr;
    if (!gpath || !gpath[0]) return -EFAULT;

    char guest[1024], host[1024];
    int rc = proot_resolve_exec_path(AT_FDCWD, gpath, true, guest, host, sizeof(host), NULL);
    const char *resolved = (rc >= 0) ? host : gpath;

    /* Fast check: already pinned in memory? */
    bpf_lock();
    struct bpf_emu_state *s = ensure_state();
    if (!s) { bpf_unlock(); return -ENOMEM; }
    for (int i = 0; i < SV_BPF_MAX_MAPS; i++) {
        if (s->maps[i].used && s->maps[i].path[0] && !strcmp(s->maps[i].path, resolved)) {
            long fd = alloc_handle_fd(s, i);
            bpf_unlock();
            return fd;
        }
    }
    bpf_unlock();

    /* Otherwise require a backing metadata file at the resolved host path. */
    long mfd = raw_syscall(__NR_openat, AT_FDCWD, (long)resolved, O_RDONLY | O_CLOEXEC, 0, 0, 0);
    if (mfd < 0) return mfd;
    char meta[256];
    memset(meta, 0, sizeof(meta));
    long n = raw_syscall(__NR_read, mfd, (long)meta, (long)(sizeof(meta) - 1), 0, 0, 0);
    raw_syscall(__NR_close, mfd, 0, 0, 0, 0, 0);
    if (n < 0) return n;
    meta[n] = '\0';

    bpf_lock();
    s = ensure_state();
    if (!s) { bpf_unlock(); return -ENOMEM; }
    /* Re-check after reacquiring lock. */
    for (int i = 0; i < SV_BPF_MAX_MAPS; i++) {
        if (s->maps[i].used && s->maps[i].path[0] && !strcmp(s->maps[i].path, resolved)) {
            long fd = alloc_handle_fd(s, i);
            bpf_unlock();
            return fd;
        }
    }
    int idx = -1;
    for (int i = 0; i < SV_BPF_MAX_MAPS; i++) {
        if (!s->maps[i].used) { idx = i; break; }
    }
    if (idx < 0) { bpf_unlock(); return -ENOSPC; }
    struct bpf_map_slot *m = &s->maps[idx];
    memset(m, 0, sizeof(*m));
    m->used = 1;
    m->id = s->next_id++;
    size_t plen = strnlen(resolved, SV_BPF_PATH_MAX - 1);
    memcpy(m->path, resolved, plen);
    m->path[plen] = '\0';
    parse_meta(meta, gpath, m);
    long fd = alloc_handle_fd(s, idx);
    if (fd < 0) m->used = 0;
    bpf_unlock();
    return fd;
}

static long do_get_info(uint8_t *attr, unsigned int size)
{
    if (!attr || size < 16) return -EINVAL;
    uint32_t bpf_fd = 0, info_len = 0;
    uint64_t info_ptr = 0;
    memcpy(&bpf_fd,   attr + 0, 4);
    memcpy(&info_len, attr + 4, 4);
    memcpy(&info_ptr, attr + 8, 8);
    if (!info_ptr) return -EFAULT;

    bpf_lock();
    struct bpf_emu_state *s = ensure_state();
    int idx = find_fd_map(s, (int)bpf_fd);
    if (idx < 0) { bpf_unlock(); return -EBADF; }
    struct bpf_map_slot *m = &s->maps[idx];

    if (m->is_prog) {
        struct sv_bpf_prog_info pi;
        memset(&pi, 0, sizeof(pi));
        pi.type = m->type;
        pi.id = m->id;
        memcpy(pi.name, m->name, sizeof(pi.name));
        uint32_t out_len = info_len < sizeof(pi) ? info_len : (uint32_t)sizeof(pi);
        memcpy((void *)(uintptr_t)info_ptr, &pi, out_len);
        memcpy(attr + 4, &out_len, 4);
    } else {
        struct sv_bpf_map_info mi;
        memset(&mi, 0, sizeof(mi));
        mi.type = m->type;
        mi.id = m->id;
        mi.key_size = m->key_size;
        mi.value_size = m->value_size;
        mi.max_entries = m->max_entries;
        mi.map_flags = m->map_flags;
        memcpy(mi.name, m->name, sizeof(mi.name));
        uint32_t out_len = info_len < sizeof(mi) ? info_len : (uint32_t)sizeof(mi);
        memcpy((void *)(uintptr_t)info_ptr, &mi, out_len);
        memcpy(attr + 4, &out_len, 4);
    }
    bpf_unlock();
    return 0;
}

static long do_map_op(int cmd, const uint8_t *attr, unsigned int size)
{
    if (!attr || size < 16) return -EINVAL;
    uint32_t map_fd = 0;
    uint64_t key_ptr = 0, val_ptr = 0, flags = 0;
    memcpy(&map_fd, attr + 0, 4);
    memcpy(&key_ptr, attr + 8, 8);
    if (size >= 24) memcpy(&val_ptr, attr + 16, 8);
    if (size >= 32) memcpy(&flags, attr + 24, 8);

    bpf_lock();
    struct bpf_emu_state *s = ensure_state();
    int idx = find_fd_map(s, (int)map_fd);
    if (idx < 0) { bpf_unlock(); return -EBADF; }
    struct bpf_map_slot *m = &s->maps[idx];
    if (m->is_prog) { bpf_unlock(); return -EINVAL; }
    int rc = ensure_map_store(m);
    if (rc < 0) { bpf_unlock(); return rc; }

    const uint8_t *key = (const uint8_t *)(uintptr_t)key_ptr;
    uint8_t *val = (uint8_t *)(uintptr_t)val_ptr;

    if (m->type == SV_BPF_MAP_TYPE_ARRAY) {
        if (cmd == SV_BPF_MAP_DELETE_ELEM) {
            bpf_unlock();
            return -EINVAL;
        }
        if (cmd == SV_BPF_MAP_GET_NEXT_KEY) {
            if (!val || m->key_size != 4) { bpf_unlock(); return -EINVAL; }
            uint32_t next_k = 0;
            if (key) {
                uint32_t cur = 0;
                memcpy(&cur, key, 4);
                if (cur + 1u >= m->max_entries) { bpf_unlock(); return -ENOENT; }
                next_k = cur + 1u;
            } else if (m->max_entries == 0) {
                bpf_unlock();
                return -ENOENT;
            }
            memcpy(val, &next_k, 4);
            bpf_unlock();
            return 0;
        }
        if (!key || m->key_size != 4) { bpf_unlock(); return -EINVAL; }
        uint32_t k = 0;
        memcpy(&k, key, 4);
        if (k >= m->max_entries) { bpf_unlock(); return -ENOENT; }
        if (cmd == SV_BPF_MAP_LOOKUP_ELEM) {
            if (!val) { bpf_unlock(); return -EFAULT; }
            if (k < m->slot_cap) {
                uint8_t *slot = m->store + (size_t)k * m->stride;
                memcpy(val, slot + 1u + m->key_size, m->value_size);
            } else {
                memset(val, 0, m->value_size);
            }
            bpf_unlock();
            return 0;
        }
        if (cmd == SV_BPF_MAP_UPDATE_ELEM) {
            if (!val) { bpf_unlock(); return -EFAULT; }
            if (flags == SV_BPF_NOEXIST) { bpf_unlock(); return -EEXIST; }
            if (k < m->slot_cap) {
                uint8_t *slot = m->store + (size_t)k * m->stride;
                slot[0] = 1;
                memcpy(slot + 1u, &k, 4);
                memcpy(slot + 1u + m->key_size, val, m->value_size);
            }
            bpf_unlock();
            return 0;
        }
        bpf_unlock();
        return -EINVAL;
    }

    /* Hash / generic map semantics */
    if (cmd == SV_BPF_MAP_GET_NEXT_KEY) {
        if (!val) { bpf_unlock(); return -EFAULT; }
        uint32_t start = 0;
        if (key) {
            int found = -1;
            for (uint32_t i = 0; i < m->slot_cap; i++) {
                uint8_t *slot = m->store + (size_t)i * m->stride;
                if (slot[0] && bytes_eq(slot + 1u, key, m->key_size)) {
                    found = (int)i;
                    break;
                }
            }
            start = (found >= 0) ? (uint32_t)(found + 1) : 0u;
        }
        for (uint32_t i = start; i < m->slot_cap; i++) {
            uint8_t *slot = m->store + (size_t)i * m->stride;
            if (slot[0]) {
                memcpy(val, slot + 1u, m->key_size);
                bpf_unlock();
                return 0;
            }
        }
        bpf_unlock();
        return -ENOENT;
    }

    if (!key) { bpf_unlock(); return -EFAULT; }
    int match = -1, free_slot = -1;
    for (uint32_t i = 0; i < m->slot_cap; i++) {
        uint8_t *slot = m->store + (size_t)i * m->stride;
        if (slot[0]) {
            if (bytes_eq(slot + 1u, key, m->key_size)) { match = (int)i; break; }
        } else if (free_slot < 0) {
            free_slot = (int)i;
        }
    }

    if (cmd == SV_BPF_MAP_LOOKUP_ELEM) {
        if (!val) { bpf_unlock(); return -EFAULT; }
        if (match < 0) { bpf_unlock(); return -ENOENT; }
        uint8_t *slot = m->store + (size_t)match * m->stride;
        memcpy(val, slot + 1u + m->key_size, m->value_size);
        bpf_unlock();
        return 0;
    }
    if (cmd == SV_BPF_MAP_DELETE_ELEM) {
        if (match < 0) { bpf_unlock(); return -ENOENT; }
        uint8_t *slot = m->store + (size_t)match * m->stride;
        slot[0] = 0;
        bpf_unlock();
        return 0;
    }
    if (cmd == SV_BPF_MAP_UPDATE_ELEM) {
        if (!val) { bpf_unlock(); return -EFAULT; }
        if (match >= 0) {
            if (flags == SV_BPF_NOEXIST) { bpf_unlock(); return -EEXIST; }
            uint8_t *slot = m->store + (size_t)match * m->stride;
            memcpy(slot + 1u + m->key_size, val, m->value_size);
            bpf_unlock();
            return 0;
        }
        if (flags == SV_BPF_EXIST) { bpf_unlock(); return -ENOENT; }
        if (free_slot < 0) { bpf_unlock(); return -E2BIG; }
        uint8_t *slot = m->store + (size_t)free_slot * m->stride;
        slot[0] = 1;
        memcpy(slot + 1u, key, m->key_size);
        memcpy(slot + 1u + m->key_size, val, m->value_size);
        bpf_unlock();
        return 0;
    }

    bpf_unlock();
    return -EINVAL;
}

int bpf_emu_syscall(long number, long a[6], long *result)
{
    if (!g_payload_config.emulate_bpf)
        return 0;

    if (number == __NR_close) {
        if (__atomic_load_n(&g_bpf_fd_count, __ATOMIC_RELAXED) > 0) {
            bpf_lock();
            drop_fd_locked(g_state, (int)a[0]);
            bpf_unlock();
        }
        return 0; /* let real close(2) close the underlying eventfd */
    }
    if (number == __NR_dup3) {
        if (__atomic_load_n(&g_bpf_fd_count, __ATOMIC_RELAXED) > 0) {
            bpf_lock();
            drop_fd_locked(g_state, (int)a[1]);
            bpf_unlock();
        }
        return 0;
    }

#ifdef __NR_bpf
    if (number != __NR_bpf)
        return 0;

    int cmd = (int)a[0];
    uint8_t *attr = (uint8_t *)(uintptr_t)a[1];
    unsigned int size = (unsigned int)a[2];

    switch (cmd) {
    case SV_BPF_MAP_CREATE:
        *result = do_map_create(attr, size);
        return 1;
    case SV_BPF_OBJ_PIN:
        *result = do_obj_pin(attr, size);
        return 1;
    case SV_BPF_OBJ_GET:
        *result = do_obj_get(attr, size);
        return 1;
    case SV_BPF_OBJ_GET_INFO_BY_FD:
        *result = do_get_info(attr, size);
        return 1;
    case SV_BPF_MAP_LOOKUP_ELEM:
    case SV_BPF_MAP_UPDATE_ELEM:
    case SV_BPF_MAP_DELETE_ELEM:
    case SV_BPF_MAP_GET_NEXT_KEY:
        *result = do_map_op(cmd, attr, size);
        return 1;
    case SV_BPF_PROG_ATTACH:
    case SV_BPF_PROG_DETACH:
        *result = 0;
        return 1;
    default:
        *result = -ENOSYS;
        return 1;
    }
#else
    (void)a;
    (void)result;
    return 0;
#endif
}
