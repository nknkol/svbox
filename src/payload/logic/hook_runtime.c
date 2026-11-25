#include <stddef.h>
#include <stdint.h>

#include "hook_runtime.h"
#include "config.h"
#include "platform.h"
#include "stub.h"
#include "syscall_nums.h"

/*
 * Run-time hooking: code that becomes executable (shared libraries, JIT
 * output) is scanned for svc instructions, which are replaced by branches
 * to stubs calling the payload. Uses a page-granular shared region pool so
 * small shared libraries and JIT allocations reuse protected VA regions and
 * reclaim stub pages when guest code is munmapped. Raw syscalls only.
 */

#define PROT_NONE   0x0
#define PROT_READ   0x1
#define PROT_WRITE  0x2
#define PROT_EXEC   0x4
#ifndef PROT_BTI
#define PROT_BTI    0x10
#endif

extern long raw_syscall(long sys_no, long a1, long a2, long a3, long a4, long a5, long a6);

#define ISLAND_HAS_POOL 1
static uintptr_t island_pool_alloc(uintptr_t lo, uintptr_t hi, size_t len);
static void island_pool_free(uintptr_t base, size_t len);
static void island_pool_record(uintptr_t code_lo, size_t code_len, uintptr_t island_base, size_t island_len);

#include "stub_island.h"

static long svc_cache_openat(const char *path, int flags, int mode)
{
    return raw_syscall(__NR_openat, -100 /* AT_FDCWD */, (long)path, flags, mode, 0, 0);
}
static long svc_cache_fstat(int fd, void *st_buf)
{
    return raw_syscall(__NR_fstat, fd, (long)st_buf, 0, 0, 0, 0);
}
static long svc_cache_ftruncate(int fd, long len)
{
    return raw_syscall(__NR_ftruncate, fd, len, 0, 0, 0, 0);
}
static long svc_cache_mmap_shared(int fd, size_t len)
{
    return raw_syscall(__NR_mmap, 0, (long)len, PROT_READ | PROT_WRITE, 0x01 /* MAP_SHARED */, fd, 0);
}
static long svc_cache_munmap(void *addr, size_t len)
{
    return raw_syscall(__NR_munmap, (long)addr, (long)len, 0, 0, 0, 0);
}
static long svc_cache_close(int fd)
{
    return raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
}
static int svc_cache_note_protected(uintptr_t base, size_t len)
{
    return island_note(base, len);
}

#include "svc_cache.h"

long island_mmap(uintptr_t addr, size_t len, int prot, int flags)
{
    return raw_syscall(__NR_mmap, (long)addr, (long)len, prot, flags, -1, 0);
}
long island_munmap(uintptr_t addr, size_t len)
{
    return raw_syscall(__NR_munmap, (long)addr, (long)len, 0, 0, 0, 0);
}
long island_mprotect(uintptr_t addr, size_t len, int prot)
{
    return platform_mprotect_exec(addr, len, prot);
}
long island_pread(int fd, void *buf, size_t len, long offset)
{
    return raw_syscall(__NR_pread64, fd, (long)buf, (long)len, offset, 0, 0);
}

/* Memory the guest's own mm calls must not unmap, remap or reprotect: the
 * payload image and the loader image with its islands (fixed before the
 * guest runs: the config the loader wrote), and the islands made at run
 * time (appended lock-free; fork copies them). */
#define PROTECTED_MAX 4096
static uintptr_t protected_lo[PROTECTED_MAX], protected_hi[PROTECTED_MAX];
static unsigned protected_count;
extern char __ehdr_start[], _end[];

static int protected_add(uintptr_t lo, uintptr_t hi)
{
    unsigned n = __atomic_load_n(&protected_count, __ATOMIC_ACQUIRE);
    do {
        if (n >= PROTECTED_MAX) return -1;
    } while (!__atomic_compare_exchange_n(&protected_count, &n, n + 1, 0,
                                          __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    protected_lo[n] = lo;
    __atomic_store_n(&protected_hi[n], hi, __ATOMIC_RELEASE);
    return 0;
}

int island_note(uintptr_t base, size_t len)
{
    return protected_add(base, base + len);
}

int hook_note_internal(uintptr_t base, size_t len)
{
    return protected_add(base, base + len);
}

void hook_unnote_internal(uintptr_t base, size_t len)
{
    uintptr_t hi = base + len;
    unsigned n = __atomic_load_n(&protected_count, __ATOMIC_ACQUIRE);
    if (n > PROTECTED_MAX) n = PROTECTED_MAX;
    for (unsigned i = 0; i < n; i++) {
        if (protected_lo[i] == base &&
            __atomic_load_n(&protected_hi[i], __ATOMIC_ACQUIRE) == hi) {
            __atomic_store_n(&protected_hi[i], 0, __ATOMIC_RELEASE);
            break;
        }
    }
}

/* ---- Virtualized VMA tracking for copied executable file mappings ---- */
#define VMA_TRACK_MAX 2048u

struct vma_slot {
    uintptr_t start;
    uintptr_t end;
    uint64_t  file_off;
    uint64_t  dev;
    uint64_t  ino;
    uint8_t   is_guest_path;
    uint8_t   is_exec_copy;
    char      host_path[256];
};

static struct vma_slot g_vmas[VMA_TRACK_MAX];
static unsigned g_vma_hi; /* high-water slot index */
static int g_vma_lock;

static inline void vma_lock(void)
{
    while (__atomic_test_and_set(&g_vma_lock, __ATOMIC_ACQUIRE))
        raw_syscall(__NR_sched_yield, 0, 0, 0, 0, 0, 0);
}
static inline void vma_unlock(void)
{
    __atomic_clear(&g_vma_lock, __ATOMIC_RELEASE);
}

static void vma_remove_locked(uintptr_t u_lo, uintptr_t u_hi)
{
    unsigned hi = g_vma_hi;
    for (unsigned i = 0; i < hi; i++) {
        uintptr_t s = g_vmas[i].start, e = g_vmas[i].end;
        if (!e || u_hi <= s || u_lo >= e)
            continue;
        if (u_lo <= s && u_hi >= e) {
            g_vmas[i].start = 0;
            g_vmas[i].end = 0;
        } else if (u_lo <= s) {
            g_vmas[i].file_off += (uint64_t)(u_hi - s);
            g_vmas[i].start = u_hi;
        } else if (u_hi >= e) {
            g_vmas[i].end = u_lo;
        } else {
            /* Split in middle: keep left half in place, try to store right half. */
            uint64_t right_off = g_vmas[i].file_off + (uint64_t)(u_hi - s);
            g_vmas[i].end = u_lo;
            for (unsigned j = 0; j < VMA_TRACK_MAX; j++) {
                if (!g_vmas[j].end) {
                    g_vmas[j] = g_vmas[i];
                    g_vmas[j].start = u_hi;
                    g_vmas[j].end = e;
                    g_vmas[j].file_off = right_off;
                    if (j + 1 > g_vma_hi) g_vma_hi = j + 1;
                    break;
                }
            }
        }
    }
}

void vma_track_remove(uintptr_t start, size_t len)
{
    if (!len || !__atomic_load_n(&g_vma_hi, __ATOMIC_ACQUIRE))
        return;
    uintptr_t u_lo = start & ~(ISLAND_PAGE - 1);
    uintptr_t u_hi = (start + len + ISLAND_PAGE - 1) & ~(ISLAND_PAGE - 1);
    if (u_hi <= u_lo)
        return;
    vma_lock();
    vma_remove_locked(u_lo, u_hi);
    vma_unlock();
}

void vma_track_add(uintptr_t start, size_t len, uint64_t file_off, int fd)
{
    if (!len || fd < 0)
        return;
    uintptr_t u_lo = start & ~(ISLAND_PAGE - 1);
    uintptr_t u_hi = (start + len + ISLAND_PAGE - 1) & ~(ISLAND_PAGE - 1);
    if (u_hi <= u_lo)
        return;

    /* Resolve host path + (dev, ino) directly from fd before taking lock. */
    unsigned char st[128];
    uint64_t dev = 0, ino = 0;
    if (raw_syscall(__NR_fstat, fd, (long)st, 0, 0, 0, 0) == 0) {
        __builtin_memcpy(&dev, st + 0, 8);
        __builtin_memcpy(&ino, st + 8, 8);
    }
    char link_path[32];
    const char *pfx = "/proc/self/fd/";
    size_t lp = 0;
    while (pfx[lp]) { link_path[lp] = pfx[lp]; lp++; }
    char digs[12];
    int dn = 0, fdv = fd;
    do { digs[dn++] = (char)('0' + (fdv % 10)); fdv /= 10; } while (fdv > 0 && dn < 12);
    while (dn > 0) link_path[lp++] = digs[--dn];
    link_path[lp] = '\0';

    char hpath[256];
    long rlen = raw_syscall(__NR_readlinkat, -100 /* AT_FDCWD */, (long)link_path,
                            (long)hpath, (long)(sizeof(hpath) - 1), 0, 0);
    if (rlen > 0 && hpath[0] == '/')
        hpath[rlen] = '\0';
    else {
        hpath[0] = '\0';
        rlen = 0;
    }

    vma_lock();
    vma_remove_locked(u_lo, u_hi);
    unsigned slot = VMA_TRACK_MAX;
    for (unsigned i = 0; i < g_vma_hi; i++) {
        if (!g_vmas[i].end) { slot = i; break; }
    }
    if (slot == VMA_TRACK_MAX && g_vma_hi < VMA_TRACK_MAX)
        slot = g_vma_hi++;
    if (slot < VMA_TRACK_MAX) {
        g_vmas[slot].start = u_lo;
        g_vmas[slot].end = u_hi;
        g_vmas[slot].file_off = file_off;
        g_vmas[slot].dev = dev;
        g_vmas[slot].ino = ino;
        g_vmas[slot].is_guest_path = 0;
        g_vmas[slot].is_exec_copy = 1;
        __builtin_memcpy(g_vmas[slot].host_path, hpath, (size_t)rlen + 1);
    }
    vma_unlock();
}

void vma_track_add_guest(uintptr_t start, size_t len, uint64_t file_off,
                         uint64_t dev, uint64_t ino, const char *guest_path)
{
    if (!len || !guest_path || !guest_path[0])
        return;
    uintptr_t u_lo = start & ~(ISLAND_PAGE - 1);
    uintptr_t u_hi = (start + len + ISLAND_PAGE - 1) & ~(ISLAND_PAGE - 1);
    if (u_hi <= u_lo)
        return;
    size_t plen = 0;
    while (guest_path[plen] && plen + 1 < sizeof(g_vmas[0].host_path))
        plen++;

    vma_lock();
    vma_remove_locked(u_lo, u_hi);
    unsigned slot = VMA_TRACK_MAX;
    for (unsigned i = 0; i < g_vma_hi; i++) {
        if (!g_vmas[i].end) { slot = i; break; }
    }
    if (slot == VMA_TRACK_MAX && g_vma_hi < VMA_TRACK_MAX)
        slot = g_vma_hi++;
    if (slot < VMA_TRACK_MAX) {
        g_vmas[slot].start = u_lo;
        g_vmas[slot].end = u_hi;
        g_vmas[slot].file_off = file_off;
        g_vmas[slot].dev = dev;
        g_vmas[slot].ino = ino;
        g_vmas[slot].is_guest_path = 1;
        g_vmas[slot].is_exec_copy = 0;
        __builtin_memcpy(g_vmas[slot].host_path, guest_path, plen);
        g_vmas[slot].host_path[plen] = '\0';
    }
    vma_unlock();
}

int vma_track_lookup(uintptr_t start, uintptr_t end, struct vma_info *out)
{
    if (!out || end <= start)
        return 0;
    if (__atomic_load_n(&g_vma_hi, __ATOMIC_ACQUIRE) > 0) {
        vma_lock();
        unsigned hi = g_vma_hi;
        for (unsigned i = 0; i < hi; i++) {
            if (g_vmas[i].end && g_vmas[i].host_path[0] &&
                start >= g_vmas[i].start && end <= g_vmas[i].end) {
                out->start = g_vmas[i].start;
                out->end = g_vmas[i].end;
                out->file_off = g_vmas[i].file_off;
                out->dev = g_vmas[i].dev;
                out->ino = g_vmas[i].ino;
                out->is_guest_path = g_vmas[i].is_guest_path;
                __builtin_memcpy(out->path, g_vmas[i].host_path, sizeof(out->path));
                vma_unlock();
                return 1;
            }
        }
        vma_unlock();
    }
    /* Fall back to initial loader-mapped ELF segments (prog and interp). */
    uint32_t icnt = g_payload_config.init_vma_count;
    if (icnt > CONFIG_MAX_INIT_VMAS) icnt = CONFIG_MAX_INIT_VMAS;
    for (uint32_t i = 0; i < icnt; i++) {
        const struct init_vma *iv = &g_payload_config.init_vmas[i];
        if (iv->end && start >= (uintptr_t)iv->start && end <= (uintptr_t)iv->end) {
            const char *src = iv->is_interp ? g_payload_config.exec_interp_path
                                            : g_payload_config.exec_exe;
            if (!src[0])
                return 0;
            out->start = (uintptr_t)iv->start;
            out->end = (uintptr_t)iv->end;
            out->file_off = iv->file_off;
            out->dev = iv->dev;
            out->ino = iv->ino;
            out->is_guest_path = iv->is_interp ? 0 : 1;
            size_t n = 0;
            while (src[n] && n + 1 < sizeof(out->path)) {
                out->path[n] = src[n];
                n++;
            }
            out->path[n] = '\0';
            return 1;
        }
    }
    return 0;
}

int vma_track_next_overlap(uintptr_t start, uintptr_t end,
                           uintptr_t *ov_lo, uintptr_t *ov_hi)
{
    if (end <= start)
        return 0;
    int found = 0;
    uintptr_t best_lo = 0, best_hi = 0;
    if (__atomic_load_n(&g_vma_hi, __ATOMIC_ACQUIRE) > 0) {
        vma_lock();
        unsigned hi = g_vma_hi;
        for (unsigned i = 0; i < hi; i++) {
            uintptr_t s = g_vmas[i].start, e = g_vmas[i].end;
            if (!e || !g_vmas[i].is_exec_copy || e <= start || s >= end)
                continue;
            if (!found || s < best_lo || (s == best_lo && e > best_hi)) {
                best_lo = s;
                best_hi = e;
                found = 1;
            }
        }
        vma_unlock();
    }
    uint32_t icnt = g_payload_config.init_vma_count;
    if (icnt > CONFIG_MAX_INIT_VMAS) icnt = CONFIG_MAX_INIT_VMAS;
    for (uint32_t i = 0; i < icnt; i++) {
        uintptr_t s = (uintptr_t)g_payload_config.init_vmas[i].start;
        uintptr_t e = (uintptr_t)g_payload_config.init_vmas[i].end;
        if (!e || e <= start || s >= end)
            continue;
        if (!found || s < best_lo || (s == best_lo && e > best_hi)) {
            best_lo = s;
            best_hi = e;
            found = 1;
        }
    }
    if (found) {
        if (ov_lo) *ov_lo = best_lo;
        if (ov_hi) *ov_hi = best_hi;
    }
    return found;
}

int hook_protected_overlap(uintptr_t addr, size_t len)
{
    if (!len) return 0;
    uintptr_t end = addr + len < addr ? (uintptr_t)-1 : addr + len;
    if (addr < (((uintptr_t)_end + 4095) & ~(uintptr_t)4095) && end > (uintptr_t)__ehdr_start)
        return 1;
    for (uint32_t i = 0; i < g_payload_config.protected_count && i < 64; i++)
        if (addr < g_payload_config.protected_ranges[i][1] &&
            end > g_payload_config.protected_ranges[i][0])
            return 1;
    unsigned n = __atomic_load_n(&protected_count, __ATOMIC_ACQUIRE);
    if (n > PROTECTED_MAX) n = PROTECTED_MAX;
    for (unsigned i = 0; i < n; i++) {
        uintptr_t hi = __atomic_load_n(&protected_hi[i], __ATOMIC_ACQUIRE);
        if (hi && addr < hi && end > protected_lo[i]) return 1;
    }
    return 0;
}

/* ---- Page-granular Shared Region Stub Pool + munmap reclamation ---- */
#define POOL_MAX_REGIONS 64
#define POOL_PAGES       64u
#define POOL_BYTES       (POOL_PAGES * ISLAND_PAGE) /* 256 KiB per region */
#define POOL_MAX_ALLOC   (16u * ISLAND_PAGE)        /* 64 KiB max single pooled carve */
#define POOL_TRACK_MAX   1024

struct stub_pool_region {
    uintptr_t base;
    uint64_t  used_mask; /* bit i = page i is allocated */
};

struct stub_code_track {
    uintptr_t code_lo;
    uintptr_t code_hi;
    uintptr_t island_base;
    size_t    island_len;
};

static volatile int g_pool_lock = 0;
static struct stub_pool_region g_pools[POOL_MAX_REGIONS];
static unsigned g_pool_count = 0;
static struct stub_code_track g_tracks[POOL_TRACK_MAX];
static unsigned g_track_active = 0;

static void pool_lock(void)
{
    while (__sync_lock_test_and_set(&g_pool_lock, 1))
        __asm__ volatile("yield" ::: "memory");
}

static void pool_unlock(void)
{
    __sync_lock_release(&g_pool_lock);
}

static int pool_range_ok(uintptr_t lo, uintptr_t hi, uintptr_t pbase, size_t plen)
{
    if (!hi || hi <= lo) return 0;
    uintptr_t first_site = lo;
    uintptr_t last_site = (hi - 4) & ~(uintptr_t)3;
    uintptr_t first_slot = pbase;
    uintptr_t last_slot = pbase + plen - STUB_SIZE;
    return island_slot_ok(first_site, first_slot) &&
           island_slot_ok(first_site, last_slot) &&
           island_slot_ok(last_site, first_slot) &&
           island_slot_ok(last_site, last_slot);
}

static uintptr_t pool_carve_locked(struct stub_pool_region *r, uintptr_t lo, uintptr_t hi,
                                   unsigned npages, size_t len)
{
    uint64_t want_mask = (npages >= 64u) ? ~0ull : ((1ull << npages) - 1ull);
    for (unsigned p = 0; p + npages <= POOL_PAGES; p++) {
        uint64_t m = want_mask << p;
        if ((r->used_mask & m) == 0) {
            uintptr_t addr = r->base + (uintptr_t)p * ISLAND_PAGE;
            if (pool_range_ok(lo, hi, addr, len)) {
                r->used_mask |= m;
                return addr;
            }
        }
    }
    return 0;
}

static uintptr_t island_pool_alloc(uintptr_t lo, uintptr_t hi, size_t len)
{
    if (!len || len > POOL_MAX_ALLOC || (len & (ISLAND_PAGE - 1)))
        return 0;
    unsigned npages = (unsigned)(len / ISLAND_PAGE);
    uintptr_t addr = 0;

    pool_lock();
    for (unsigned i = 0; i < g_pool_count; i++) {
        addr = pool_carve_locked(&g_pools[i], lo, hi, npages, len);
        if (addr) break;
    }
    pool_unlock();

    if (addr) {
        if (raw_syscall(__NR_mprotect, (long)addr, (long)len, PROT_READ | PROT_WRITE, 0, 0, 0) < 0) {
            island_pool_free(addr, len);
            return 0;
        }
        return addr;
    }

    /* Try to reserve a new 256 KiB PROT_NONE region nearby (after, then before). */
    struct island reg = {0, 0, 0};
    if (!island_place_prot(&reg, lo, hi, POOL_BYTES, 1, PROT_NONE) &&
        !island_place_prot(&reg, lo, hi, POOL_BYTES, -1, PROT_NONE))
        return 0;

    if (island_note(reg.base, POOL_BYTES) != 0) {
        island_munmap(reg.base, POOL_BYTES);
        return 0;
    }

    pool_lock();
    if (g_pool_count < POOL_MAX_REGIONS) {
        struct stub_pool_region *r = &g_pools[g_pool_count++];
        r->base = reg.base;
        r->used_mask = 0;
        addr = pool_carve_locked(r, lo, hi, npages, len);
    }
    pool_unlock();

    if (!addr) {
        /* Region is already in protected_ranges; leave it PROT_NONE if pool table full. */
        return 0;
    }
    if (raw_syscall(__NR_mprotect, (long)addr, (long)len, PROT_READ | PROT_WRITE, 0, 0, 0) < 0) {
        island_pool_free(addr, len);
        return 0;
    }
    return addr;
}

static void island_pool_free(uintptr_t base, size_t len)
{
    if (!base || !len || (base & (ISLAND_PAGE - 1)) || (len & (ISLAND_PAGE - 1)))
        return;
    unsigned npages = (unsigned)(len / ISLAND_PAGE);
    if (npages == 0 || npages > POOL_PAGES)
        return;
    /* Drop permissions before returning pages to the free bitmap. */
    raw_syscall(__NR_mprotect, (long)base, (long)len, PROT_NONE, 0, 0, 0);
    pool_lock();
    for (unsigned i = 0; i < g_pool_count; i++) {
        uintptr_t rb = g_pools[i].base;
        if (base >= rb && base + len <= rb + POOL_BYTES) {
            unsigned p = (unsigned)((base - rb) / ISLAND_PAGE);
            uint64_t m = (npages >= 64u) ? ~0ull : (((1ull << npages) - 1ull) << p);
            g_pools[i].used_mask &= ~m;
            break;
        }
    }
    pool_unlock();
}

static void island_pool_record(uintptr_t code_lo, size_t code_len, uintptr_t island_base, size_t island_len)
{
    if (!code_len || !island_base || !island_len)
        return;
    pool_lock();
    for (unsigned i = 0; i < POOL_TRACK_MAX; i++) {
        if (!g_tracks[i].island_base) {
            g_tracks[i].code_lo = code_lo;
            g_tracks[i].code_hi = code_lo + code_len;
            g_tracks[i].island_base = island_base;
            g_tracks[i].island_len = island_len;
            __atomic_fetch_add(&g_track_active, 1u, __ATOMIC_RELEASE);
            break;
        }
    }
    pool_unlock();
}

void hook_on_munmap(uintptr_t addr, size_t len)
{
    if (!len)
        return;
    vma_track_remove(addr, len);
    if (__atomic_load_n(&g_track_active, __ATOMIC_ACQUIRE) == 0)
        return;
    uintptr_t u_lo = addr & ~(ISLAND_PAGE - 1);
    uintptr_t u_hi = (addr + len + ISLAND_PAGE - 1) & ~(ISLAND_PAGE - 1);
    if (u_hi <= u_lo)
        return;

    uintptr_t free_bases[16];
    size_t free_lens[16];
    unsigned free_n = 0;

    pool_lock();
    for (unsigned i = 0; i < POOL_TRACK_MAX; i++) {
        if (g_tracks[i].island_base &&
            u_lo <= g_tracks[i].code_lo && u_hi >= g_tracks[i].code_hi) {
            if (free_n < 16) {
                free_bases[free_n] = g_tracks[i].island_base;
                free_lens[free_n] = g_tracks[i].island_len;
                free_n++;
            }
            g_tracks[i].island_base = 0;
            g_tracks[i].island_len = 0;
            __atomic_fetch_sub(&g_track_active, 1u, __ATOMIC_RELEASE);
        }
    }
    pool_unlock();

    for (unsigned i = 0; i < free_n; i++)
        island_pool_free(free_bases[i], free_lens[i]);
}

long install_hook_prot(void *target_base, size_t target_size, void *payload_entry, int prot)
{
    if (!target_base || !payload_entry || target_size < 4)
        return 0;
    /* Other threads may already run this code: keep it executable while
     * patching (each branch is a single aligned store). */
    return island_hook_range((uintptr_t)target_base, target_size, (uintptr_t)payload_entry,
                             PROT_READ | PROT_WRITE | PROT_EXEC, prot);
}

long install_hook_file(void *target_base, size_t target_size, void *payload_entry, int prot,
                       int fd, unsigned long file_off)
{
    if (!target_base || !payload_entry || target_size < 4)
        return 0;
    /* Code that may already run stays executable while patched; fresh code
     * (final prot without exec) is patched through a plain writable view. */
    int writable = (prot & PROT_EXEC) ? PROT_READ | PROT_WRITE | PROT_EXEC : PROT_READ | PROT_WRITE;

    struct svc_cache_map *cache = NULL;
    struct svc_cache_key key;
    int has_key = 0;
    uint32_t cached_sites[1024];

    if (!g_payload_config.isolate && g_payload_config.mount_scratch[0] && fd >= 0) {
        cache = svc_cache_get(g_payload_config.mount_scratch);
        if (cache && svc_cache_key_from_fd(fd, (uint64_t)file_off, target_size, &key) == 0) {
            has_key = 1;
            uint32_t hit_cnt = 0;
            if (svc_cache_lookup(cache, &key, cached_sites, 1024u, &hit_cnt)) {
                if (hit_cnt == 0)
                    return 0;
                return island_hook_sites((uintptr_t)target_base, target_size,
                                         (uintptr_t)payload_entry, writable, prot,
                                         cached_sites, hit_cnt);
            }
        }
    }

    struct island_code code[ISLAND_CODE_MAX];
    /* Section headers do not limit control flow: only with the seccomp
     * backstop catching anything skipped may scanning trust them. */
    int ranges = g_payload_config.seccomp_backstop ?
        island_code_ranges(fd, file_off, target_size, code) : 0;
    if (ranges < 0) {
        /* Valid ELF with SHF_EXECINSTR sections elsewhere, 0 overlap here. */
        if (has_key)
            svc_cache_store(cache, &key, NULL, 0);
        return 0;
    }

    size_t found_sites = 0;
    long rc = island_hook_code_ex((uintptr_t)target_base, target_size, (uintptr_t)payload_entry,
                                  writable, prot, code, ranges,
                                  has_key ? cached_sites : NULL, 1024u, &found_sites);
    if (rc >= 0 && has_key && found_sites <= 1024u)
        svc_cache_store(cache, &key, cached_sites, found_sites);
    return rc;
}

int install_hook(void *target_base, size_t target_size, void *payload_entry, size_t payload_size)
{
    (void)payload_size;
    long rc = install_hook_prot(target_base, target_size, payload_entry, PROT_READ | PROT_EXEC);
    return rc > 0 ? (int)rc : 0;
}
