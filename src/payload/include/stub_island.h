/* Shared syscall-stub placement for the loader (initial images) and the
 * payload (code mapped at run time). The includer defines:
 *   long island_mmap(uintptr_t addr, size_t len, int prot, int flags);
 *       returns the address or a negative errno
 *   long island_munmap(uintptr_t addr, size_t len);
 *   long island_mprotect(uintptr_t addr, size_t len, int prot);
 *
 * Every `svc #0` gets a stub that its `b` (±128 MiB) can reach, in one or two
 * islands placed right after and right before the code with
 * MAP_FIXED_NOREPLACE, so any segment up to 256 MiB is fully covered. Both
 * directions are checked (stub → return address too). Islands are filled,
 * then made executable once; the code is made writable once. A site that
 * cannot be covered fails the whole range instead of being left as a raw
 * syscall that bypasses the payload. */
#ifndef STUB_ISLAND_H
#define STUB_ISLAND_H

#include <stddef.h>
#include <stdint.h>
#include "stub.h"

#define ISLAND_SVC0 0xd4000001u
#define ISLAND_PAGE 4096ul
#define ISLAND_REACH 134217727l
#define ISLAND_STEP (1ul << 20)
#define ISLAND_PROT_READ 1
#define ISLAND_PROT_WRITE 2
#define ISLAND_PROT_EXEC 4
#define ISLAND_MAP_PRIVATE 0x02
#define ISLAND_MAP_ANONYMOUS 0x20
#define ISLAND_MAP_FIXED_NOREPLACE 0x100000

long island_mmap(uintptr_t addr, size_t len, int prot, int flags);
long island_munmap(uintptr_t addr, size_t len);
/* Called for every finished island, so the payload can protect it.
 * Nonzero when it could not be registered: the installation then fails. */
int island_note(uintptr_t base, size_t len);
long island_pread(int fd, void *buf, size_t len, long offset);

/* Byte ranges of real code inside a mapping, relative to its start. */
struct island_code { size_t start, end; };
#define ISLAND_CODE_MAX 16

/* Code ranges of the file bytes [file_off, file_off + len) of an ELF64
 * AArch64 file, from its SHF_EXECINSTR sections, so literal data that
 * happens to encode `svc #0` is never rewritten. Returns the count, or 0
 * when the file has no usable section headers (scan everything then). */
static inline int island_code_ranges(int fd, unsigned long file_off, size_t len,
                                     struct island_code *out)
{
    unsigned char eh[64];
    if (fd < 0 || island_pread(fd, eh, sizeof(eh), 0) != (long)sizeof(eh)) return 0;
    if (eh[0] != 0x7f || eh[1] != 'E' || eh[2] != 'L' || eh[3] != 'F' || eh[4] != 2) return 0;
    uint64_t shoff = 0;
    uint16_t shentsize = 0, shnum = 0;
    __builtin_memcpy(&shoff, eh + 0x28, 8);
    __builtin_memcpy(&shentsize, eh + 0x3a, 2);
    __builtin_memcpy(&shnum, eh + 0x3c, 2);
    if (!shoff || shentsize != 64 || !shnum || shnum > 4096) return 0;
    int count = 0;
    for (uint16_t i = 0; i < shnum; i++) {
        unsigned char sh[64];
        if (island_pread(fd, sh, sizeof(sh), (long)(shoff + (uint64_t)i * 64)) != (long)sizeof(sh))
            return 0;
        uint32_t type;
        uint64_t flags, offset, size;
        __builtin_memcpy(&type, sh + 4, 4);
        __builtin_memcpy(&flags, sh + 8, 8);
        __builtin_memcpy(&offset, sh + 24, 8);
        __builtin_memcpy(&size, sh + 32, 8);
        if (type != 1 /* PROGBITS */ || !(flags & 4 /* SHF_EXECINSTR */) || !size) continue;
        if (offset + size <= file_off || offset >= file_off + len) continue;
        if (count == ISLAND_CODE_MAX) return 0; /* Too fragmented: scan everything. */
        size_t start = offset > file_off ? offset - file_off : 0;
        size_t end = offset + size - file_off;
        out[count++] = (struct island_code){start, end > len ? len : end};
    }
    /* Section headers that place no code here (e.g. a non-text executable
     * segment) are not trusted: scan everything. */
    return count;
}
long island_mprotect(uintptr_t addr, size_t len, int prot);

struct island { uintptr_t base; size_t size, used; };

static inline int island_branch_ok(uintptr_t from, uintptr_t to)
{
    long offset = (long)to - (long)from;
    return offset >= -ISLAND_REACH - 1 && offset <= ISLAND_REACH && !(offset & 3);
}

/* Every branch between the site and its stub, both ways (stub.c layout). */
static inline int island_slot_ok(uintptr_t site, uintptr_t slot)
{
    return island_branch_ok(site, slot) && island_branch_ok(slot + 15 * 4, site + 4) &&
           island_branch_ok(slot + 17 * 4, site + 4) && island_branch_ok(slot + 27 * 4, site + 4) &&
           island_branch_ok(slot + 31 * 4, site + 4);
}

/* An island of len bytes at exactly `want`, or 0. Kernels that treat
 * MAP_FIXED_NOREPLACE as a hint return another address: refused too. */
static inline uintptr_t island_map_at_prot(uintptr_t want, size_t len, int prot)
{
    long r = island_mmap(want, len, prot,
                         ISLAND_MAP_PRIVATE | ISLAND_MAP_ANONYMOUS | ISLAND_MAP_FIXED_NOREPLACE);
    if (r < 0 && r > -4096) return 0;
    if ((uintptr_t)r != want) { island_munmap((uintptr_t)r, len); return 0; }
    return want;
}

static inline uintptr_t island_map_at(uintptr_t want, size_t len)
{
    return island_map_at_prot(want, len, ISLAND_PROT_READ | ISLAND_PROT_WRITE);
}

/* Search outward from the code with a given stride: after end (dir > 0) or before start. */
static inline int island_place_stride(struct island *is, uintptr_t lo, uintptr_t hi, size_t len,
                                      int dir, uintptr_t stride, uintptr_t max_dist, int prot)
{
    uintptr_t limit = (uintptr_t)ISLAND_REACH;
    if (len >= limit) return 0;
    limit -= len;
    if (max_dist && max_dist < limit) limit = max_dist;
    for (uintptr_t step = 0; step <= limit; step += stride) {
        uintptr_t want;
        if (dir > 0) {
            want = ((hi + ISLAND_PAGE - 1) & ~(ISLAND_PAGE - 1)) + step;
        } else {
            uintptr_t base_lo = lo & ~(ISLAND_PAGE - 1);
            if (base_lo <= step + len + ISLAND_PAGE) return 0;
            want = base_lo - step - len;
        }
        if (island_map_at_prot(want, len, prot)) {
            *is = (struct island){want, len, 0};
            return 1;
        }
    }
    return 0;
}

/* Three-stage outward hole search: fast 1 MiB coarse scan, then 64 KiB fine scan,
 * then 4 KiB ultra-fine edge scan so even tight gaps in crowded VA spaces work. */
static inline int island_place_prot(struct island *is, uintptr_t lo, uintptr_t hi, size_t len,
                                    int dir, int prot)
{
    if (island_place_stride(is, lo, hi, len, dir, ISLAND_STEP, 0, prot))
        return 1;
    if (island_place_stride(is, lo, hi, len, dir, 65536ul, 0, prot))
        return 1;
    return island_place_stride(is, lo, hi, len, dir, ISLAND_PAGE, 2ul << 20, prot);
}

static inline int island_place(struct island *is, uintptr_t lo, uintptr_t hi, size_t len, int dir)
{
    return island_place_prot(is, lo, hi, len, dir, ISLAND_PROT_READ | ISLAND_PROT_WRITE);
}

static inline uintptr_t island_take(struct island *is, uintptr_t site)
{
    if (!is->base || is->used + STUB_SIZE > is->size) return 0;
    uintptr_t slot = is->base + is->used;
    if (!island_slot_ok(site, slot)) return 0;
    is->used += STUB_SIZE;
    return slot;
}

static inline void island_flush(uintptr_t start, size_t len)
{
    for (uintptr_t p = start & ~63ul; p < start + len; p += 64)
        __asm__ volatile("dc cvau, %0" : : "r"(p) : "memory");
    __asm__ volatile("dsb ish");
    for (uintptr_t p = start & ~63ul; p < start + len; p += 64)
        __asm__ volatile("ic ivau, %0" : : "r"(p) : "memory");
    __asm__ volatile("dsb ish\n isb" ::: "memory");
}

/* Hooks every svc #0 in [base, base + size). writable_prot is the protection
 * used while patching (RW for code nothing executes yet, RWX when other
 * threads may run it); final_prot is restored afterwards. Returns the
 * number of hooked sites, or a negative errno when any site could not be
 * covered (then nothing in the range is patched). */
static inline int island_in_code(const struct island_code *code_ranges, int ranges, size_t byte)
{
    if (!ranges) return 1;
    for (int r = 0; r < ranges; r++)
        if (byte >= code_ranges[r].start && byte < code_ranges[r].end) return 1;
    return 0;
}
#define ISLAND_SITE(i) (code[i] == ISLAND_SVC0 && island_in_code(code_ranges, ranges, (i) * 4))

static inline long island_hook_code(uintptr_t base, size_t size, uintptr_t payload_entry,
                                    int writable_prot, int final_prot,
                                    const struct island_code *code_ranges, int ranges)
{
    uint32_t *code = (uint32_t *)base;
    size_t words = size / 4, sites = 0;
    for (size_t i = 0; i < words; i++)
        sites += ISLAND_SITE(i);
    if (!sites) return 0;
    /* The sites' word indexes, so later passes do not rescan the code.
     * Avoid mmap/munmap overhead on small JIT / shared-lib segments. */
    uint32_t small_list[256];
    uint32_t *list = small_list;
    size_t list_len = 0;
    if (sites > 256) {
        list_len = (sites * sizeof(uint32_t) + ISLAND_PAGE - 1) & ~(ISLAND_PAGE - 1);
        long list_mem = island_mmap(0, list_len, ISLAND_PROT_READ | ISLAND_PROT_WRITE,
                                    ISLAND_MAP_PRIVATE | ISLAND_MAP_ANONYMOUS);
        if (list_mem < 0 && list_mem > -4096) return list_mem;
        list = (uint32_t *)list_mem;
    }
    for (size_t i = 0, n = 0; i < words && n < sites; i++)
        if (ISLAND_SITE(i)) list[n++] = (uint32_t)i;
    size_t len = (sites * STUB_SIZE + ISLAND_PAGE - 1) & ~(ISLAND_PAGE - 1);
    struct island after = {0, 0, 0}, before = {0, 0, 0};
    int after_pooled = 0, before_pooled = 0;
#ifdef ISLAND_HAS_POOL
    if (size <= (120ul << 20)) {
        uintptr_t pbase = island_pool_alloc(base, base + size, len);
        if (pbase) {
            after = (struct island){pbase, len, 0};
            after_pooled = 1;
        }
    }
#endif
    if (!after.base)
        island_place(&after, base, base + size, len, 1);
    /* Sites the after-island cannot reach (segments over 128 MiB). */
    size_t far = 0;
    for (size_t k = 0; k < sites; k++) {
        uintptr_t site = (uintptr_t)&code[list[k]];
        if (!after.base || !island_slot_ok(site, after.base) ||
            !island_slot_ok(site, after.base + len - STUB_SIZE))
            far++;
    }
    if (far) {
        size_t far_len = (far * STUB_SIZE + ISLAND_PAGE - 1) & ~(ISLAND_PAGE - 1);
#ifdef ISLAND_HAS_POOL
        if (size <= (120ul << 20)) {
            uintptr_t pbase = island_pool_alloc(base, base + size, far_len);
            if (pbase) {
                before = (struct island){pbase, far_len, 0};
                before_pooled = 1;
            }
        }
#endif
        if (!before.base)
            island_place(&before, base, base + size, far_len, -1);
    }
    /* Assign every site before touching the code: all or nothing. */
    long rc = 0;
    for (size_t k = 0; k < sites && !rc; k++) {
        uintptr_t site = (uintptr_t)&code[list[k]];
        uintptr_t slot = island_take(&after, site);
        if (!slot) slot = island_take(&before, site);
        if (!slot) { rc = -12; break; } /* -ENOMEM: no reachable stub */
        stub_emit((void *)slot, payload_entry, site + 4);
    }
    struct island *islands[2] = {&after, &before};
    int pooled[2] = {after_pooled, before_pooled};
    for (int k = 0; k < 2; k++) {
        struct island *is = islands[k];
        if (!is->base) continue;
        if (rc || !is->used) {
#ifdef ISLAND_HAS_POOL
            if (pooled[k]) island_pool_free(is->base, is->size);
            else
#endif
            island_munmap(is->base, is->size);
            is->base = 0;
            continue;
        }
        size_t used = (is->used + ISLAND_PAGE - 1) & ~(ISLAND_PAGE - 1);
        if (used < is->size) {
#ifdef ISLAND_HAS_POOL
            if (pooled[k]) island_pool_free(is->base + used, is->size - used);
            else
#endif
            island_munmap(is->base + used, is->size - used);
            is->size = used;
        }
        island_flush(is->base, is->used);
        long p = island_mprotect(is->base, used, ISLAND_PROT_READ | ISLAND_PROT_EXEC);
        if (p < 0 && !rc) rc = p;
        /* Non-pooled islands register individually; pooled regions are already protected. */
        if (p >= 0 && !pooled[k] && island_note(is->base, used) && !rc) rc = -12;
    }
    for (int k = 0; rc && k < 2; k++) {
        struct island *is = islands[k];
        if (is->base) {
#ifdef ISLAND_HAS_POOL
            if (pooled[k]) island_pool_free(is->base, is->size);
            else
#endif
            island_munmap(is->base, is->size);
            is->base = 0;
        }
    }
    long hooked = 0;
    if (!rc) {
        /* Patch: the stubs exist; each branch is one aligned 4-byte store. */
        uintptr_t page_lo = base & ~(ISLAND_PAGE - 1);
        size_t span = ((base + size + ISLAND_PAGE - 1) & ~(ISLAND_PAGE - 1)) - page_lo;
        rc = island_mprotect(page_lo, span, writable_prot);
        if (!rc) {
            /* Same assignment order as above, so the same slots: after-island
             * first, then before (unused tails were unmapped beyond the last). */
            after.used = before.used = 0;
            uintptr_t flushed = 0;
            for (size_t k = 0; k < sites; k++) {
                uintptr_t site = (uintptr_t)&code[list[k]];
                uintptr_t slot = island_take(&after, site);
                if (!slot) slot = island_take(&before, site);
                long offset = (long)slot - (long)site;
                __atomic_store_n(&code[list[k]],
                                 0x14000000u | ((uint32_t)(offset >> 2) & 0x03ffffffu),
                                 __ATOMIC_RELEASE);
                /* Only the patched lines need cache maintenance. */
                uintptr_t line = site & ~63ul;
                if (line != flushed) {
                    __asm__ volatile("dc cvau, %0" : : "r"(line) : "memory");
                    flushed = line;
                }
                hooked++;
            }
            __asm__ volatile("dsb ish" ::: "memory");
            flushed = 0;
            for (size_t k = 0; k < sites; k++) {
                uintptr_t line = (uintptr_t)&code[list[k]] & ~63ul;
                if (line != flushed) {
                    __asm__ volatile("ic ivau, %0" : : "r"(line) : "memory");
                    flushed = line;
                }
            }
            __asm__ volatile("dsb ish\n isb" ::: "memory");
            rc = island_mprotect(page_lo, span, final_prot);
#ifdef ISLAND_HAS_POOL
            if (!rc) {
                for (int k = 0; k < 2; k++) {
                    if (pooled[k] && islands[k]->base)
                        island_pool_record(page_lo, span, islands[k]->base, islands[k]->size);
                }
            }
#endif
        }
    }
    if (list_len)
        island_munmap((uintptr_t)list, list_len);
    return rc < 0 ? rc : hooked;
}
#undef ISLAND_SITE

static inline long island_hook_range(uintptr_t base, size_t size, uintptr_t payload_entry,
                                     int writable_prot, int final_prot)
{
    return island_hook_code(base, size, payload_entry, writable_prot, final_prot, NULL, 0);
}

#endif /* STUB_ISLAND_H */
