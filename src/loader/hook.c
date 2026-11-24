/* SPDX-License-Identifier: MIT */
/* Syscall hooking of the initial images (stub_island.h): the loader side
 * of the island primitives, and the islands to protect later. */
#include <asm/unistd.h>
#include "loader.h"
#include "stub_island.h"

long island_mmap(uintptr_t addr, size_t len, int prot, int flags)
{
	return z_syscall(__NR_mmap, addr, len, prot, flags, -1, 0);
}
long island_munmap(uintptr_t addr, size_t len)
{
	return z_syscall(__NR_munmap, addr, len);
}
long island_mprotect(uintptr_t addr, size_t len, int prot)
{
	return mprotect_exec((void *)addr, len, prot);
}
long island_pread(int fd, void *buf, size_t len, long offset)
{
	return z_syscall(__NR_pread64, fd, buf, len, offset);
}

static long svc_cache_openat(const char *path, int flags, int mode)
{
	return z_syscall(__NR_openat, AT_FDCWD, path, flags, mode);
}
static long svc_cache_fstat(int fd, void *st_buf)
{
	return z_syscall(__NR_fstat, fd, st_buf);
}
static long svc_cache_ftruncate(int fd, long len)
{
	return z_syscall(__NR_ftruncate, fd, len);
}
static long svc_cache_mmap_shared(int fd, size_t len)
{
	return z_syscall(__NR_mmap, 0, len, PROT_READ | PROT_WRITE, 0x01 /* MAP_SHARED */, fd, 0);
}
static long svc_cache_munmap(void *addr, size_t len)
{
	return z_syscall(__NR_munmap, addr, len);
}
static long svc_cache_close(int fd)
{
	return z_syscall(__NR_close, fd);
}
static int svc_cache_note_protected(uintptr_t base, size_t len)
{
	/* Loader unmaps the temporary cache mapping before jumping to guest. */
	(void)base;
	(void)len;
	return 0;
}

#include "svc_cache.h"

static int g_section_scan;
static const char *g_hook_scratch;
void hook_set_section_scan(int enabled) { g_section_scan = enabled; }
void hook_set_scratch(const char *scratch_dir)
{
	g_hook_scratch = (scratch_dir && scratch_dir[0]) ? scratch_dir : NULL;
}
void hook_release_cache(void)
{
	if (g_svc_cache_ptr) {
		svc_cache_munmap(g_svc_cache_ptr, SVC_CACHE_BYTES);
		g_svc_cache_ptr = NULL;
	}
	g_svc_cache_state = 0;
}

/* Islands made for the initial images; copied into the payload config. */
uint64_t g_loader_islands[64][2];
unsigned g_loader_island_count;
int island_note(uintptr_t base, size_t len)
{
	/* The payload config holds 63 islands next to the loader image. */
	if (g_loader_island_count >= 63)
		return -1;
	g_loader_islands[g_loader_island_count][0] = base;
	g_loader_islands[g_loader_island_count][1] = base + len;
	g_loader_island_count++;
	return 0;
}

long install_hook_file(void *target_base, size_t target_size, void *payload_entry, int prot,
		       int fd, unsigned long file_off)
{
	if (!payload_entry || !target_base || !target_size)
		return 0;

	struct svc_cache_map *cache = NULL;
	struct svc_cache_key key;
	int has_key = 0;
	uint32_t cached_sites[1024];

	if (g_hook_scratch && fd >= 0) {
		cache = svc_cache_get(g_hook_scratch);
		if (cache && svc_cache_key_from_fd(fd, (uint64_t)file_off, target_size, &key) == 0) {
			has_key = 1;
			uint32_t hit_cnt = 0;
			if (svc_cache_lookup(cache, &key, cached_sites, 1024u, &hit_cnt)) {
				if (hit_cnt == 0)
					return 0;
				long hrc = island_hook_sites((uintptr_t)target_base, target_size,
							     (uintptr_t)payload_entry,
							     PROT_READ | PROT_WRITE, prot,
							     cached_sites, hit_cnt);
				if (hrc < 0)
					z_printf("[loader] cannot cover syscalls in %p (+%lu): %ld\n",
						 target_base, (unsigned long)target_size, hrc);
				return hrc;
			}
		}
	}

	struct island_code code[ISLAND_CODE_MAX];
	/* Section headers do not limit control flow: only with the seccomp
	 * backstop catching anything skipped may scanning trust them. */
	int ranges = g_section_scan ? island_code_ranges(fd, file_off, target_size, code) : 0;
	if (ranges < 0) {
		if (has_key)
			svc_cache_store(cache, &key, NULL, 0);
		return 0;
	}
	/* Nothing runs this code yet: patch through a read-write view. */
	size_t found_sites = 0;
	long rc = island_hook_code_ex((uintptr_t)target_base, target_size, (uintptr_t)payload_entry,
				      PROT_READ | PROT_WRITE, prot, code, ranges,
				      has_key ? cached_sites : NULL, 1024u, &found_sites);
	if (rc >= 0 && has_key && found_sites <= 1024u)
		svc_cache_store(cache, &key, cached_sites, found_sites);
	if (rc < 0)
		z_printf("[loader] cannot cover syscalls in %p (+%lu): %ld\n",
			 target_base, (unsigned long)target_size, rc);
	return rc;
}
