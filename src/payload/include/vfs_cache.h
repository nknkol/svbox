/* SPDX-License-Identifier: MIT */
/* Coherent per-process cache for immutable read-only --lower layers.
 *
 * Only caches plain read-only root --lower directories (never writable upper
 * layers, never lazy erofs caches, never dynamic overlay mounts, never under
 * --isolate). Allocated lazily via anonymous mmap on first use; holds zero
 * persistent file descriptors. */
#ifndef VFS_CACHE_H
#define VFS_CACHE_H
#include <asm/stat.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Coherent per-directory summary for an upper layer directory, validated on
 * every use against the directory's live (dev, ino, mtime, ctime, size, nlink)
 * plus an in-process atomic mutation generation counter. */
struct vfs_upper_dir_info {
    bool     has_opaque;  /* ".wh..wh..opq" exists in this directory */
    bool     has_any_wh;  /* any ".wh.*" whiteout entry exists in this directory */
    bool     bloom_valid; /* false when directory has >128 entries */
    uint64_t bloom[4];    /* 256-bit Bloom filter of child names */
};

/* Bump process-local upper mutation generation (invalidates same-tick upper cache). */
void vfs_upper_note_mutation(void);

/* Query coherent upper-directory summary for host_dir whose live lstat is dir_st.
 * Returns true if out was populated. */
bool vfs_upper_dir_probe(const char *host_dir, const struct stat *dir_st,
                         struct vfs_upper_dir_info *out);

/* Returns false iff name[0..len) is guaranteed absent from this upper directory. */
bool vfs_upper_bloom_may_contain(const struct vfs_upper_dir_info *info,
                                 const char *name, size_t len);

/* Cached lstat + directory metadata for a read-only --lower path.
 * Returns:
 *   1  if the object exists (fills *st_out, *is_empty_dir_out, *is_opaque_out)
 *   0  if the object does not exist (fills *has_wh_out if check_wh && wh_path)
 *  -1  if the lookup failed with an uncacheable error (caller may retry) */
int vfs_ro_lookup(int layer, const char *host_path, const char *rel, size_t rel_len,
                  bool check_opaque, const char *opaque_path,
                  bool check_wh, const char *wh_path,
                  struct stat *st_out, bool *is_empty_dir_out,
                  bool *is_opaque_out, bool *has_wh_out);

/* Cached readlink for a host path under a plain read-only --lower layer.
 * Returns link length (>= 0) on hit/cached fill, -EAGAIN if path is not in a
 * cacheable read-only --lower (caller should issue raw readlinkat), or other
 * negative -errno on readlink failure. */
int vfs_ro_readlink(const char *host_path, char *out, size_t size);

#endif /* VFS_CACHE_H */
