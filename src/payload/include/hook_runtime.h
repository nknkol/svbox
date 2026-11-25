#ifndef PAYLOAD_HOOK_RUNTIME_H
#define PAYLOAD_HOOK_RUNTIME_H

#include <stddef.h>
#include <stdint.h>

/* Install payload stub on SVC instructions within [target_base, target_base+size). */
int install_hook(void *target_base, size_t target_size, void *payload_entry, size_t payload_size);
/* Same, restoring prot; negative when a site could not be covered (then
 * nothing is patched and the caller must not leave the range executable). */
long install_hook_prot(void *target_base, size_t target_size, void *payload_entry, int prot);
/* For a range copied from fd at file_off: only code sections are scanned. */
long install_hook_file(void *target_base, size_t target_size, void *payload_entry, int prot,
                       int fd, unsigned long file_off);
/* Whether [addr, addr + len) touches loader, payload or stub-island memory. */
int hook_protected_overlap(uintptr_t addr, size_t len);
/* Register/unregister an internal runtime mapping so guest mm calls cannot
 * touch it while active and /proc/self/maps omits it. */
int hook_note_internal(uintptr_t base, size_t len);
void hook_unnote_internal(uintptr_t base, size_t len);
/* Reclaim pooled stub-island pages associated with an unmapped code range. */
void hook_on_munmap(uintptr_t addr, size_t len);

/* Track file-backed executable mappings copied into anonymous pages so
 * /proc/self/maps and /proc/self/smaps report their original paths/offsets. */
struct vma_info {
    uintptr_t start;
    uintptr_t end;
    uint64_t  file_off;
    uint64_t  dev;
    uint64_t  ino;
    int       is_guest_path; /* 1 = already guest path, 0 = host path to map */
    char      path[256];
};
void vma_track_add(uintptr_t start, size_t len, uint64_t file_off, int fd);
void vma_track_remove(uintptr_t start, size_t len);
int  vma_track_lookup(uintptr_t start, uintptr_t end, struct vma_info *out);
int  vma_track_next_overlap(uintptr_t start, uintptr_t end,
                            uintptr_t *ov_lo, uintptr_t *ov_hi);

#endif /* PAYLOAD_HOOK_RUNTIME_H */
