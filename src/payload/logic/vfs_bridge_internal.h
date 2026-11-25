/* SPDX-License-Identifier: MIT */
/* Internal to the PRoot path backend: the per-call Bridge and the helpers
 * its parts share:
 *  - vfs_bridge.c : Bridge pool, table caching, optimism retry, public proot_* APIs
 *  - vfs_walk.c   : path resolution, view/visibility, reverse map, secure walk, union_prepare
 *  - vfs_ops.c    : syscall dispatch, mutations, owners, socket addresses
 *  - vfs_glue.c   : synthetic bind-mount parent glue tree
 *  - vfs_cache.c  : coherent read-only --lower stat/dir/readlink cache
 *  - vfs_mounts.c : R4 mount table, tmpfs, loop devices, overlay, /proc/filesystems
 *  - vfs_procfs.c : /proc links, cmdline, mount tables, status, cpuinfo, meminfo
 * Not a public interface: include only from these. */
#ifndef PROOT_BRIDGE_INTERNAL_H
#define PROOT_BRIDGE_INTERNAL_H
#include <asm/stat.h>
#include <asm/unistd.h>
#include <linux/fcntl.h>
#include <linux/inotify.h>
#include <linux/un.h>
#ifndef AF_UNIX
#define AF_UNIX 1 /* linux/socket.h does not export address families. */
#endif
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include "config.h"
#include "platform.h"
#include "syscall_nums.h"
#include "vfs_bridge.h"
#include "fake_ids.h"
#include "container_state.h"
#include "union_view.h"
#include "vfs_cache.h"
#include "net_view.h"
#include "fd_runtime.h"
#include "fs_policy.h"
#include "vfs_scratch.h"
#include "path/resolve_core.h"
#include "path/binding_core.h"

#define S_IFMT 0170000
#define S_IFDIR 0040000
#define S_IFREG 0100000
#define S_IFLNK 0120000
extern long raw_syscall(long, long, long, long, long, long, long);
/* Host path calls go through the broker in isolation mode. */
#include "host_syscall.h"
#include "broker_proto.h"
#define raw_syscall host_syscall
_Static_assert(sizeof(struct stat) == 128 && offsetof(struct stat, st_mode) == 16,
               "Adapter requires Linux AArch64 kernel stat ABI");
/* AArch64 user msghdr; only the name fields are rewritten, in a private copy. */
struct guest_msghdr {
    void *name;
    int name_length;
    void *iov;
    size_t iov_length;
    void *control;
    size_t control_length;
    unsigned int flags;
};
_Static_assert(sizeof(struct guest_msghdr) == 56, "AArch64 msghdr ABI");

#define BRIDGE_FRAMES 6
#define DEEP_FRAMES_SIZE ((CANON_LEVELS - BRIDGE_FRAMES) * sizeof(PathFrame))
#define LINK_HINTS 8
struct link_hints {
    int count;
    char path[LINK_HINTS][PATH_MAX], target[LINK_HINTS][PATH_MAX];
};

typedef struct {
    /* Cached binding/mount/view tables across pooled Bridge reuses. */
    bool table_ready;
    uint64_t cached_mount_ver;

    BindingTable table;
    bool mutation;
    bool traverse; /* Final ancestor-only paths are acceptable for this call. */
    bool follow_final; /* Resolution dereferences a final symlink. */
    bool attributes; /* The call changes metadata of an existing name. */
    bool creates; /* The call creates a new name (EEXIST if it exists). */
    /* Skip the final lstat: the call itself detects a final symlink
     * (open with O_NOFOLLOW, ELOOP) and is then resolved again. */
    bool defer_final;
    /* The final lstat of a followed resolution found no symlink: that is
     * the stat result for the same host path (saves one host walk). */
    bool final_valid;
    /* final_stat describes the object b->host names (checked before the
     * guarded walk rewrites b->host; the walk pins that same inode). */
    bool final_match;
    struct stat final_stat;
    /* Per-resolve last host_map dedup (eliminates redundant resolve_core final map). */
    bool last_map_valid;
    const struct union_view *last_map_view;
    char last_map_guest[PATH_MAX];
    char last_map_host[PATH_MAX];
    /* Isolation mode: every host lookup is a round trip to the broker. */
    bool optimistic_allowed, optimistic, optimistic_used, force_full;
    const struct link_hints *hints;
    /* Guarded modes: walked parent directory descriptors. */
    bool secure;
    int walk_fd[4], walk_count;
    bool reads; /* Immutable read policy snapshot below is active. */
    enum fs_access access[CONFIG_MOUNT_IDS];
    struct fs_policy policy;
    const char *exposed[CONFIG_MOUNT_IDS];
    size_t exposed_count;
    /* Private getdents64 bounce: hidden names never reach guest memory. */
    unsigned char dirents[4096];
    char classified[PATH_MAX];
    const struct proot_path_context *context;
    int anchor_fd;
    struct proot_open_origin anchor;
    PathBinding bindings[CONFIG_MOUNT_IDS - 1];
    /* R4: the mount table as this call sees it (bindings point into it). */
    struct mount_entry mounts[CONFIG_MAX_MOUNTS];
    int mount_count;
    char cwd[PATH_MAX], guest[PATH_MAX], host[PATH_MAX];
    char first_guest[PATH_MAX], first_host[PATH_MAX];
    struct sockaddr_un address;
    struct guest_msghdr message;
    /* /proc link emulation: never the first_* pair a caller may hold. */
    char proc_guest[PATH_MAX], proc_host[PATH_MAX], proc_link_host[PATH_MAX];
    char proc_data[65536]; /* A loader-run process's kernel cmdline (supports long argv). */
    char proc_candidate[PATH_MAX];
    PathFrame path_frames[BRIDGE_FRAMES];
    PathFrame *deep_frames;
    char resolve_scratch[2][PATH_MAX];
    char fd_host[PATH_MAX], mapped[PATH_MAX], final_host[PATH_MAX];
    /* R6: the root's merged view (union_view.h). */
    struct union_view views[1 + MOUNT_OVERLAYS];
    int view_count;
    const struct union_view *uv, *first_uv;
    const struct union_view *map_view, *final_view;
    bool root_union; /* views[0] is the root's */
    char overlay_lowers[MOUNT_OVERLAYS * CONFIG_MAX_LOWERS][CONFIG_MAX_PATH];
    bool union_on;
    int union_op;
    long open_flags;
    bool union_opaque;
    int union_layer, first_union_layer;
    struct union_memo umemo;
    char union_rel[PATH_MAX], first_union_rel[PATH_MAX], union_named[PATH_MAX];
} Bridge;

enum { UOP_READ, UOP_COPY, UOP_RECORD, UOP_CREATE, UOP_OPEN };

/* Shared between the VFS modules (pb_: proot bridge). */
extern const char pb_unmounted[];
#define UNMOUNTED pb_unmounted

/* vfs_glue.c */
bool pb_glue_ancestor(const Bridge *b, const char *guest);
int pb_glue_host(Bridge *b);
bool pb_glue_guest(const char *host, char *guest);

/* vfs_walk.c */
int pb_bridge_alias(Bridge *b, const char *host, char *out);
int pb_host_map(void *opaque, const char *guest, char *host);
int pb_path_visibility(Bridge *b, const char *guest);
int pb_watch_hides_child(Bridge *b, const char *guest);
int pb_host_readlink(void *opaque, const char *path, char *out, size_t size);
int pb_guest_link_target(Bridge *b, char *target);
int pb_observed_guest_path(Bridge *b, const char *host, char *guest);
int pb_preferred_guest_path(Bridge *b, const char *host, char *guest);
int pb_host_fd(void *opaque, int fd, char *guest);
long pb_guest_cwd(Bridge *b);
int pb_union_fd(Bridge *b, int fd);
bool pb_lexical_path(const char *path);
int pb_resolve(Bridge *b, int dirfd, const char *path, bool follow);

/* vfs_ops.c */
long pb_dispatch(Bridge *b, long number, long a[6], struct proot_open_origin *origin);

/* vfs_mounts.c */
int pb_loop_device(const char *guest);
long pb_loop_path_call(long number, long a[6], int device);
long pb_mount_call(Bridge *b, long a[6]);
long pb_umount_call(Bridge *b, long a[6]);
long pb_proc_filesystems(Bridge *b, int flags);

/* vfs_procfs.c */
long pb_proc_cmdline(Bridge *b, int flags);
int pb_proc_link(void *opaque, char *out, const char *path, const char *component, Comparison comparison);
long pb_proc_mounts(Bridge *b, int flags);
long pb_proc_status(Bridge *b, int flags);
long pb_proc_cgroup(Bridge *b, int flags);
long pb_proc_environ(Bridge *b, int flags);
long pb_proc_attr(Bridge *b, int flags);
long pb_proc_maps(Bridge *b, int flags);
long pb_proc_cpuinfo(Bridge *b, int flags);
long pb_proc_meminfo(Bridge *b, int flags);
long pb_proc_fallback(Bridge *b, int flags);
long pb_proc_readlink(Bridge *b, long a[6]);
void pb_vfd_record(int fd, const char *guest_path);
int pb_vfd_guest_path(int fd, char *out, size_t cap);

#endif
