#ifndef PAYLOAD_CONFIG_H
#define PAYLOAD_CONFIG_H

#include <stdint.h>

#define LOG_LEVEL_NONE   0
#define LOG_LEVEL_ERROR  1
#define LOG_LEVEL_WARN   2
#define LOG_LEVEL_INFO   3
#define LOG_LEVEL_DEBUG  4

#define CONFIG_MAGIC        0x484f4f4b /* "HOOK" */
#define CONFIG_VERSION      1

/* compat keeps the host environment and identity; container starts from a
 * clean environment and fake root (PRoot -0). */
#define CONFIG_MODE_COMPAT     0
#define CONFIG_MODE_CONTAINER  1

#define SVBOX_VERSION "0.1.0"

#define CONFIG_MAX_PATH     256
#define CONFIG_AUXV_PAIRS   64
#define CONFIG_MAX_BINDS    64
#define CONFIG_MAX_VDEVS    32

struct vdev_entry {
    char guest[CONFIG_MAX_PATH];
    char sock[CONFIG_MAX_PATH];
    int32_t type; /* VDEV_TYPE_CHR=0, VDEV_TYPE_BINDER=1 */
};

#define CONFIG_MAX_INIT_VMAS 16
struct init_vma {
    uint64_t start;
    uint64_t end;
    uint64_t file_off;
    uint64_t dev;
    uint64_t ino;
    uint32_t is_interp;
    uint32_t _pad;
};

/* Internal child-loader exec handoff (not part of the public CLI).
 * --__handoff-fd carries a binary svbox_handoff_t in an unlinked memfd;
 * --__exec-exe remains in argv so /proc/<pid>/exe inspection of sibling
 * processes can recover the guest executable path from /proc/<pid>/cmdline. */
#define SVBOX_HANDOFF_MAGIC    0x53564258484E4431ull /* "SVBXHND1" */
#define SVBOX_HANDOFF_VERSION  1u
#define SVBOX_CHILD_HANDOFF_FD "--__handoff-fd"
#define SVBOX_CHILD_EXEC_EXE   "--__exec-exe"

#define CONFIG_OWNERS (CONFIG_MAX_BINDS + 2)
#define CONFIG_ISOLATE_DEVICES 4
/* Isolation mode: the loader FD every guest exec runs (the filter knows it). */
#define CONFIG_ISOLATE_LOADER_FD 898
/* Container mounts (docs/OCI.md, R4): the shared mount table every process
 * of the view maps (inherited at this number), and where tmpfs mounts get
 * their directories. */
#define CONFIG_MOUNT_TABLE_FD 901
#define CONFIG_MAX_MOUNTS 48
#define CONFIG_MOUNT_TABLE_BYTES 53248 /* container_state.h checks it */
/* Mount ids of one view: 0 the root, 1.. the binds, then the table slots. */
#define CONFIG_MOUNT_IDS (CONFIG_MAX_BINDS + 1 + CONFIG_MAX_MOUNTS)
/* Owner metadata (docs/OCI.md, R5): the owner database file, opened by the
 * initial loader (--owner-db PATH) and inherited at this number. */
#define CONFIG_OWNER_DB_FD 902
/* Copy-on-write root (docs/OCI.md, R6): read-only lower directories under
 * the root, topmost first (--lower DIR[:IMAGE], repeated); the root is upper. */
#define CONFIG_MAX_LOWERS 8
/* FDs the runtime holds: the loader FD (898), the isolation control
 * socket (899 up), the broker channels (900 up), the mount table (901) and
 * the owner database (902). --pass-fd refuses these numbers. */
#define CONFIG_RESERVED_FD_MIN 898
/* --pass-fd N: an inherited FD the caller hands to the guest, writable when
 * it was opened for writing. Known by its object (dev, ino) and access flags. */
#define CONFIG_MAX_PASSED_FDS 16
struct passed_fd {
    int32_t fd;
    uint32_t flags;  /* O_ACCMODE | O_APPEND as opened */
    uint64_t dev, ino;
};

#define BIND_FLAG_NOMNT 1u

struct bind_entry {
    char src[CONFIG_MAX_PATH];
    char dst[CONFIG_MAX_PATH];
    /* Set by the loader when host names below the parent mount match this
     * mountpoint regardless of case: 1 + length of the parent's guest
     * prefix (matched exactly); the rest matches ignoring ASCII case. */
    uint32_t fold;
    /* Optional generic bind flags (e.g. BIND_FLAG_NOMNT: omit from /proc/mounts). */
    uint32_t flags;
};

/* What the FD runtime and mount access policy enforce (each level includes
 * the previous ones). GUARD_NONE disables the FD runtime completely for
 * zero fast-path overhead. */
enum guard_level {
    GUARD_NONE = 0, /* Fast path: no FD runtime overhead */
    GUARD_TRACK,    /* FD tracking runtime enabled, no mount policy */
    GUARD_OBSERVE,  /* --observe-mount-access: record origins only */
    GUARD_PATHS,    /* --guard-path-mutations: path-based changes */
    GUARD_FILES,    /* --guard-file-mutations: and FD-based changes */
    GUARD_READS,    /* --guard-file-access: and reads, listings, exec */
};

/* Written by the loader into the payload before the guest runs
 * (PAYLOAD_ABI_VERSION). `guard` MUST remain at offset 0 for entry.S. */
typedef struct payload_config {
    int32_t guard;           /* enum guard_level; offset 0 read by entry.S */
    int32_t log_level;       /* LOG_LEVEL_* */
    int32_t mode;            /* CONFIG_MODE_* */
    int32_t bind_count;
    char root[CONFIG_MAX_PATH];
    struct bind_entry binds[CONFIG_MAX_BINDS];
    /* Host path of the loader binary, re-executed for every guest exec. */
    char loader_path[CONFIG_MAX_PATH];
    /* Guest path of the running executable (interpreter for scripts), for
     * /proc/<pid>/exe. The kernel link names the loader instead. */
    char exec_exe[CONFIG_MAX_PATH];
    /* Glue tree base: PROOT_TMP_DIR, TMPDIR or /tmp of the initial loader. */
    char glue_dir[CONFIG_MAX_PATH];
    uint32_t fake_ids[8]; /* Guest r/e/s/fs uid then gid; all 0 initially. */
    /* --link-copy: a hard link the storage refuses becomes a copy. */
    int32_t link_copy;
    /* --seccomp-backstop: unhooked syscalls trap to the payload. */
    int32_t seccomp_backstop;
    /* --isolate: host path calls go to the broker (isolate_fd: its control
     * socket, inherited by every guest process). */
    int32_t isolate;
    int32_t isolate_fd;
    int32_t loader_fd; /* the loader binary, not close-on-exec */
    int32_t owner_count; /* isolation mode: owners known (else looked up) */
    uint32_t owners[CONFIG_OWNERS][2];
    /* --isolate-device: selected devices; the addresses of their paths and
     * of the empty execveat path in the loader's constant page (the filter
     * allows only those pointers). */
    uint32_t device_mask;
    uint64_t device_paths[CONFIG_ISOLATE_DEVICES];
    uint64_t empty_path;
    /* Loader image and the stub islands the loader created: guest memory
     * calls may not unmap, remap or reprotect them. */
    uint32_t protected_count;
    uint64_t protected_ranges[64][2];
    /* Supplementary groups (PRoot fake_id0); fake_group_count < 0: {0}. */
    int32_t fake_group_count;
    uint32_t fake_groups[32];
    /* uname overrides (PRoot -k for the release); empty keeps the kernel's. */
    char kernel_release[65];
    char kernel_sysname[65];
    /* --hostname: uname nodename; empty keeps the kernel's. */
    char hostname[65];
    /* --proc-cmdline: virtual /proc/cmdline string; empty falls back to host. */
    char proc_cmdline[256];
    /* Guarded build only (zero otherwise). */
    int32_t fd_state; /* Internal sealed exec handoff, -1 if absent. */
    /* --fd-capacity: FD records the runtime holds, when below the FD
     * numbers it holds (0: as many). For tests of the capacity boundary;
     * passed down the exec chain. */
    int32_t fd_capacity;
    /* Root then bind order, d/r/w; empty=legacy, guard selects partial enforcement. */
    char mount_access_observe[CONFIG_MAX_BINDS + 2];
    int32_t revalidate_file_fds; /* Re-derive regular-file origins, never trust snapshot tags. */
    int32_t allow_pipe_output; /* Newly created pipe2 write ends only. */
    int32_t allow_stdio_output; /* Revalidate pipe/TTY stdout+stderr, write/writev only. */
    int32_t allow_stream_input; /* Inherited pipe/socket/verified TTY reads in read guard mode. */
    int32_t allow_local_output; /* Writes to locally created sockets/eventfd/memfd. */
    /* R4: shared mount table FD (-1: mount calls are not emulated) and the
     * host directory for tmpfs mounts (empty: tmpfs is refused). */
    int32_t mount_table_fd;
    char mount_scratch[CONFIG_MAX_PATH];
    /* R5: owner database FD (-1: owners as fake_id0 reports them). */
    int32_t owner_db_fd;
    /* R6: the root's lower layers (union_view.h); 0: a plain root. */
    int32_t lower_count;
    char lower[CONFIG_MAX_LOWERS][CONFIG_MAX_PATH];
    /* R6 layer images (lazy_layer.h): lower i is the cache of this erofs
     * image (--lower-image after its --lower); empty: a plain directory. */
    char lower_image[CONFIG_MAX_LOWERS][CONFIG_MAX_PATH];
    /* Container networks (net_view.h): the container's address (host
     * order; 0: sockets as they are) and its peers file. */
    uint32_t net_addr;
    char net_peers[CONFIG_MAX_PATH];
    /* Generic userspace virtual network daemon socket (--net-sock PATH). */
    char net_sock[CONFIG_MAX_PATH];
    /* --pass-fd (guarded build). */
    int32_t passed_count;
    struct passed_fd passed[CONFIG_MAX_PASSED_FDS];
    /* --vdev GUEST:SOCK[:chr|binder]: generic userspace character-device proxies. */
    int32_t vdev_count;
    struct vdev_entry vdevs[CONFIG_MAX_VDEVS];
    /* --cap-add ALL|<hex>: additional Linux capability bits added to default bounding set. */
    uint64_t extra_caps;
    /* Generic container resource governance & signal guard:
     * cpu_mask: allowed host CPU bitmask (0 = unrestricted, up to 64 CPUs).
     * mem_limit_mb: virtual /proc/meminfo MemTotal cap in MiB (0 = unrestricted).
     * disk_limit_mb: virtual statfs/fstatfs filesystem capacity cap in MiB (0 = unrestricted).
     * nice_val: initial setpriority() nice value (0x7fffffff = unset).
     * sched_policy: initial sched_setscheduler() policy (-1 = unset).
     * trap_sigsys: install zero-stack SIGSYS(SYS_SECCOMP) -> -ENOSYS guard. */
    uint64_t cpu_mask;
    uint32_t mem_limit_mb;
    uint32_t disk_limit_mb;
    int32_t nice_val;
    int32_t sched_policy;
    int32_t trap_sigsys;
    int32_t emulate_bpf;
    /* --deny-memfd-prefix PREFIX: return -ENOSYS for memfd_create() names
     * matching PREFIX (lets runtimes fall back cleanly when host denies
     * MAP_SHARED|PROT_EXEC on memfd). */
    char deny_memfd_prefix[32];
    /* --no-inline-patch / --no-inline-patch-prefix DIR: keep mapped code pages
     * bit-for-bit unmodified (requiring --seccomp-backstop to intercept svc). */
    int32_t no_inline_patch_all;
    uint32_t no_inline_patch_count;
    char no_inline_patch_prefixes[8][CONFIG_MAX_PATH];
    /* Initial ELF segments copied into anonymous pages by the loader so
     * /proc/self/maps can report their guest paths and offsets accurately. */
    uint32_t init_vma_count;
    uint32_t _init_vma_pad;
    struct init_vma init_vmas[CONFIG_MAX_INIT_VMAS];
    char exec_interp_path[CONFIG_MAX_PATH];
    /* Packed NUL-separated initial guest environment (container mode, !child)
     * so /proc/self/environ matches the sanitized container env instead of
     * the host's execve environment. */
    uint64_t init_env_addr;
    uint64_t init_env_size;
    uint64_t guest_auxv_bytes;
    uint64_t guest_auxv[CONFIG_AUXV_PAIRS * 2];
} payload_config_t;

extern payload_config_t g_payload_config;

/* Binary child-loader exec handoff transferred across execve via memfd. */
typedef struct svbox_handoff {
    uint64_t magic;
    uint32_t version;
    uint32_t size;
    payload_config_t cfg;
    char exec_target[CONFIG_MAX_PATH];
    char exec_path[CONFIG_MAX_PATH];
    char exec_exe[CONFIG_MAX_PATH];
    char exec_interp[CONFIG_MAX_PATH];
    char exec_name[CONFIG_MAX_PATH];
    int32_t exec_fd;
    int32_t exec_interp_fd;
} svbox_handoff_t;

#endif /* PAYLOAD_CONFIG_H */
