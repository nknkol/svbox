/* SPDX-License-Identifier: MIT */
/* Generic userspace virtual character-device proxy wire protocol (AF_UNIX
 * SOCK_STREAM + SCM_RIGHTS), shared between svbox payload and external device
 * daemons (e.g. svbox-binderd, virtual evdev, etc.). */
#ifndef SVBOX_VDEV_PROTO_H
#define SVBOX_VDEV_PROTO_H

#include <stdint.h>

#define VDEV_PROTO_MAGIC   0x56444556u /* "VDEV" */
#define VDEV_PROTO_VERSION 1u

#define VDEV_MAX_FDS       16
#define VDEV_MAX_PAYLOAD   (512u * 1024u)

/* Device classes (matches config.h VDEV_TYPE_*). */
#define VDEV_TYPE_CHR      0
#define VDEV_TYPE_BINDER   1
#define VDEV_TYPE_TUN      2

/* Wire message opcodes. */
enum vdev_op {
    VDEV_OP_OPEN           = 1, /* -> open device, returns notify channel + memfd */
    VDEV_OP_ATTACH_THREAD  = 2, /* -> attach per-thread RPC socket to proc_id */
    VDEV_OP_MMAP           = 3, /* -> inform daemon of guest_base / map len */
    VDEV_OP_IOCTL          = 4, /* -> generic _IOC_DIR/_IOC_SIZE ioctl */
    VDEV_OP_BINDER_WR      = 5, /* -> Binder BINDER_WRITE_READ packet */
    VDEV_OP_BINDER_CTL     = 6, /* -> Binder control ioctl (SET_CONTEXT_MGR, MAX_THREADS, THREAD_EXIT) */
    VDEV_OP_CLOSE          = 7, /* -> device closed */
};

/* Every message on the stream is a fixed 32-byte header followed by `payload_len`
 * bytes. Optional kernel file descriptors (`fd_count`) are sent via SCM_RIGHTS
 * attached to the header's sendmsg() call. */
struct vdev_hdr {
    uint32_t magic;
    uint32_t op;
    int32_t  status;       /* 0 or -errno on reply */
    uint32_t payload_len;
    uint32_t proc_id;
    uint32_t fd_count;
    uint64_t arg0;
    uint64_t arg1;
};

struct vdev_open_req {
    uint32_t pid;
    uint32_t tid;
    uint32_t uid;
    uint32_t gid;
    uint32_t vdev_type;
    uint32_t flags;
    char     guest_path[128];
};

struct vdev_open_rep {
    uint32_t proc_id;
    uint32_t major;
    uint32_t minor;
    uint32_t memfd_size;   /* 0 if no backing memfd */
};

struct vdev_attach_req {
    uint32_t proc_id;
    uint32_t pid;
    uint32_t tid;
    uint32_t reserved;
};

struct vdev_mmap_req {
    uint64_t guest_base;
    uint64_t length;
};

struct vdev_ioctl_req {
    uint64_t cmd;
    uint64_t arg;          /* raw arg when size == 0 */
    uint32_t in_len;
    uint32_t out_len;
};

/* ---- 64-bit Linux Android Binder ABI (AArch64, BINDER_CURRENT_PROTOCOL_VERSION = 8) ---- */
#define SV_BINDER_PROTOCOL_VERSION        8
#define SV_BINDER_WRITE_READ              0xc0306201u
#define SV_BINDER_SET_MAX_THREADS         0x40046205u
#define SV_BINDER_SET_CONTEXT_MGR         0x40046207u
#define SV_BINDER_THREAD_EXIT             0x40046208u
#define SV_BINDER_VERSION                 0xc0046209u
#define SV_BINDER_SET_CONTEXT_MGR_EXT     0x4018620du
#define SV_BINDER_ENABLE_ONEWAY_SPAM_DET  0x40046210u

#define SV_BC_TRANSACTION                 0x40406300u
#define SV_BC_REPLY                       0x40406301u
#define SV_BC_FREE_BUFFER                 0x40086303u
#define SV_BC_INCREFS                     0x40046304u
#define SV_BC_ACQUIRE                     0x40046305u
#define SV_BC_RELEASE                     0x40046306u
#define SV_BC_DECREFS                     0x40046307u
#define SV_BC_INCREFS_DONE                0x40106308u
#define SV_BC_ACQUIRE_DONE                0x40106309u
#define SV_BC_REGISTER_LOOPER             0x0000630bu
#define SV_BC_ENTER_LOOPER                0x0000630cu
#define SV_BC_EXIT_LOOPER                 0x0000630du
#define SV_BC_REQUEST_DEATH_NOTIFICATION  0x400c630eu
#define SV_BC_CLEAR_DEATH_NOTIFICATION    0x400c630fu
#define SV_BC_DEAD_BINDER_DONE            0x40086310u
#define SV_BC_TRANSACTION_SG              0x40486311u
#define SV_BC_REPLY_SG                    0x40486312u

#define SV_BR_ERROR                       0x80047200u
#define SV_BR_OK                          0x00007201u
#define SV_BR_TRANSACTION                 0x80407202u
#define SV_BR_REPLY                       0x80407203u
#define SV_BR_DEAD_REPLY                  0x00007205u
#define SV_BR_TRANSACTION_COMPLETE        0x00007206u
#define SV_BR_INCREFS                     0x80107207u
#define SV_BR_ACQUIRE                     0x80107208u
#define SV_BR_RELEASE                     0x80107209u
#define SV_BR_DECREFS                     0x8010720au
#define SV_BR_NOOP                        0x0000720cu
#define SV_BR_SPAWN_LOOPER                0x0000720du
#define SV_BR_DEAD_BINDER                 0x8008720fu
#define SV_BR_CLEAR_DEATH_NOTIFICATION_DONE 0x80087210u
#define SV_BR_FAILED_REPLY                0x00007211u

#define SV_BINDER_TYPE_BINDER             0x73622a85u
#define SV_BINDER_TYPE_WEAK_BINDER        0x77622a85u
#define SV_BINDER_TYPE_HANDLE             0x73682a85u
#define SV_BINDER_TYPE_WEAK_HANDLE        0x77682a85u
#define SV_BINDER_TYPE_FD                 0x66642a85u
#define SV_BINDER_TYPE_FDA                0x66646185u
#define SV_BINDER_TYPE_PTR                0x70742a85u

#define SV_TF_ONE_WAY                     0x01u
#define SV_TF_ACCEPT_FDS                  0x10u

struct sv_binder_write_read {
    uint64_t write_size;
    uint64_t write_consumed;
    uint64_t write_buffer;
    uint64_t read_size;
    uint64_t read_consumed;
    uint64_t read_buffer;
};

struct sv_binder_transaction_data {
    union {
        uint32_t handle;
        uint64_t ptr;
    } target;
    uint64_t cookie;
    uint32_t code;
    uint32_t flags;
    int32_t  sender_pid;
    uint32_t sender_euid;
    uint64_t data_size;
    uint64_t offsets_size;
    union {
        struct {
            uint64_t buffer;
            uint64_t offsets;
        } ptr;
        uint8_t buf[8];
    } data;
};

struct sv_binder_transaction_data_sg {
    struct sv_binder_transaction_data txn;
    uint64_t buffers_size;
};

struct sv_flat_binder_object {
    uint32_t type;
    uint32_t flags;
    union {
        uint64_t binder;
        uint32_t handle;
    };
    uint64_t cookie;
};

struct sv_binder_fd_object {
    uint32_t type;
    uint32_t pad_flags;
    union {
        uint64_t pad_binder;
        uint32_t fd;
    };
    uint64_t cookie;
};

struct sv_binder_ptr_cookie {
    uint64_t ptr;
    uint64_t cookie;
};

struct sv_binder_handle_cookie {
    uint32_t handle;
    uint64_t cookie;
} __attribute__((packed));

#define SV_BINDER_BUFFER_FLAG_HAS_PARENT 0x01u

struct sv_binder_buffer_object {
    uint32_t type;
    uint32_t flags;
    uint64_t buffer;
    uint64_t length;
    uint64_t parent;
    uint64_t parent_offset;
};

struct sv_binder_fd_array_object {
    uint32_t type;
    uint32_t pad;
    uint64_t num_fds;
    uint64_t parent;
    uint64_t parent_offset;
};

/* Packed BINDER_WRITE_READ request over VDEV_OP_BINDER_WR:
 *   struct vdev_binder_wr_req
 *   followed by packed write stream:
 *     for normal BC_* commands: [u32 cmd][raw arg bytes]
 *     for BC_TRANSACTION / BC_REPLY / BC_TRANSACTION_SG / BC_REPLY_SG:
 *       [u32 cmd][64B or 72B txn][data_size bytes][offsets_size bytes]
 *       (any BINDER_TYPE_FD objects have their fd replaced by 0-based index
 *        into the SCM_RIGHTS fd array attached to the message!)
 * Reply payload:
 *   struct vdev_binder_wr_rep
 *   followed by `read_bytes` of raw BR_* stream ready to copy into guest
 *   read_buffer (with any BINDER_TYPE_FD objects in the shared memfd already
 *   patched by the payload upon receiving SCM_RIGHTS FDs from daemon).
 */
struct vdev_binder_wr_req {
    uint32_t tid;
    uint32_t uid;
    uint32_t pid;
    uint32_t read_cap;       /* guest bwr.read_size - bwr.read_consumed */
    uint32_t packed_len;     /* bytes of packed BC_* stream following this struct */
    uint32_t raw_write_size; /* guest write_size - write_consumed */
};

struct vdev_binder_wr_rep {
    uint32_t write_consumed;
    uint32_t read_bytes;
    uint32_t fd_patch_count; /* count of uint64_t memfd offsets where received FDs go */
    uint32_t reserved;
    /* Followed by:
     *   uint64_t fd_patch_offsets[fd_patch_count] (byte offset inside guest mmap of binder_fd_object.fd)
     *   uint8_t  br_stream[read_bytes]
     */
};

#endif /* SVBOX_VDEV_PROTO_H */
