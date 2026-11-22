/* SPDX-License-Identifier: MIT */
/* Generic userspace virtual character-device proxy (--vdev GUEST:SOCK[:TYPE]).
 *
 * When a guest opens a configured virtual device path, svbox connects to the
 * external device daemon over AF_UNIX SOCK_STREAM and returns that live socket
 * FD to the guest so poll/epoll works natively in the kernel. For Binder
 * devices, per-thread RPC channels avoid contention between looper threads and
 * outgoing calls, while a shared memfd serves zero-copy transaction buffers. */
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include "syscall_nums.h"
#include "config.h"
#include "fake_ids.h"
#include "vdev.h"
#include "vdev_proto.h"

extern long raw_syscall(long number, long a1, long a2, long a3, long a4, long a5, long a6);

#define AF_UNIX_         1
#define SOCK_STREAM_     1
#define SOCK_CLOEXEC_    02000000
#define SOL_SOCKET_      1
#define SCM_RIGHTS_      1
#define MSG_DONTWAIT_    0x40
#define MSG_NOSIGNAL_    0x4000
#define MSG_CMSG_CLOEXEC_ 0x40000000
#define PROT_READ_       1
#define PROT_WRITE_      2
#define MAP_SHARED_      1
#define MAP_PRIVATE_     2
#define MAP_ANONYMOUS_   0x20

struct vdev_sockaddr_un {
    uint16_t sun_family;
    char sun_path[108];
};

struct vdev_iovec {
    void *iov_base;
    size_t iov_len;
};

struct vdev_msghdr {
    void *msg_name;
    uint32_t msg_namelen;
    uint32_t _pad0;
    struct vdev_iovec *msg_iov;
    size_t msg_iovlen;
    void *msg_control;
    size_t msg_controllen;
    int msg_flags;
    int _pad1;
};

struct vdev_cmsghdr {
    size_t cmsg_len;
    int cmsg_level;
    int cmsg_type;
};

#define VDEV_ALIGN8(x) (((x) + 7ul) & ~7ul)
#define VDEV_CMSG_LEN(n) (VDEV_ALIGN8(sizeof(struct vdev_cmsghdr)) + (n))
#define VDEV_CMSG_SPACE(n) (VDEV_ALIGN8(sizeof(struct vdev_cmsghdr)) + VDEV_ALIGN8(n))

#define VDEV_MAX_OPEN 16
#define VDEV_MAX_THREADS 64

struct vdev_thread_chan {
    int32_t tid;
    int32_t pid;
    int32_t rpc_fd;
    int32_t used;
};

struct vdev_open_slot {
    int32_t active;
    int32_t vdev_idx;
    int32_t fd;          /* guest-visible notify socket FD */
    int32_t memfd;       /* backing shared memfd from daemon, or -1 */
    uint32_t proc_id;
    uint32_t major;
    uint32_t minor;
    uint32_t memfd_size;
    int32_t owner_pid;
    uint64_t map_base;
    uint64_t map_len;
    struct vdev_thread_chan threads[VDEV_MAX_THREADS];
};

static struct vdev_open_slot g_open_slots[VDEV_MAX_OPEN];
static volatile int g_vdev_lock = 0;

static void vdev_lock(void)
{
    while (__sync_lock_test_and_set(&g_vdev_lock, 1)) {
        __asm__ volatile("yield" ::: "memory");
    }
}

static void vdev_unlock(void)
{
    __sync_lock_release(&g_vdev_lock);
}

static long connect_unix_sock(const char *path, int cloexec)
{
    long fd = raw_syscall(__NR_socket, AF_UNIX_,
                          SOCK_STREAM_ | (cloexec ? SOCK_CLOEXEC_ : 0),
                          0, 0, 0, 0);
    if (fd < 0)
        return fd;
    struct vdev_sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX_;
    size_t len = strlen(path);
    if (len >= sizeof(sa.sun_path)) {
        raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
        return -ENAMETOOLONG;
    }
    memcpy(sa.sun_path, path, len + 1);
    long rc = raw_syscall(__NR_connect, fd, (long)&sa,
                          (long)(sizeof(sa.sun_family) + len + 1), 0, 0, 0);
    if (rc < 0) {
        raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
        return rc;
    }
    return fd;
}

static long send_all(int fd, const void *buf, size_t len, const int *fds, uint32_t fd_count)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;
    while (sent < len) {
        struct vdev_iovec iov = { (void *)(p + sent), len - sent };
        struct vdev_msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        unsigned char cbuf[VDEV_CMSG_SPACE(sizeof(int) * VDEV_MAX_FDS)];
        if (sent == 0 && fd_count > 0) {
            if (fd_count > VDEV_MAX_FDS)
                return -EINVAL;
            memset(cbuf, 0, sizeof(cbuf));
            msg.msg_control = cbuf;
            msg.msg_controllen = VDEV_CMSG_SPACE(sizeof(int) * fd_count);
            struct vdev_cmsghdr *c = (struct vdev_cmsghdr *)cbuf;
            c->cmsg_level = SOL_SOCKET_;
            c->cmsg_type = SCM_RIGHTS_;
            c->cmsg_len = VDEV_CMSG_LEN(sizeof(int) * fd_count);
            memcpy(cbuf + VDEV_ALIGN8(sizeof(struct vdev_cmsghdr)), fds, sizeof(int) * fd_count);
        }
        long n = raw_syscall(__NR_sendmsg, fd, (long)&msg, MSG_NOSIGNAL_, 0, 0, 0);
        if (n == -EINTR)
            continue;
        if (n <= 0)
            return n < 0 ? n : -EPIPE;
        sent += (size_t)n;
    }
    return 0;
}

static long recv_all(int fd, void *buf, size_t len, int *out_fds, uint32_t max_fds, uint32_t *got_fds)
{
    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;
    if (got_fds)
        *got_fds = 0;
    while (got < len) {
        struct vdev_iovec iov = { p + got, len - got };
        struct vdev_msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        unsigned char cbuf[VDEV_CMSG_SPACE(sizeof(int) * VDEV_MAX_FDS)];
        if (out_fds && max_fds > 0) {
            memset(cbuf, 0, sizeof(cbuf));
            msg.msg_control = cbuf;
            msg.msg_controllen = sizeof(cbuf);
        }
        long n = raw_syscall(__NR_recvmsg, fd, (long)&msg, MSG_CMSG_CLOEXEC_, 0, 0, 0);
        if (n == -EINTR)
            continue;
        if (n <= 0)
            return n < 0 ? n : -EPIPE;
        if (out_fds && max_fds > 0 && msg.msg_controllen >= sizeof(struct vdev_cmsghdr)) {
            size_t off = 0;
            while (off + sizeof(struct vdev_cmsghdr) <= msg.msg_controllen) {
                struct vdev_cmsghdr *c = (struct vdev_cmsghdr *)(cbuf + off);
                if (c->cmsg_len < sizeof(struct vdev_cmsghdr) || off + c->cmsg_len > msg.msg_controllen)
                    break;
                if (c->cmsg_level == SOL_SOCKET_ && c->cmsg_type == SCM_RIGHTS_) {
                    size_t data_off = VDEV_ALIGN8(sizeof(struct vdev_cmsghdr));
                    size_t nf = (c->cmsg_len - data_off) / sizeof(int);
                    const int *rfds = (const int *)(cbuf + off + data_off);
                    for (size_t i = 0; i < nf; i++) {
                        if (got_fds && *got_fds < max_fds)
                            out_fds[(*got_fds)++] = rfds[i];
                        else
                            raw_syscall(__NR_close, rfds[i], 0, 0, 0, 0, 0);
                    }
                }
                off += VDEV_ALIGN8(c->cmsg_len);
            }
        }
        got += (size_t)n;
    }
    return 0;
}

static long send_msg(int fd, uint32_t op, uint32_t proc_id, uint64_t arg0, uint64_t arg1,
                     const void *payload, uint32_t payload_len, const int *fds, uint32_t fd_count)
{
    struct vdev_hdr hdr;
    hdr.magic = VDEV_PROTO_MAGIC;
    hdr.op = op;
    hdr.status = 0;
    hdr.payload_len = payload_len;
    hdr.proc_id = proc_id;
    hdr.fd_count = fd_count;
    hdr.arg0 = arg0;
    hdr.arg1 = arg1;
    long rc = send_all(fd, &hdr, sizeof(hdr), fds, fd_count);
    if (rc < 0)
        return rc;
    if (payload_len > 0)
        rc = send_all(fd, payload, payload_len, NULL, 0);
    return rc;
}

static long recv_msg(int fd, struct vdev_hdr *hdr, void *payload, uint32_t cap,
                     int *out_fds, uint32_t max_fds, uint32_t *got_fds)
{
    long rc = recv_all(fd, hdr, sizeof(*hdr), out_fds, max_fds, got_fds);
    if (rc < 0)
        return rc;
    if (hdr->magic != VDEV_PROTO_MAGIC || hdr->payload_len > cap)
        return -EPROTO;
    if (hdr->payload_len > 0) {
        rc = recv_all(fd, payload, hdr->payload_len, NULL, 0, NULL);
        if (rc < 0)
            return rc;
    }
    return 0;
}

static struct vdev_open_slot *find_slot_by_fd(int fd)
{
    if (fd < 0)
        return NULL;
    int32_t pid = (int32_t)raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
    for (int i = 0; i < VDEV_MAX_OPEN; i++) {
        if (g_open_slots[i].active && g_open_slots[i].fd == fd &&
            g_open_slots[i].owner_pid == pid)
            return &g_open_slots[i];
    }
    return NULL;
}

static int get_thread_rpc_fd(struct vdev_open_slot *slot)
{
    int32_t pid = (int32_t)raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
    int32_t tid = (int32_t)raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
    vdev_lock();
    for (int i = 0; i < VDEV_MAX_THREADS; i++) {
        if (slot->threads[i].used && slot->threads[i].tid == tid && slot->threads[i].pid == pid) {
            int rfd = slot->threads[i].rpc_fd;
            vdev_unlock();
            return rfd;
        }
    }
    vdev_unlock();

    const struct vdev_entry *ve = &g_payload_config.vdevs[slot->vdev_idx];
    long rfd = connect_unix_sock(ve->sock, 1);
    if (rfd < 0)
        return (int)rfd;

    struct vdev_attach_req req;
    req.proc_id = slot->proc_id;
    req.pid = (uint32_t)pid;
    req.tid = (uint32_t)tid;
    req.reserved = 0;
    long rc = send_msg((int)rfd, VDEV_OP_ATTACH_THREAD, slot->proc_id, 0, 0,
                       &req, sizeof(req), NULL, 0);
    struct vdev_hdr rep;
    if (rc == 0)
        rc = recv_msg((int)rfd, &rep, NULL, 0, NULL, 0, NULL);
    if (rc < 0 || rep.status < 0) {
        raw_syscall(__NR_close, rfd, 0, 0, 0, 0, 0);
        return rc < 0 ? (int)rc : rep.status;
    }

    vdev_lock();
    for (int i = 0; i < VDEV_MAX_THREADS; i++) {
        if (!slot->threads[i].used || slot->threads[i].pid != pid) {
            slot->threads[i].used = 1;
            slot->threads[i].pid = pid;
            slot->threads[i].tid = tid;
            slot->threads[i].rpc_fd = (int32_t)rfd;
            vdev_unlock();
            return (int)rfd;
        }
    }
    vdev_unlock();
    return (int)rfd;
}

static void close_slot(struct vdev_open_slot *slot)
{
    vdev_lock();
    if (!slot->active) {
        vdev_unlock();
        return;
    }
    int memfd = slot->memfd;
    slot->memfd = -1;
    for (int i = 0; i < VDEV_MAX_THREADS; i++) {
        if (slot->threads[i].used && slot->threads[i].rpc_fd >= 0) {
            raw_syscall(__NR_close, slot->threads[i].rpc_fd, 0, 0, 0, 0, 0);
            slot->threads[i].used = 0;
            slot->threads[i].rpc_fd = -1;
        }
    }
    slot->active = 0;
    slot->fd = -1;
    vdev_unlock();
    if (memfd >= 0)
        raw_syscall(__NR_close, memfd, 0, 0, 0, 0, 0);
}

int vdev_match_path(const char *guest_path)
{
    if (!guest_path || g_payload_config.vdev_count <= 0)
        return -1;
    for (int i = 0; i < g_payload_config.vdev_count; i++) {
        if (strcmp(guest_path, g_payload_config.vdevs[i].guest) == 0)
            return i;
    }
    return -1;
}

static void fill_chr_stat(struct stat *st, uint32_t major, uint32_t minor)
{
    memset(st, 0, sizeof(*st));
    st->st_mode = 0020666; /* S_IFCHR | 0666 */
    st->st_nlink = 1;
    st->st_rdev = ((uint64_t)major << 8) | minor;
    st->st_blksize = 4096;
}

long vdev_path_call(long number, long a[6], int vdev_idx)
{
    if (vdev_idx < 0 || vdev_idx >= g_payload_config.vdev_count)
        return -ENOENT;
    const struct vdev_entry *ve = &g_payload_config.vdevs[vdev_idx];
    uint32_t major = 10, minor = 250u + (uint32_t)vdev_idx;

    switch (number) {
    case __NR_openat: {
        if ((a[2] & O_CREAT) && (a[2] & O_EXCL))
            return -EEXIST;
        if (a[2] & O_DIRECTORY)
            return -ENOTDIR;
        int cloexec = (a[2] & O_CLOEXEC) ? 1 : 0;
        long fd = connect_unix_sock(ve->sock, cloexec);
        if (fd < 0)
            return fd;

        struct vdev_open_req req;
        memset(&req, 0, sizeof(req));
        req.pid = (uint32_t)raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
        req.tid = (uint32_t)raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
        req.uid = fake_ids_effective(0);
        req.gid = fake_ids_effective(1);
        req.vdev_type = (uint32_t)ve->type;
        req.flags = (uint32_t)a[2];
        size_t glen = strlen(ve->guest);
        if (glen >= sizeof(req.guest_path))
            glen = sizeof(req.guest_path) - 1;
        memcpy(req.guest_path, ve->guest, glen);

        long rc = send_msg((int)fd, VDEV_OP_OPEN, 0, 0, 0, &req, sizeof(req), NULL, 0);
        struct vdev_hdr hdr;
        struct vdev_open_rep rep;
        memset(&rep, 0, sizeof(rep));
        int rfds[2] = { -1, -1 };
        uint32_t nfds = 0;
        if (rc == 0)
            rc = recv_msg((int)fd, &hdr, &rep, sizeof(rep), rfds, 2, &nfds);
        if (rc < 0 || hdr.status < 0) {
            for (uint32_t i = 0; i < nfds; i++)
                raw_syscall(__NR_close, rfds[i], 0, 0, 0, 0, 0);
            raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
            return rc < 0 ? rc : hdr.status;
        }

        vdev_lock();
        int idx = -1;
        int32_t cur_pid = (int32_t)req.pid;
        for (int i = 0; i < VDEV_MAX_OPEN; i++) {
            if (!g_open_slots[i].active || g_open_slots[i].owner_pid != cur_pid) {
                idx = i;
                break;
            }
        }
        if (idx < 0) {
            vdev_unlock();
            for (uint32_t i = 0; i < nfds; i++)
                raw_syscall(__NR_close, rfds[i], 0, 0, 0, 0, 0);
            raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
            return -EMFILE;
        }
        struct vdev_open_slot *s = &g_open_slots[idx];
        memset(s, 0, sizeof(*s));
        s->active = 1;
        s->vdev_idx = vdev_idx;
        s->fd = (int32_t)fd;
        s->memfd = nfds > 0 ? rfds[0] : -1;
        for (uint32_t i = 1; i < nfds; i++)
            raw_syscall(__NR_close, rfds[i], 0, 0, 0, 0, 0);
        s->proc_id = rep.proc_id;
        s->major = rep.major ? rep.major : major;
        s->minor = rep.minor ? rep.minor : minor;
        s->memfd_size = rep.memfd_size;
        s->owner_pid = cur_pid;
        vdev_unlock();
        return fd;
    }
    case __NR_newfstatat: {
        struct stat st;
        fill_chr_stat(&st, major, minor);
        if (!a[2])
            return -EFAULT;
        memcpy((void *)a[2], &st, sizeof(st));
        return 0;
    }
    case __NR_statx: {
        unsigned char sx[256];
        memset(sx, 0, sizeof(sx));
        uint32_t mask = 0x7ff, blksize = 4096, nlink = 1;
        uint16_t mode = 0020666;
        memcpy(sx, &mask, 4);
        memcpy(sx + 4, &blksize, 4);
        memcpy(sx + 16, &nlink, 4);
        memcpy(sx + 28, &mode, 2);
        memcpy(sx + 128, &major, 4);
        memcpy(sx + 132, &minor, 4);
        if (!a[4])
            return -EFAULT;
        memcpy((void *)a[4], sx, sizeof(sx));
        return 0;
    }
    case __NR_faccessat:
    case __NR_faccessat2:
        if (a[2] & 1 /* X_OK */)
            return -EACCES;
        return 0;
    default:
        return -EPERM;
    }
}

/* ---- Binder BINDER_WRITE_READ marshaler ---- */
static uint32_t binder_bc_arg_size(uint32_t cmd)
{
    return (cmd >> 16) & 0x3fffu;
}

static long binder_write_read(struct vdev_open_slot *slot, unsigned long arg)
{
    if (!arg)
        return -EFAULT;
    struct sv_binder_write_read bwr;
    memcpy(&bwr, (const void *)arg, sizeof(bwr));

    int rpc_fd = get_thread_rpc_fd(slot);
    if (rpc_fd < 0)
        return rpc_fd;

    /* Drain level-triggered epoll wakeup bytes only when actually reading. */
    if (bwr.read_size > 0) {
        char drain[64];
        while (raw_syscall(__NR_recvfrom, slot->fd, (long)drain, sizeof(drain),
                           MSG_DONTWAIT_, 0, 0) > 0) {
        }
    }

    size_t buf_cap = 262144;
    long scratch_addr = raw_syscall(__NR_mmap, 0, (long)buf_cap,
                                    PROT_READ_ | PROT_WRITE_,
                                    MAP_PRIVATE_ | MAP_ANONYMOUS_, -1, 0);
    if (scratch_addr < 0)
        return scratch_addr;
    uint8_t *scratch = (uint8_t *)scratch_addr;

    struct vdev_binder_wr_req *wreq = (struct vdev_binder_wr_req *)scratch;
    memset(wreq, 0, sizeof(*wreq));
    wreq->pid = (uint32_t)raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
    wreq->tid = (uint32_t)raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
    wreq->uid = g_payload_config.fake_ids[1];
    uint64_t rcap = bwr.read_size > bwr.read_consumed ? bwr.read_size - bwr.read_consumed : 0;
    if (rcap > 65536)
        rcap = 65536;
    wreq->read_cap = (uint32_t)rcap;

    uint8_t *dst = scratch + sizeof(*wreq);
    size_t dst_cap = buf_cap - sizeof(*wreq);
    size_t dst_off = 0;

    int send_fds[VDEV_MAX_FDS];
    uint32_t send_fd_count = 0;

    uint64_t wrem = bwr.write_size > bwr.write_consumed ? bwr.write_size - bwr.write_consumed : 0;
    wreq->raw_write_size = (uint32_t)wrem;
    const uint8_t *src = (const uint8_t *)(uintptr_t)(bwr.write_buffer + bwr.write_consumed);
    size_t soff = 0;
    long rc = 0;

    while (soff + 4 <= wrem) {
        uint32_t cmd;
        memcpy(&cmd, src + soff, 4);
        uint32_t asz = binder_bc_arg_size(cmd);
        if (soff + 4 + asz > wrem) {
            rc = -EINVAL;
            break;
        }
        if (cmd == SV_BC_TRANSACTION || cmd == SV_BC_REPLY ||
            cmd == SV_BC_TRANSACTION_SG || cmd == SV_BC_REPLY_SG) {
            struct sv_binder_transaction_data txn;
            memcpy(&txn, src + soff + 4, sizeof(txn));
            size_t total = 4 + asz + (size_t)txn.data_size + (size_t)txn.offsets_size;
            if (dst_off + total > dst_cap) {
                rc = -ENOMEM;
                break;
            }
            memcpy(dst + dst_off, src + soff, 4 + asz);
            uint8_t *tdata = dst + dst_off + 4 + asz;
            uint8_t *toffs = tdata + txn.data_size;
            if (txn.data_size > 0 && txn.data.ptr.buffer)
                memcpy(tdata, (const void *)(uintptr_t)txn.data.ptr.buffer, (size_t)txn.data_size);
            if (txn.offsets_size > 0 && txn.data.ptr.offsets)
                memcpy(toffs, (const void *)(uintptr_t)txn.data.ptr.offsets, (size_t)txn.offsets_size);

            /* Extract any BINDER_TYPE_FD / BINDER_TYPE_FDA objects into SCM_RIGHTS
             * array, and append BINDER_TYPE_PTR scatter-gather payloads right after offsets. */
            size_t sg_extra = 0;
            size_t n_offs = (size_t)txn.offsets_size / sizeof(uint64_t);
            uint8_t *sg_packed_ptrs[64];
            size_t sg_packed_lens[64];
            memset(sg_packed_ptrs, 0, sizeof(sg_packed_ptrs));
            memset(sg_packed_lens, 0, sizeof(sg_packed_lens));
            for (size_t k = 0; k < n_offs; k++) {
                uint64_t o;
                memcpy(&o, toffs + k * sizeof(uint64_t), sizeof(uint64_t));
                if (o + 4 <= txn.data_size) {
                    uint32_t otype;
                    memcpy(&otype, tdata + o, 4);
                    if (otype == SV_BINDER_TYPE_FD && o + sizeof(struct sv_binder_fd_object) <= txn.data_size) {
                        struct sv_binder_fd_object fobj;
                        memcpy(&fobj, tdata + o, sizeof(fobj));
                        if (send_fd_count >= VDEV_MAX_FDS) {
                            rc = -EMFILE;
                            break;
                        }
                        uint32_t fidx = send_fd_count;
                        send_fds[send_fd_count++] = (int)fobj.fd;
                        fobj.fd = fidx;
                        memcpy(tdata + o, &fobj, sizeof(fobj));
                    } else if (otype == SV_BINDER_TYPE_PTR && o + sizeof(struct sv_binder_buffer_object) <= txn.data_size) {
                        struct sv_binder_buffer_object bbo;
                        memcpy(&bbo, tdata + o, sizeof(bbo));
                        if (dst_off + total + sg_extra + bbo.length > dst_cap) {
                            rc = -ENOMEM;
                            break;
                        }
                        uint8_t *sg_dst = dst + dst_off + total + sg_extra;
                        if (bbo.length > 0 && bbo.buffer)
                            memcpy(sg_dst, (const void *)(uintptr_t)bbo.buffer, (size_t)bbo.length);
                        if (k < 64) {
                            sg_packed_ptrs[k] = sg_dst;
                            sg_packed_lens[k] = (size_t)bbo.length;
                        }
                        sg_extra += (size_t)bbo.length;
                    } else if (otype == SV_BINDER_TYPE_FDA && o + sizeof(struct sv_binder_fd_array_object) <= txn.data_size) {
                        struct sv_binder_fd_array_object fda;
                        memcpy(&fda, tdata + o, sizeof(fda));
                        if (fda.parent < k && fda.parent < 64 && sg_packed_ptrs[fda.parent]) {
                            for (uint64_t j = 0; j < fda.num_fds; j++) {
                                size_t foff = (size_t)fda.parent_offset + (size_t)j * 4;
                                if (foff + 4 > sg_packed_lens[fda.parent])
                                    break;
                                int32_t raw_fd = -1;
                                memcpy(&raw_fd, sg_packed_ptrs[fda.parent] + foff, 4);
                                int32_t fidx = -1;
                                if (raw_fd >= 0) {
                                    if (send_fd_count >= VDEV_MAX_FDS) {
                                        rc = -EMFILE;
                                        break;
                                    }
                                    fidx = (int32_t)send_fd_count;
                                    send_fds[send_fd_count++] = raw_fd;
                                }
                                memcpy(sg_packed_ptrs[fda.parent] + foff, &fidx, 4);
                            }
                            if (rc < 0)
                                break;
                        }
                    }
                }
            }
            if (rc < 0)
                break;
            dst_off += total + sg_extra;
        } else {
            if (dst_off + 4 + asz > dst_cap) {
                rc = -ENOMEM;
                break;
            }
            memcpy(dst + dst_off, src + soff, 4 + asz);
            dst_off += 4 + asz;
        }
        soff += 4 + asz;
    }

    if (rc == 0) {
        wreq->packed_len = (uint32_t)dst_off;
        rc = send_msg(rpc_fd, VDEV_OP_BINDER_WR, slot->proc_id, 0, 0,
                      scratch, (uint32_t)(sizeof(*wreq) + dst_off),
                      send_fds, send_fd_count);
    }

    struct vdev_hdr rhdr;
    int recv_fds[VDEV_MAX_FDS];
    uint32_t recv_fd_count = 0;
    if (rc == 0)
        rc = recv_msg(rpc_fd, &rhdr, scratch, (uint32_t)buf_cap,
                      recv_fds, VDEV_MAX_FDS, &recv_fd_count);

    if (rc == 0 && rhdr.status < 0)
        rc = rhdr.status;

    if (rc == 0 && rhdr.payload_len >= sizeof(struct vdev_binder_wr_rep)) {
        struct vdev_binder_wr_rep wrep;
        memcpy(&wrep, scratch, sizeof(wrep));
        size_t patch_bytes = (size_t)wrep.fd_patch_count * sizeof(uint64_t);
        if (sizeof(wrep) + patch_bytes + wrep.read_bytes <= rhdr.payload_len) {
            /* Patch received FDs into guest's shared memfd mapping if any. */
            if (wrep.fd_patch_count > 0 && slot->map_base && slot->map_len) {
                /* Daemon wrote the memfd; guest mapping is PROT_READ unless
                 * daemon passed memfd offsets that we patch via pwrite on slot->memfd. */
                const uint8_t *poffs = scratch + sizeof(wrep);
                for (uint32_t i = 0; i < wrep.fd_patch_count && i < recv_fd_count; i++) {
                    uint64_t fd_off;
                    memcpy(&fd_off, poffs + i * sizeof(uint64_t), sizeof(uint64_t));
                    if (slot->memfd >= 0 && fd_off + 4 <= slot->map_len) {
                        uint32_t new_fd = (uint32_t)recv_fds[i];
                        raw_syscall(__NR_pwrite64, slot->memfd, (long)&new_fd, 4, (long)fd_off, 0, 0);
                    }
                }
            }
            const uint8_t *br = scratch + sizeof(wrep) + patch_bytes;
            if (wrep.read_bytes > 0 && bwr.read_buffer) {
                size_t copy_n = wrep.read_bytes;
                if (copy_n > rcap)
                    copy_n = (size_t)rcap;
                memcpy((void *)(uintptr_t)(bwr.read_buffer + bwr.read_consumed), br, copy_n);
                bwr.read_consumed += copy_n;
            }
            bwr.write_consumed += wrep.write_consumed;
            memcpy((void *)arg, &bwr, sizeof(bwr));
        } else {
            rc = -EPROTO;
        }
    }

    if (rc < 0) {
        for (uint32_t i = 0; i < recv_fd_count; i++)
            raw_syscall(__NR_close, recv_fds[i], 0, 0, 0, 0, 0);
    }
    raw_syscall(__NR_munmap, scratch_addr, (long)buf_cap, 0, 0, 0, 0);
    return rc;
}

static long binder_ioctl(struct vdev_open_slot *slot, unsigned long cmd, unsigned long arg)
{
    uint32_t c32 = (uint32_t)cmd;
    if (c32 == SV_BINDER_VERSION) {
        int32_t ver = SV_BINDER_PROTOCOL_VERSION;
        if (!arg)
            return -EFAULT;
        memcpy((void *)arg, &ver, sizeof(ver));
        return 0;
    }
    if (c32 == SV_BINDER_ENABLE_ONEWAY_SPAM_DET)
        return 0;
    if (c32 == SV_BINDER_WRITE_READ)
        return binder_write_read(slot, arg);

    int rpc_fd = get_thread_rpc_fd(slot);
    if (rpc_fd < 0)
        return rpc_fd;

    if (c32 == SV_BINDER_SET_MAX_THREADS ||
        c32 == SV_BINDER_SET_CONTEXT_MGR ||
        c32 == SV_BINDER_SET_CONTEXT_MGR_EXT ||
        c32 == SV_BINDER_THREAD_EXIT) {
        uint8_t data[32];
        uint32_t dlen = 0;
        memset(data, 0, sizeof(data));
        if (c32 == SV_BINDER_SET_MAX_THREADS && arg) {
            memcpy(data, (const void *)arg, 4);
            dlen = 4;
        } else if (c32 == SV_BINDER_SET_CONTEXT_MGR_EXT && arg) {
            memcpy(data, (const void *)arg, sizeof(struct sv_flat_binder_object));
            dlen = sizeof(struct sv_flat_binder_object);
        }
        uint32_t tid = (uint32_t)raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
        long rc = send_msg(rpc_fd, VDEV_OP_BINDER_CTL, slot->proc_id, c32, tid,
                           data, dlen, NULL, 0);
        struct vdev_hdr rep;
        if (rc == 0)
            rc = recv_msg(rpc_fd, &rep, NULL, 0, NULL, 0, NULL);
        if (rc < 0)
            return rc;
        return rep.status;
    }
    return -ENOTTY;
}

static long generic_chr_ioctl(struct vdev_open_slot *slot, unsigned long cmd, unsigned long arg)
{
    uint32_t dir = (uint32_t)((cmd >> 30) & 3u);
    uint32_t sz = (uint32_t)((cmd >> 16) & 0x3fffu);
    if (sz > 4096)
        return -EINVAL;
    int rpc_fd = get_thread_rpc_fd(slot);
    if (rpc_fd < 0)
        return rpc_fd;

    uint8_t buf[sizeof(struct vdev_ioctl_req) + 4096];
    struct vdev_ioctl_req *req = (struct vdev_ioctl_req *)buf;
    req->cmd = cmd;
    req->arg = arg;
    req->in_len = (dir & 1u) ? sz : 0;
    req->out_len = (dir & 2u) ? sz : 0;
    if (req->in_len > 0) {
        if (!arg)
            return -EFAULT;
        memcpy(buf + sizeof(*req), (const void *)arg, req->in_len);
    }
    long rc = send_msg(rpc_fd, VDEV_OP_IOCTL, slot->proc_id, 0, 0,
                       buf, (uint32_t)(sizeof(*req) + req->in_len), NULL, 0);
    struct vdev_hdr rep;
    if (rc == 0)
        rc = recv_msg(rpc_fd, &rep, buf, sizeof(buf), NULL, 0, NULL);
    if (rc < 0)
        return rc;
    if (rep.status < 0)
        return rep.status;
    if (req->out_len > 0 && rep.payload_len >= req->out_len) {
        if (!arg)
            return -EFAULT;
        memcpy((void *)arg, buf, req->out_len);
    }
    return rep.status;
}

int vdev_fd_call(long number, long a[6], long *out)
{
    if (!vdev_enabled())
        return 0;

    if (number == __NR_ioctl) {
        struct vdev_open_slot *slot = find_slot_by_fd((int)a[0]);
        if (!slot)
            return 0;
        const struct vdev_entry *ve = &g_payload_config.vdevs[slot->vdev_idx];
        *out = (ve->type == VDEV_TYPE_BINDER)
            ? binder_ioctl(slot, (unsigned long)a[1], (unsigned long)a[2])
            : generic_chr_ioctl(slot, (unsigned long)a[1], (unsigned long)a[2]);
        return 1;
    }

    if (number == __NR_mmap) {
        int fd = (int)a[4];
        if (fd < 0 || (a[3] & MAP_ANONYMOUS_))
            return 0;
        struct vdev_open_slot *slot = find_slot_by_fd(fd);
        if (!slot)
            return 0;
        if (slot->memfd < 0) {
            *out = -ENODEV;
            return 1;
        }
        uint64_t len = (uint64_t)a[1];
        if (slot->memfd_size && len > slot->memfd_size)
            len = slot->memfd_size;
        /* Map the daemon-backed memfd MAP_SHARED so daemon writes are visible immediately. */
        long addr = raw_syscall(__NR_mmap, a[0], (long)len, a[2] & (PROT_READ_ | PROT_WRITE_),
                                MAP_SHARED_, slot->memfd, a[5]);
        if (addr < 0) {
            *out = addr;
            return 1;
        }
        slot->map_base = (uint64_t)addr;
        slot->map_len = len;
        int rpc_fd = get_thread_rpc_fd(slot);
        if (rpc_fd >= 0) {
            struct vdev_mmap_req mreq = { (uint64_t)addr, len };
            struct vdev_hdr rep;
            if (send_msg(rpc_fd, VDEV_OP_MMAP, slot->proc_id, 0, 0, &mreq, sizeof(mreq), NULL, 0) == 0)
                recv_msg(rpc_fd, &rep, NULL, 0, NULL, 0, NULL);
        }
        *out = addr;
        return 1;
    }

    if (number == __NR_fstat) {
        struct vdev_open_slot *slot = find_slot_by_fd((int)a[0]);
        if (!slot)
            return 0;
        struct stat st;
        fill_chr_stat(&st, slot->major, slot->minor);
        if (!a[1]) {
            *out = -EFAULT;
            return 1;
        }
        memcpy((void *)a[1], &st, sizeof(st));
        *out = 0;
        return 1;
    }

    if (number == __NR_close) {
        struct vdev_open_slot *slot = find_slot_by_fd((int)a[0]);
        if (!slot)
            return 0;
        close_slot(slot);
        *out = raw_syscall(__NR_close, a[0], 0, 0, 0, 0, 0);
        return 1;
    }

    return 0;
}
