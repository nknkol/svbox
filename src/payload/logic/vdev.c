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
#include "hook_runtime.h"
#include "vdev.h"
#include "vdev_proto.h"
#include "net_proto.h"

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

#define VDEV_MAX_OPEN        32
#define VDEV_INIT_THREADS    256
#define VDEV_MAX_THREADS     4096
#define VDEV_BWR_STACK_CAP   8192u
#define VDEV_BWR_SCRATCH_CAP 262144u

struct vdev_thread_chan {
    int32_t tid;
    int32_t pid;
    int32_t rpc_fd;
    int32_t used;
    uint8_t *bwr_scratch; /* lazily cached 256 KiB scratch buffer for large BWR calls */
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
    struct vdev_thread_chan *threads;
    uint32_t threads_cap;
};

static struct vdev_open_slot g_open_slots[VDEV_MAX_OPEN];
static volatile int g_vdev_lock = 0;
static volatile int g_vdev_open_count = 0;

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
    if (fd < 0 || __atomic_load_n(&g_vdev_open_count, __ATOMIC_RELAXED) == 0)
        return NULL;
    int32_t pid = (int32_t)raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
    for (int i = 0; i < VDEV_MAX_OPEN; i++) {
        if (g_open_slots[i].active && g_open_slots[i].fd == fd &&
            g_open_slots[i].owner_pid == pid)
            return &g_open_slots[i];
    }
    return NULL;
}

static int slot_reclaim_dead_threads_locked(struct vdev_open_slot *slot, int32_t pid)
{
    int reclaimed = -1;
    if (!slot->threads)
        return -1;
    for (uint32_t i = 0; i < slot->threads_cap; i++) {
        if (!slot->threads[i].used) {
            if (reclaimed < 0)
                reclaimed = (int)i;
            continue;
        }
        int dead = 0;
        if (slot->threads[i].pid != pid) {
            dead = 1;
        } else {
            long rc = raw_syscall(__NR_tgkill, pid, slot->threads[i].tid, 0, 0, 0, 0);
            if (rc == -ESRCH)
                dead = 1;
        }
        if (dead) {
            if (slot->threads[i].pid == pid && slot->threads[i].rpc_fd >= 0)
                raw_syscall(__NR_close, slot->threads[i].rpc_fd, 0, 0, 0, 0, 0);
            if (slot->threads[i].bwr_scratch) {
                raw_syscall(__NR_munmap, (long)slot->threads[i].bwr_scratch,
                            (long)VDEV_BWR_SCRATCH_CAP, 0, 0, 0, 0);
                slot->threads[i].bwr_scratch = NULL;
            }
            slot->threads[i].used = 0;
            slot->threads[i].rpc_fd = -1;
            slot->threads[i].tid = 0;
            slot->threads[i].pid = 0;
            if (reclaimed < 0)
                reclaimed = (int)i;
        }
    }
    return reclaimed;
}

static int slot_alloc_thread_idx_locked(struct vdev_open_slot *slot, int32_t pid)
{
    if (slot->threads) {
        for (uint32_t i = 0; i < slot->threads_cap; i++) {
            if (!slot->threads[i].used || slot->threads[i].pid != pid)
                return (int)i;
        }
        int reclaimed = slot_reclaim_dead_threads_locked(slot, pid);
        if (reclaimed >= 0)
            return reclaimed;
    }
    uint32_t old_cap = slot->threads_cap;
    if (old_cap >= VDEV_MAX_THREADS)
        return -1;
    uint32_t new_cap = old_cap ? old_cap * 2u : VDEV_INIT_THREADS;
    if (new_cap > VDEV_MAX_THREADS)
        new_cap = VDEV_MAX_THREADS;
    size_t new_bytes = (size_t)new_cap * sizeof(struct vdev_thread_chan);
    long addr = raw_syscall(__NR_mmap, 0, (long)new_bytes,
                            PROT_READ_ | PROT_WRITE_,
                            MAP_PRIVATE_ | MAP_ANONYMOUS_, -1, 0);
    if (addr < 0)
        return -1;
    struct vdev_thread_chan *ntbl = (struct vdev_thread_chan *)addr;
    if (slot->threads && old_cap > 0) {
        size_t old_bytes = (size_t)old_cap * sizeof(struct vdev_thread_chan);
        memcpy(ntbl, slot->threads, old_bytes);
        raw_syscall(__NR_munmap, (long)slot->threads, (long)old_bytes, 0, 0, 0, 0);
    }
    slot->threads = ntbl;
    slot->threads_cap = new_cap;
    return (int)old_cap;
}

static int get_thread_rpc_fd_ex(struct vdev_open_slot *slot, int32_t *out_pid, int32_t *out_tid)
{
    int32_t pid = (int32_t)raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
    int32_t tid = (int32_t)raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
    if (out_pid) *out_pid = pid;
    if (out_tid) *out_tid = tid;
    vdev_lock();
    if (slot->threads) {
        for (uint32_t i = 0; i < slot->threads_cap; i++) {
            if (slot->threads[i].used && slot->threads[i].tid == tid && slot->threads[i].pid == pid) {
                int rfd = slot->threads[i].rpc_fd;
                vdev_unlock();
                return rfd;
            }
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
    int idx = slot_alloc_thread_idx_locked(slot, pid);
    if (idx < 0) {
        vdev_unlock();
        raw_syscall(__NR_close, rfd, 0, 0, 0, 0, 0);
        return -ENOMEM;
    }
    if (slot->threads[idx].bwr_scratch) {
        raw_syscall(__NR_munmap, (long)slot->threads[idx].bwr_scratch,
                    (long)VDEV_BWR_SCRATCH_CAP, 0, 0, 0, 0);
        slot->threads[idx].bwr_scratch = NULL;
    }
    slot->threads[idx].used = 1;
    slot->threads[idx].pid = pid;
    slot->threads[idx].tid = tid;
    slot->threads[idx].rpc_fd = (int32_t)rfd;
    vdev_unlock();
    return (int)rfd;
}

static int get_thread_rpc_fd(struct vdev_open_slot *slot)
{
    return get_thread_rpc_fd_ex(slot, NULL, NULL);
}

static uint8_t *get_thread_bwr_scratch(struct vdev_open_slot *slot, int32_t pid, int32_t tid)
{
    vdev_lock();
    if (slot->threads) {
        for (uint32_t i = 0; i < slot->threads_cap; i++) {
            if (slot->threads[i].used && slot->threads[i].tid == tid && slot->threads[i].pid == pid) {
                uint8_t *buf = slot->threads[i].bwr_scratch;
                vdev_unlock();
                if (buf)
                    return buf;
                goto alloc_buf;
            }
        }
    }
    vdev_unlock();

alloc_buf:;
    long addr = raw_syscall(__NR_mmap, 0, (long)VDEV_BWR_SCRATCH_CAP,
                            PROT_READ_ | PROT_WRITE_,
                            MAP_PRIVATE_ | MAP_ANONYMOUS_, -1, 0);
    if (addr < 0)
        return NULL;
    uint8_t *buf = (uint8_t *)addr;
    vdev_lock();
    int cached = 0;
    if (slot->threads) {
        for (uint32_t i = 0; i < slot->threads_cap; i++) {
            if (slot->threads[i].used && slot->threads[i].tid == tid && slot->threads[i].pid == pid) {
                if (!slot->threads[i].bwr_scratch) {
                    slot->threads[i].bwr_scratch = buf;
                    cached = 1;
                } else {
                    uint8_t *existing = slot->threads[i].bwr_scratch;
                    vdev_unlock();
                    raw_syscall(__NR_munmap, addr, (long)VDEV_BWR_SCRATCH_CAP, 0, 0, 0, 0);
                    return existing;
                }
                break;
            }
        }
    }
    vdev_unlock();
    if (!cached) {
        raw_syscall(__NR_munmap, addr, (long)VDEV_BWR_SCRATCH_CAP, 0, 0, 0, 0);
        return NULL;
    }
    return buf;
}

static void drop_thread_rpc_fd(struct vdev_open_slot *slot)
{
    int32_t pid = (int32_t)raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
    int32_t tid = (int32_t)raw_syscall(__NR_gettid, 0, 0, 0, 0, 0, 0);
    int close_fd = -1;
    uint8_t *free_buf = NULL;
    vdev_lock();
    if (slot->threads) {
        for (uint32_t i = 0; i < slot->threads_cap; i++) {
            if (slot->threads[i].used && slot->threads[i].tid == tid && slot->threads[i].pid == pid) {
                close_fd = slot->threads[i].rpc_fd;
                free_buf = slot->threads[i].bwr_scratch;
                slot->threads[i].used = 0;
                slot->threads[i].rpc_fd = -1;
                slot->threads[i].tid = 0;
                slot->threads[i].pid = 0;
                slot->threads[i].bwr_scratch = NULL;
                break;
            }
        }
    }
    vdev_unlock();
    if (close_fd >= 0)
        raw_syscall(__NR_close, close_fd, 0, 0, 0, 0, 0);
    if (free_buf)
        raw_syscall(__NR_munmap, (long)free_buf, (long)VDEV_BWR_SCRATCH_CAP, 0, 0, 0, 0);
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
    struct vdev_thread_chan *tbl = slot->threads;
    uint32_t cap = slot->threads_cap;
    slot->threads = NULL;
    slot->threads_cap = 0;
    if (tbl) {
        for (uint32_t i = 0; i < cap; i++) {
            if (tbl[i].used && tbl[i].rpc_fd >= 0) {
                raw_syscall(__NR_close, tbl[i].rpc_fd, 0, 0, 0, 0, 0);
                tbl[i].used = 0;
                tbl[i].rpc_fd = -1;
            }
            if (tbl[i].bwr_scratch) {
                raw_syscall(__NR_munmap, (long)tbl[i].bwr_scratch,
                            (long)VDEV_BWR_SCRATCH_CAP, 0, 0, 0, 0);
                tbl[i].bwr_scratch = NULL;
            }
        }
        raw_syscall(__NR_munmap, (long)tbl, (long)((size_t)cap * sizeof(struct vdev_thread_chan)),
                    0, 0, 0, 0);
    }
    slot->active = 0;
    slot->fd = -1;
    __atomic_sub_fetch(&g_vdev_open_count, 1, __ATOMIC_RELEASE);
    vdev_unlock();
    if (memfd >= 0)
        raw_syscall(__NR_close, memfd, 0, 0, 0, 0, 0);
}

int vdev_match_path(const char *guest_path)
{
    if (!guest_path || g_payload_config.vdev_count <= 0)
        return -1;
    char c1 = guest_path[1];
    for (int i = 0; i < g_payload_config.vdev_count; i++) {
        const char *vg = g_payload_config.vdevs[i].guest;
        if (vg[1] == c1 && strcmp(guest_path, vg) == 0)
            return i;
    }
    return -1;
}

static void fill_chr_stat(struct stat *st, uint32_t major, uint32_t minor)
{
    memset(st, 0, sizeof(*st));
    st->st_mode = 0020666; /* S_IFCHR | 0666 */
    st->st_nlink = 1;
    st->st_rdev = ((uint64_t)(minor & 0xffu)) |
                  ((uint64_t)(major & 0xfffu) << 8) |
                  ((uint64_t)(minor & ~0xffu) << 12) |
                  ((uint64_t)(major & ~0xfffu) << 32);
    st->st_blksize = 4096;
}

long vdev_path_call(long number, long a[6], int vdev_idx)
{
    if (vdev_idx < 0 || vdev_idx >= g_payload_config.vdev_count)
        return -ENOENT;
    const struct vdev_entry *ve = &g_payload_config.vdevs[vdev_idx];
    uint32_t major = 10;
    uint32_t minor = (ve->type == VDEV_TYPE_TUN) ? 200u : (220u + (uint32_t)vdev_idx);

    switch (number) {
    case __NR_openat: {
        if ((a[2] & O_CREAT) && (a[2] & O_EXCL))
            return -EEXIST;
        if (a[2] & O_DIRECTORY)
            return -ENOTDIR;
        int cloexec = (a[2] & O_CLOEXEC) ? 1 : 0;
        long fd = connect_unix_sock(ve->sock, (ve->type == VDEV_TYPE_TUN) ? 1 : cloexec);
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

        int guest_fd = (int)fd;
        int memfd = nfds > 0 ? rfds[0] : -1;
        if (ve->type == VDEV_TYPE_TUN) {
            /* Daemon sends a kernel AF_UNIX SOCK_SEQPACKET data FD via SCM_RIGHTS
             * so packet boundaries, epoll, O_NONBLOCK, dup and SCM_RIGHTS passing
             * work natively; close the ephemeral control socket immediately. */
            raw_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
            if (nfds < 1 || rfds[0] < 0) {
                for (uint32_t i = 0; i < nfds; i++)
                    raw_syscall(__NR_close, rfds[i], 0, 0, 0, 0, 0);
                return -EPROTO;
            }
            guest_fd = rfds[0];
            memfd = -1;
            for (uint32_t i = 1; i < nfds; i++)
                raw_syscall(__NR_close, rfds[i], 0, 0, 0, 0, 0);
            if (!cloexec)
                raw_syscall(__NR_fcntl, guest_fd, F_SETFD, 0, 0, 0, 0);
        } else {
            for (uint32_t i = 1; i < nfds; i++)
                raw_syscall(__NR_close, rfds[i], 0, 0, 0, 0, 0);
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
            if (memfd >= 0)
                raw_syscall(__NR_close, memfd, 0, 0, 0, 0, 0);
            raw_syscall(__NR_close, guest_fd, 0, 0, 0, 0, 0);
            return -EMFILE;
        }
        struct vdev_open_slot *s = &g_open_slots[idx];
        int was_active = s->active;
        if (was_active && s->threads && s->threads_cap > 0) {
            for (uint32_t i = 0; i < s->threads_cap; i++) {
                if (s->threads[i].bwr_scratch) {
                    raw_syscall(__NR_munmap, (long)s->threads[i].bwr_scratch,
                                (long)VDEV_BWR_SCRATCH_CAP, 0, 0, 0, 0);
                }
            }
            raw_syscall(__NR_munmap, (long)s->threads,
                        (long)((size_t)s->threads_cap * sizeof(struct vdev_thread_chan)),
                        0, 0, 0, 0);
        }
        memset(s, 0, sizeof(*s));
        s->active = 1;
        s->vdev_idx = vdev_idx;
        s->fd = (int32_t)guest_fd;
        s->memfd = memfd;
        s->proc_id = rep.proc_id;
        s->major = rep.major ? rep.major : major;
        s->minor = rep.minor ? rep.minor : minor;
        s->memfd_size = rep.memfd_size;
        s->owner_pid = cur_pid;
        if (!was_active)
            __atomic_add_fetch(&g_vdev_open_count, 1, __ATOMIC_RELEASE);
        vdev_unlock();
        if (a[2] & O_NONBLOCK) {
            long fl = raw_syscall(__NR_fcntl, guest_fd, F_GETFL, 0, 0, 0, 0);
            if (fl >= 0)
                raw_syscall(__NR_fcntl, guest_fd, F_SETFL, fl | O_NONBLOCK, 0, 0, 0);
        }
        return guest_fd;
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

    int32_t cur_pid = 0, cur_tid = 0;
    int rpc_fd = get_thread_rpc_fd_ex(slot, &cur_pid, &cur_tid);
    if (rpc_fd < 0)
        return rpc_fd;

    /* Drain level-triggered epoll wakeup bytes only when actually reading. */
    if (bwr.read_size > 0) {
        char drain[64];
        while (raw_syscall(__NR_recvfrom, slot->fd, (long)drain, sizeof(drain),
                           MSG_DONTWAIT_, 0, 0) > 0) {
        }
    }

    uint64_t rcap = bwr.read_size > bwr.read_consumed ? bwr.read_size - bwr.read_consumed : 0;
    if (rcap > 65536)
        rcap = 65536;
    uint64_t wrem = bwr.write_size > bwr.write_consumed ? bwr.write_size - bwr.write_consumed : 0;
    const uint8_t *src = (const uint8_t *)(uintptr_t)(bwr.write_buffer + bwr.write_consumed);

    /* Estimate total marshaled payload size for write commands so we can choose:
     * 1) 8 KiB stack fast-path (99% of calls, zero mmap),
     * 2) 256 KiB cached per-thread scratch, or
     * 3) one-shot mmap up to VDEV_MAX_PAYLOAD (2 MiB) for large IPC transfers. */
    size_t est = sizeof(struct vdev_binder_wr_req);
    int has_sg = 0;
    {
        size_t p = 0;
        while (p + 4 <= wrem) {
            uint32_t cmd;
            memcpy(&cmd, src + p, 4);
            uint32_t asz = binder_bc_arg_size(cmd);
            if (p + 4 + asz > wrem)
                break;
            if (cmd == SV_BC_TRANSACTION || cmd == SV_BC_REPLY ||
                cmd == SV_BC_TRANSACTION_SG || cmd == SV_BC_REPLY_SG) {
                struct sv_binder_transaction_data txn;
                memcpy(&txn, src + p + 4, sizeof(txn));
                if (txn.data_size > VDEV_MAX_PAYLOAD || txn.offsets_size > VDEV_MAX_PAYLOAD) {
                    est = (size_t)VDEV_MAX_PAYLOAD + 1u;
                    break;
                }
                est += 4 + asz + (size_t)txn.data_size + (size_t)txn.offsets_size;
                if (cmd == SV_BC_TRANSACTION_SG || cmd == SV_BC_REPLY_SG) {
                    has_sg = 1;
                    if (p + 4 + sizeof(struct sv_binder_transaction_data_sg) <= wrem) {
                        struct sv_binder_transaction_data_sg tsg;
                        memcpy(&tsg, src + p + 4, sizeof(tsg));
                        if (tsg.buffers_size > VDEV_MAX_PAYLOAD) {
                            est = (size_t)VDEV_MAX_PAYLOAD + 1u;
                            break;
                        }
                        est += (size_t)tsg.buffers_size;
                    }
                }
            } else {
                est += 4 + asz;
            }
            if (est > VDEV_MAX_PAYLOAD) {
                est = (size_t)VDEV_MAX_PAYLOAD + 1u;
                break;
            }
            p += 4 + asz;
        }
    }

    int use_stack = (!has_sg && rcap <= VDEV_BWR_STACK_CAP - 1024u && est <= VDEV_BWR_STACK_CAP);
    uint8_t stack_buf[VDEV_BWR_STACK_CAP];
    uint8_t *scratch;
    size_t buf_cap;
    size_t dyn_mmap_cap = 0;
    if (use_stack) {
        scratch = stack_buf;
        buf_cap = sizeof(stack_buf);
    } else if (est <= VDEV_BWR_SCRATCH_CAP) {
        scratch = get_thread_bwr_scratch(slot, cur_pid, cur_tid);
        if (!scratch)
            return -ENOMEM;
        buf_cap = VDEV_BWR_SCRATCH_CAP;
    } else if (est <= VDEV_MAX_PAYLOAD) {
        size_t need_cap = est;
        if (need_cap < (size_t)rcap + 4096u)
            need_cap = (size_t)rcap + 4096u;
        need_cap = (need_cap + 4095ul) & ~4095ul;
        if (need_cap > VDEV_MAX_PAYLOAD)
            need_cap = VDEV_MAX_PAYLOAD;
        long addr = raw_syscall(__NR_mmap, 0, (long)need_cap,
                                PROT_READ_ | PROT_WRITE_,
                                MAP_PRIVATE_ | MAP_ANONYMOUS_, -1, 0);
        if (addr < 0 && addr >= -4095)
            return -ENOMEM;
        scratch = (uint8_t *)(uintptr_t)addr;
        buf_cap = need_cap;
        dyn_mmap_cap = need_cap;
    } else {
        return -ENOMEM;
    }

    struct vdev_binder_wr_req *wreq = (struct vdev_binder_wr_req *)scratch;
    memset(wreq, 0, sizeof(*wreq));
    wreq->pid = (uint32_t)cur_pid;
    wreq->tid = (uint32_t)cur_tid;
    wreq->uid = g_payload_config.fake_ids[1];
    wreq->read_cap = (uint32_t)rcap;

    uint8_t *dst = scratch + sizeof(*wreq);
    size_t dst_cap = buf_cap - sizeof(*wreq);
    size_t dst_off = 0;

    int send_fds[VDEV_MAX_FDS];
    uint32_t send_fd_count = 0;

    wreq->raw_write_size = (uint32_t)wrem;
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
    if (dyn_mmap_cap > 0) {
        raw_syscall(__NR_munmap, (long)scratch, (long)dyn_mmap_cap, 0, 0, 0, 0);
    }
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
        if (c32 == SV_BINDER_THREAD_EXIT)
            drop_thread_rpc_fd(slot);
        if (rc < 0)
            return rc;
        return rep.status;
    }
    return -ENOTTY;
}

#define SV_FIONREAD                0x541bu
#define SV_FIONBIO                 0x5421u
#define SV_TCGETS                  0x5401u
#define SV_TCSETS                  0x5402u
#define SV_TCSETSW                 0x5403u
#define SV_TCSETSF                 0x5404u
#define SV_TIOCGWINSZ              0x5413u
#define SV_TIOCSWINSZ              0x5414u
#define SV_TIOCMGET                0x5415u
#define SV_TIOCMBIS                0x5416u
#define SV_TIOCMBIC                0x5417u
#define SV_TIOCMSET                0x5418u
#define SV_USBDEVFS_CONTROL        0xc0185500u
#define SV_USBDEVFS_BULK           0xc0185502u
#define SV_USBDEVFS_SETINTERFACE   0x80085504u
#define SV_USBDEVFS_SETCONFIG      0x80045505u
#define SV_USBDEVFS_GETDRIVER      0x41045508u
#define SV_USBDEVFS_CLAIMIFACE     0x8004550fu
#define SV_USBDEVFS_RELEASEIFACE   0x80045510u
#define SV_USBDEVFS_CONNECTINFO    0x40085511u
#define SV_USBDEVFS_CLEAR_HALT     0x80045515u

struct sv_usbdevfs_ctrl {
    uint8_t  bRequestType;
    uint8_t  bRequest;
    uint16_t wValue;
    uint16_t wIndex;
    uint16_t wLength;
    uint32_t timeout;
    uint32_t _pad;
    uint64_t data;
};

struct sv_usbdevfs_bulk {
    uint32_t ep;
    uint32_t len;
    uint32_t timeout;
    uint32_t _pad;
    uint64_t data;
};

static int generic_chr_ioctl(struct vdev_open_slot *slot, unsigned long cmd, unsigned long arg, long *out)
{
    uint32_t c32 = (uint32_t)cmd;
    if (c32 == SV_FIONBIO || c32 == SV_FIONREAD)
        return 0; /* Let kernel run FIONBIO/FIONREAD directly on the stream socket FD. */

    int rpc_fd = get_thread_rpc_fd(slot);
    if (rpc_fd < 0) {
        *out = rpc_fd;
        return 1;
    }

    /* Special-case Linux usbfs transfers carrying an embedded userspace data pointer. */
    if (c32 == SV_USBDEVFS_CONTROL || c32 == SV_USBDEVFS_BULK) {
        if (!arg) {
            *out = -EFAULT;
            return 1;
        }
        uint64_t data_ptr = 0;
        uint32_t xfer_len = 0;
        int is_in = 0;
        uint8_t xhdr[24];
        memcpy(xhdr, (const void *)arg, 24);
        if (c32 == SV_USBDEVFS_CONTROL) {
            struct sv_usbdevfs_ctrl ct;
            memcpy(&ct, xhdr, sizeof(ct));
            is_in = (ct.bRequestType & 0x80u) != 0;
            xfer_len = ct.wLength;
            data_ptr = ct.data;
        } else {
            struct sv_usbdevfs_bulk bt;
            memcpy(&bt, xhdr, sizeof(bt));
            is_in = (bt.ep & 0x80u) != 0;
            xfer_len = bt.len;
            data_ptr = bt.data;
        }
        if (xfer_len > 4096u) {
            *out = -EINVAL;
            return 1;
        }
        if (xfer_len > 0 && !data_ptr) {
            *out = -EFAULT;
            return 1;
        }
        uint8_t buf[sizeof(struct vdev_ioctl_req) + 24 + 4096];
        struct vdev_ioctl_req *req = (struct vdev_ioctl_req *)buf;
        req->cmd = c32;
        req->arg = arg;
        req->in_len = 24u + (is_in ? 0u : xfer_len);
        req->out_len = is_in ? xfer_len : 0u;
        memcpy(buf + sizeof(*req), xhdr, 24);
        if (!is_in && xfer_len > 0)
            memcpy(buf + sizeof(*req) + 24, (const void *)(uintptr_t)data_ptr, xfer_len);
        long rc = send_msg(rpc_fd, VDEV_OP_IOCTL, slot->proc_id, 0, 0,
                           buf, (uint32_t)(sizeof(*req) + req->in_len), NULL, 0);
        struct vdev_hdr rep;
        if (rc == 0)
            rc = recv_msg(rpc_fd, &rep, buf, sizeof(buf), NULL, 0, NULL);
        if (rc < 0) {
            *out = rc;
            return 1;
        }
        if (rep.status < 0) {
            *out = rep.status;
            return 1;
        }
        if (is_in && xfer_len > 0 && rep.payload_len > 0) {
            uint32_t copy_n = rep.payload_len < xfer_len ? rep.payload_len : xfer_len;
            memcpy((void *)(uintptr_t)data_ptr, buf, copy_n);
        }
        *out = rep.status;
        return 1;
    }

    uint32_t dir = (uint32_t)((c32 >> 30) & 3u);
    uint32_t sz = (uint32_t)((c32 >> 16) & 0x3fffu);
    uint32_t in_len = (dir & 1u) ? sz : 0u;
    uint32_t out_len = (dir & 2u) ? sz : 0u;

    /* Legacy Linux tty/termios and reversed-direction usbfs ioctl sizing. */
    switch (c32) {
    case SV_TCGETS:
        in_len = 0; out_len = 36; break;
    case SV_TCSETS:
    case SV_TCSETSW:
    case SV_TCSETSF:
        in_len = 36; out_len = 0; break;
    case SV_TIOCGWINSZ:
        in_len = 0; out_len = 8; break;
    case SV_TIOCSWINSZ:
        in_len = 8; out_len = 0; break;
    case SV_TIOCMGET:
        in_len = 0; out_len = 4; break;
    case SV_TIOCMBIS:
    case SV_TIOCMBIC:
    case SV_TIOCMSET:
        in_len = 4; out_len = 0; break;
    case SV_USBDEVFS_CLAIMIFACE:
    case SV_USBDEVFS_RELEASEIFACE:
    case SV_USBDEVFS_SETCONFIG:
    case SV_USBDEVFS_CLEAR_HALT:
        in_len = 4; out_len = 0; break;
    case SV_USBDEVFS_SETINTERFACE:
        in_len = 8; out_len = 0; break;
    case SV_USBDEVFS_GETDRIVER:
        in_len = 260; out_len = 260; break;
    case SV_USBDEVFS_CONNECTINFO:
        in_len = 0; out_len = 8; break;
    default:
        break;
    }

    if (in_len > 4096u || out_len > 4096u) {
        *out = -EINVAL;
        return 1;
    }

    uint8_t buf[sizeof(struct vdev_ioctl_req) + 4096];
    struct vdev_ioctl_req *req = (struct vdev_ioctl_req *)buf;
    req->cmd = c32;
    req->arg = arg;
    req->in_len = in_len;
    req->out_len = out_len;
    if (req->in_len > 0) {
        if (!arg) {
            *out = -EFAULT;
            return 1;
        }
        memcpy(buf + sizeof(*req), (const void *)arg, req->in_len);
    }
    long rc = send_msg(rpc_fd, VDEV_OP_IOCTL, slot->proc_id, 0, 0,
                       buf, (uint32_t)(sizeof(*req) + req->in_len), NULL, 0);
    struct vdev_hdr rep;
    if (rc == 0)
        rc = recv_msg(rpc_fd, &rep, buf, sizeof(buf), NULL, 0, NULL);
    if (rc < 0) {
        *out = rc;
        return 1;
    }
    if (rep.status < 0) {
        *out = rep.status;
        return 1;
    }
    if (out_len > 0 && rep.payload_len > 0) {
        if (!arg) {
            *out = -EFAULT;
            return 1;
        }
        uint32_t copy_n = rep.payload_len < out_len ? rep.payload_len : out_len;
        memcpy((void *)arg, buf, copy_n);
    }
    *out = rep.status;
    return 1;
}

static int tun_ioctl(struct vdev_open_slot *slot, unsigned long cmd, unsigned long arg, long *out)
{
    uint32_t c32 = (uint32_t)cmd;
    uint32_t in_len = 0, out_len = 0;
    switch (c32) {
    case SV_TUNSETIFF:
        in_len = 40; /* sizeof(struct ifreq) on LP64 */
        out_len = 40;
        break;
    case SV_TUNGETIFF:
        in_len = 0;
        out_len = 40;
        break;
    case SV_TUNSETQUEUE:
        in_len = 40;
        out_len = 0;
        break;
    case SV_TUNGETFEATURES:
    case SV_TUNGETVNETHDRSZ:
        in_len = 0;
        out_len = 4;
        break;
    case SV_TUNSETVNETHDRSZ:
        in_len = 4;
        out_len = 0;
        break;
    case SV_TUNSETPERSIST:
    case SV_TUNSETOWNER:
    case SV_TUNSETGROUP:
        in_len = 0;
        out_len = 0;
        break;
    default:
        /* Let kernel ioctls like FIONBIO/FIONREAD run directly on the SOCK_SEQPACKET FD. */
        return 0;
    }

    const struct vdev_entry *ve = &g_payload_config.vdevs[slot->vdev_idx];
    long ctl = connect_unix_sock(ve->sock, 1);
    if (ctl < 0) {
        *out = ctl;
        return 1;
    }
    uint8_t buf[sizeof(struct vdev_ioctl_req) + 64];
    struct vdev_ioctl_req *req = (struct vdev_ioctl_req *)buf;
    req->cmd = c32;
    req->arg = arg;
    req->in_len = in_len;
    req->out_len = out_len;
    if (in_len > 0) {
        if (!arg) {
            raw_syscall(__NR_close, ctl, 0, 0, 0, 0, 0);
            *out = -EFAULT;
            return 1;
        }
        memcpy(buf + sizeof(*req), (const void *)arg, in_len);
    }
    long rc = send_msg((int)ctl, VDEV_OP_IOCTL, slot->proc_id, 0, 0,
                       buf, (uint32_t)(sizeof(*req) + in_len), NULL, 0);
    struct vdev_hdr rep;
    if (rc == 0)
        rc = recv_msg((int)ctl, &rep, buf, sizeof(buf), NULL, 0, NULL);
    raw_syscall(__NR_close, ctl, 0, 0, 0, 0, 0);
    if (rc < 0) {
        *out = rc;
        return 1;
    }
    if (rep.status < 0) {
        *out = rep.status;
        return 1;
    }
    if (out_len > 0 && rep.payload_len > 0) {
        if (!arg) {
            *out = -EFAULT;
            return 1;
        }
        uint32_t copy_n = rep.payload_len < out_len ? rep.payload_len : out_len;
        memcpy((void *)arg, buf, copy_n);
    }
    *out = rep.status;
    return 1;
}

const char *vdev_fd_guest_path(int fd)
{
    if (!vdev_enabled() || fd < 0)
        return NULL;
    struct vdev_open_slot *slot = find_slot_by_fd(fd);
    if (!slot)
        return NULL;
    if (slot->vdev_idx < 0 || slot->vdev_idx >= g_payload_config.vdev_count)
        return NULL;
    return g_payload_config.vdevs[slot->vdev_idx].guest;
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
        if (ve->type == VDEV_TYPE_TUN)
            return tun_ioctl(slot, (unsigned long)a[1], (unsigned long)a[2], out);
        if (ve->type == VDEV_TYPE_BINDER) {
            *out = binder_ioctl(slot, (unsigned long)a[1], (unsigned long)a[2]);
            return 1;
        }
        return generic_chr_ioctl(slot, (unsigned long)a[1], (unsigned long)a[2], out);
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
        if (slot->vdev_idx >= 0 && slot->vdev_idx < g_payload_config.vdev_count) {
            const struct vdev_entry *ve = &g_payload_config.vdevs[slot->vdev_idx];
            uint64_t rdev = ((uint64_t)(slot->major & 0xfffu) << 8) |
                            ((uint64_t)(slot->minor & 0xffu)) |
                            ((uint64_t)(slot->minor & ~0xffu) << 12);
            vma_track_add_guest((uintptr_t)addr, (size_t)len, (uint64_t)a[5],
                                rdev, (uint64_t)(0x50000u + (uint32_t)slot->vdev_idx),
                                ve->guest);
        }
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
