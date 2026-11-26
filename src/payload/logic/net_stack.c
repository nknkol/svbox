/* SPDX-License-Identifier: MIT */
/* Generic userspace virtual network & TUN client inside svbox payload.
 *
 * When --net-sock PATH is configured, every guest process lazily maps the
 * daemon's single-writer shared state page (PROT_READ, zero persistent FDs)
 * and transparently handles:
 *  - Virtual AF_NETLINK/NETLINK_ROUTE sockets backed by SOCK_SEQPACKET
 *  - Virtual SIOC* interface & route ioctls
 *  - Unprivileged SO_MARK & SO_BINDTODEVICE recording + TUN bypass
 *  - Container-wide TCP/UDP redirection into active TUN routes (with loopback,
 *    SO_MARK, SO_BINDTODEVICE, UID-rule, and protected-socket-inode bypass)
 *  - Virtual /proc/net/{dev,route,if_inet6} and /sys/class/net/<iface>/<attr> views */
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
#include "net_view.h"
#include "net_proto.h"
#include "net_stack.h"

extern long raw_syscall(long number, long a1, long a2, long a3, long a4, long a5, long a6);

#define AF_UNIX_          1
#define AF_INET_          2
#define AF_INET6_         10
#define AF_NETLINK_       16
#define NETLINK_ROUTE_    0
#define SOCK_STREAM_      1
#define SOCK_DGRAM_       2
#define SOCK_NONBLOCK_    00004000
#define SOCK_CLOEXEC_     02000000
#define SOL_SOCKET_       1
#define SOL_NETLINK_      270
#define IPPROTO_IPV6_     41
#define IPV6_V6ONLY_      26
#define SO_TYPE_          3
#define SO_BINDTODEVICE_  25
#define SO_MARK_          36
#define SCM_RIGHTS_       1
#define MSG_NOSIGNAL_     0x4000
#define MSG_CMSG_CLOEXEC_ 0x40000000
#define PROT_READ_        1
#define PROT_WRITE_       2
#define MAP_SHARED_       1
#define MAP_PRIVATE_      2
#define MAP_ANONYMOUS_    0x20
#define F_DUPFD_          0
#define F_SETFD_          2
#define F_GETFL_          3
#define F_SETFL_          4
#define F_DUPFD_CLOEXEC_  1030

struct ns_sockaddr_un {
    uint16_t sun_family;
    char     sun_path[108];
};

struct ns_sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint8_t  sin_zero[8];
};

struct ns_sockaddr_in6 {
    uint16_t sin6_family;
    uint16_t sin6_port;
    uint32_t sin6_flowinfo;
    uint8_t  sin6_addr[16];
    uint32_t sin6_scope_id;
};

struct ns_sockaddr_nl {
    uint16_t nl_family;
    uint16_t nl_pad;
    uint32_t nl_pid;
    uint32_t nl_groups;
};

struct ns_iovec {
    void  *iov_base;
    size_t iov_len;
};

struct ns_msghdr {
    void            *msg_name;
    uint32_t         msg_namelen;
    uint32_t         _pad0;
    struct ns_iovec *msg_iov;
    size_t           msg_iovlen;
    void            *msg_control;
    size_t           msg_controllen;
    int              msg_flags;
    int              _pad1;
};

struct ns_cmsghdr {
    size_t cmsg_len;
    int    cmsg_level;
    int    cmsg_type;
};

#define NS_ALIGN8(x) (((x) + 7ul) & ~7ul)
#define NS_CMSG_LEN(n) (NS_ALIGN8(sizeof(struct ns_cmsghdr)) + (n))
#define NS_CMSG_SPACE(n) (NS_ALIGN8(sizeof(struct ns_cmsghdr)) + NS_ALIGN8(n))

static inline uint16_t ns_be16(uint16_t v) { return (uint16_t)((v << 8) | (v >> 8)); }
static inline uint32_t ns_be32(uint32_t v) { return __builtin_bswap32(v); }

static volatile int g_ns_lock = 0;
static struct sv_net_state *g_net_state = NULL;
static int g_net_state_rw = 0;

/* Lockless FD bitmaps tracking AF_INET/AF_INET6 sockets (FDs 0..1023) and
 * whether the socket's peer/destination is loopback, for zero-IPC live
 * rx/tx counter updates in shared sv_net_state. */
static uint64_t g_inet_fds[16];
static uint64_t g_inet_lo_fds[16];

static inline int inet_fd_test(const uint64_t bm[16], int fd)
{
    if ((unsigned)fd >= 1024u) return 0;
    return (int)((__atomic_load_n(&bm[(unsigned)fd >> 6], __ATOMIC_RELAXED) >>
                  ((unsigned)fd & 63u)) & 1ull);
}

static inline void inet_fd_set(uint64_t bm[16], int fd)
{
    if ((unsigned)fd >= 1024u) return;
    __atomic_fetch_or(&bm[(unsigned)fd >> 6], 1ull << ((unsigned)fd & 63u), __ATOMIC_RELAXED);
}

static inline void inet_fd_clear(uint64_t bm[16], int fd)
{
    if ((unsigned)fd >= 1024u) return;
    __atomic_fetch_and(&bm[(unsigned)fd >> 6], ~(1ull << ((unsigned)fd & 63u)), __ATOMIC_RELAXED);
}

#define NS_MAX_NL_FDS       64
#define NS_MARK_INLINE_CAP  64
#define NS_MARK_MAX_CAP     4096

struct ns_nl_slot {
    int32_t  active;
    int32_t  fd;
    uint32_t nl_id;
    uint32_t nl_groups;
    uint32_t nl_pid;
};

struct ns_mark_slot {
    int32_t  active;
    int32_t  fd;
    uint32_t mark;
    int32_t  bypass;
    char     bind_dev[16];
};

static struct ns_nl_slot    g_nl_fds[NS_MAX_NL_FDS];
static volatile int         g_nl_active_count = 0;

static struct ns_mark_slot  g_mark_inline[NS_MARK_INLINE_CAP];
static struct ns_mark_slot *g_mark_fds = g_mark_inline;
static int                  g_mark_cap = NS_MARK_INLINE_CAP;
static size_t               g_mark_mmap_bytes = 0;
static volatile int         g_mark_active_count = 0;

static void ns_lock(void)
{
    while (__sync_lock_test_and_set(&g_ns_lock, 1))
        __asm__ volatile("yield" ::: "memory");
}

static void ns_unlock(void)
{
    __sync_lock_release(&g_ns_lock);
}

/* ---- Ephemeral AF_UNIX RPC helpers (0 persistent FDs kept open) ---- */

static long ns_connect_ctl(void)
{
    const char *path = g_payload_config.net_sock;
    if (!path[0])
        return -ENOENT;
    long fd = raw_syscall(__NR_socket, AF_UNIX_, SOCK_STREAM_ | SOCK_CLOEXEC_, 0, 0, 0, 0);
    if (fd < 0)
        return fd;
    struct ns_sockaddr_un sa;
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

static long ns_send_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;
    while (sent < len) {
        struct ns_iovec iov = { (void *)(p + sent), len - sent };
        struct ns_msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        long n = raw_syscall(__NR_sendmsg, fd, (long)&msg, MSG_NOSIGNAL_, 0, 0, 0);
        if (n == -EINTR)
            continue;
        if (n <= 0)
            return n < 0 ? n : -EPIPE;
        sent += (size_t)n;
    }
    return 0;
}

static long ns_recv_all(int fd, void *buf, size_t len, int *out_fd)
{
    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;
    if (out_fd)
        *out_fd = -1;
    while (got < len) {
        struct ns_iovec iov = { p + got, len - got };
        struct ns_msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        unsigned char cbuf[NS_CMSG_SPACE(sizeof(int) * 4)];
        if (out_fd && *out_fd < 0) {
            memset(cbuf, 0, sizeof(cbuf));
            msg.msg_control = cbuf;
            msg.msg_controllen = sizeof(cbuf);
        }
        long n = raw_syscall(__NR_recvmsg, fd, (long)&msg, MSG_CMSG_CLOEXEC_, 0, 0, 0);
        if (n == -EINTR)
            continue;
        if (n <= 0)
            return n < 0 ? n : -EPIPE;
        if (out_fd && msg.msg_controllen >= sizeof(struct ns_cmsghdr)) {
            size_t off = 0;
            while (off + sizeof(struct ns_cmsghdr) <= msg.msg_controllen) {
                struct ns_cmsghdr *c = (struct ns_cmsghdr *)(cbuf + off);
                if (c->cmsg_len < sizeof(struct ns_cmsghdr) || off + c->cmsg_len > msg.msg_controllen)
                    break;
                if (c->cmsg_level == SOL_SOCKET_ && c->cmsg_type == SCM_RIGHTS_) {
                    size_t doff = NS_ALIGN8(sizeof(struct ns_cmsghdr));
                    size_t nf = (c->cmsg_len - doff) / sizeof(int);
                    const int *rfds = (const int *)(cbuf + off + doff);
                    for (size_t i = 0; i < nf; i++) {
                        if (*out_fd < 0)
                            *out_fd = rfds[i];
                        else
                            raw_syscall(__NR_close, rfds[i], 0, 0, 0, 0, 0);
                    }
                }
                off += NS_ALIGN8(c->cmsg_len);
            }
        }
        got += (size_t)n;
    }
    return 0;
}

static long ns_rpc(uint32_t op, uint32_t proc_id, uint64_t arg0, uint64_t arg1,
                   const void *req_buf, uint32_t req_len,
                   void *rep_buf, uint32_t rep_cap, uint32_t *rep_len_out,
                   struct vdev_hdr *rep_hdr_out, int *rep_fd_out)
{
    if (rep_fd_out) *rep_fd_out = -1;
    if (rep_len_out) *rep_len_out = 0;
    long cfd = ns_connect_ctl();
    if (cfd < 0)
        return cfd;
    struct vdev_hdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = VDEV_PROTO_MAGIC;
    hdr.op = op;
    hdr.payload_len = req_len;
    hdr.proc_id = proc_id;
    hdr.arg0 = arg0;
    hdr.arg1 = arg1;
    long rc = ns_send_all((int)cfd, &hdr, sizeof(hdr));
    if (rc == 0 && req_len > 0)
        rc = ns_send_all((int)cfd, req_buf, req_len);
    struct vdev_hdr rep;
    memset(&rep, 0, sizeof(rep));
    int rfd = -1;
    if (rc == 0)
        rc = ns_recv_all((int)cfd, &rep, sizeof(rep), rep_fd_out ? &rfd : NULL);
    if (rc == 0 && rep.magic != VDEV_PROTO_MAGIC)
        rc = -EPROTO;
    if (rc == 0 && rep.payload_len > 0) {
        if (!rep_buf || rep.payload_len > rep_cap) {
            rc = -EMSGSIZE;
        } else {
            rc = ns_recv_all((int)cfd, rep_buf, rep.payload_len, NULL);
            if (rc == 0 && rep_len_out)
                *rep_len_out = rep.payload_len;
        }
    }
    raw_syscall(__NR_close, cfd, 0, 0, 0, 0, 0);
    if (rc < 0) {
        if (rfd >= 0)
            raw_syscall(__NR_close, rfd, 0, 0, 0, 0, 0);
        return rc;
    }
    if (rep_hdr_out)
        *rep_hdr_out = rep;
    if (rep_fd_out)
        *rep_fd_out = rfd;
    else if (rfd >= 0)
        raw_syscall(__NR_close, rfd, 0, 0, 0, 0, 0);
    return rep.status;
}

const struct sv_net_state *net_stack_state(void)
{
    if (!net_stack_enabled())
        return NULL;
    struct sv_net_state *cur = __atomic_load_n(&g_net_state, __ATOMIC_ACQUIRE);
    if (cur)
        return cur;

    ns_lock();
    cur = g_net_state;
    if (!cur) {
        struct vdev_hdr rep;
        int mfd = -1;
        long rc = ns_rpc(NET_OP_GET_STATE, 0, 0, 0, NULL, 0, NULL, 0, NULL, &rep, &mfd);
        if (rc == 0 && mfd >= 0) {
            size_t sz = rep.arg0 >= sizeof(struct sv_net_state)
                ? (size_t)rep.arg0
                : sizeof(struct sv_net_state);
            int rw = 1;
            long addr = raw_syscall(__NR_mmap, 0, (long)sz, PROT_READ_ | PROT_WRITE_, MAP_SHARED_, mfd, 0);
            if (addr < 0 || (unsigned long)addr >= (unsigned long)-4095) {
                rw = 0;
                addr = raw_syscall(__NR_mmap, 0, (long)sz, PROT_READ_, MAP_SHARED_, mfd, 0);
            }
            raw_syscall(__NR_close, mfd, 0, 0, 0, 0, 0);
            if (addr >= 0 && (unsigned long)addr < (unsigned long)-4095) {
                struct sv_net_state *st = (struct sv_net_state *)addr;
                if (st->magic == SV_NET_STATE_MAGIC && st->version == SV_NET_STATE_VERSION) {
                    hook_note_internal((uintptr_t)addr, sz);
                    g_net_state_rw = rw;
                    __atomic_store_n(&g_net_state, st, __ATOMIC_RELEASE);
                    cur = st;
                } else {
                    raw_syscall(__NR_munmap, addr, (long)sz, 0, 0, 0, 0);
                }
            }
        } else if (mfd >= 0) {
            raw_syscall(__NR_close, mfd, 0, 0, 0, 0, 0);
        }
    }
    ns_unlock();
    return cur;
}

/* ---- Local FD tracking (virtual netlink & SO_MARK/SO_BINDTODEVICE) ---- */

static struct ns_nl_slot *nl_find(int fd)
{
    if (fd < 0) return NULL;
    for (int i = 0; i < NS_MAX_NL_FDS; i++) {
        if (g_nl_fds[i].active && g_nl_fds[i].fd == fd)
            return &g_nl_fds[i];
    }
    return NULL;
}

static void nl_clear_fd(int fd)
{
    if (fd < 0 || __atomic_load_n(&g_nl_active_count, __ATOMIC_RELAXED) == 0)
        return;
    ns_lock();
    int removed = 0;
    for (int i = 0; i < NS_MAX_NL_FDS; i++) {
        if (g_nl_fds[i].active && g_nl_fds[i].fd == fd) {
            g_nl_fds[i].active = 0;
            g_nl_fds[i].fd = -1;
            removed++;
        }
    }
    if (removed > 0)
        __atomic_sub_fetch(&g_nl_active_count, removed, __ATOMIC_RELEASE);
    ns_unlock();
}

static void nl_register(int fd, uint32_t nl_id, uint32_t groups, uint32_t pid)
{
    ns_lock();
    int free_idx = -1;
    int existed = 0;
    for (int i = 0; i < NS_MAX_NL_FDS; i++) {
        if (g_nl_fds[i].active && g_nl_fds[i].fd == fd) {
            free_idx = i;
            existed = 1;
            break;
        }
        if (!g_nl_fds[i].active && free_idx < 0)
            free_idx = i;
    }
    if (free_idx >= 0) {
        g_nl_fds[free_idx].active = 1;
        g_nl_fds[free_idx].fd = fd;
        g_nl_fds[free_idx].nl_id = nl_id;
        g_nl_fds[free_idx].nl_groups = groups;
        g_nl_fds[free_idx].nl_pid = pid;
        if (!existed)
            __atomic_add_fetch(&g_nl_active_count, 1, __ATOMIC_RELEASE);
    }
    ns_unlock();
}

static int mark_grow_locked(void)
{
    if (g_mark_cap >= NS_MARK_MAX_CAP)
        return -1;
    int new_cap = g_mark_cap * 4;
    if (new_cap < 256) new_cap = 256;
    if (new_cap > NS_MARK_MAX_CAP) new_cap = NS_MARK_MAX_CAP;
    size_t raw_bytes = (size_t)new_cap * sizeof(struct ns_mark_slot);
    size_t map_bytes = (raw_bytes + 4095u) & ~(size_t)4095u;
    long addr = raw_syscall(__NR_mmap, 0, (long)map_bytes, PROT_READ_ | PROT_WRITE_,
                            MAP_PRIVATE_ | MAP_ANONYMOUS_, -1, 0);
    if (addr < 0 || (unsigned long)addr >= (unsigned long)-4095)
        return -1;
    struct ns_mark_slot *ntbl = (struct ns_mark_slot *)addr;
    memcpy(ntbl, g_mark_fds, (size_t)g_mark_cap * sizeof(struct ns_mark_slot));
    if (g_mark_fds != g_mark_inline && g_mark_mmap_bytes > 0)
        raw_syscall(__NR_munmap, (long)g_mark_fds, (long)g_mark_mmap_bytes, 0, 0, 0, 0);
    g_mark_fds = ntbl;
    g_mark_cap = new_cap;
    g_mark_mmap_bytes = map_bytes;
    return 0;
}

static struct ns_mark_slot *mark_find_locked(int fd, int create)
{
    if (fd < 0) return NULL;
    int free_idx = -1;
    for (int i = 0; i < g_mark_cap; i++) {
        if (g_mark_fds[i].active && g_mark_fds[i].fd == fd)
            return &g_mark_fds[i];
        if (!g_mark_fds[i].active && free_idx < 0)
            free_idx = i;
    }
    if (create) {
        if (free_idx < 0) {
            int old_cap = g_mark_cap;
            if (mark_grow_locked() < 0)
                return NULL;
            free_idx = old_cap;
        }
        memset(&g_mark_fds[free_idx], 0, sizeof(g_mark_fds[free_idx]));
        g_mark_fds[free_idx].active = 1;
        g_mark_fds[free_idx].fd = fd;
        __atomic_add_fetch(&g_mark_active_count, 1, __ATOMIC_RELEASE);
        return &g_mark_fds[free_idx];
    }
    return NULL;
}

static void mark_clear_fd(int fd)
{
    if (fd < 0 || __atomic_load_n(&g_mark_active_count, __ATOMIC_RELAXED) == 0)
        return;
    ns_lock();
    int removed = 0;
    for (int i = 0; i < g_mark_cap; i++) {
        if (g_mark_fds[i].active && g_mark_fds[i].fd == fd) {
            g_mark_fds[i].active = 0;
            g_mark_fds[i].fd = -1;
            removed++;
        }
    }
    if (removed > 0)
        __atomic_sub_fetch(&g_mark_active_count, removed, __ATOMIC_RELEASE);
    ns_unlock();
}

static int mark_is_bypass(int fd)
{
    if (fd < 0 || __atomic_load_n(&g_mark_active_count, __ATOMIC_RELAXED) == 0)
        return 0;
    int bypass = 0;
    ns_lock();
    struct ns_mark_slot *s = mark_find_locked(fd, 0);
    if (s && s->bypass)
        bypass = 1;
    ns_unlock();
    return bypass;
}

static void dup_tracked_fd(int oldfd, int newfd)
{
    if (oldfd < 0 || newfd < 0 || oldfd == newfd)
        return;
    if (__atomic_load_n(&g_nl_active_count, __ATOMIC_RELAXED) == 0 &&
        __atomic_load_n(&g_mark_active_count, __ATOMIC_RELAXED) == 0)
        return;
    ns_lock();
    struct ns_nl_slot nl_copy;
    int has_nl = 0;
    for (int i = 0; i < NS_MAX_NL_FDS; i++) {
        if (g_nl_fds[i].active && g_nl_fds[i].fd == oldfd) {
            nl_copy = g_nl_fds[i];
            has_nl = 1;
            break;
        }
    }
    struct ns_mark_slot mk_copy;
    int has_mk = 0;
    for (int i = 0; i < g_mark_cap; i++) {
        if (g_mark_fds[i].active && g_mark_fds[i].fd == oldfd) {
            mk_copy = g_mark_fds[i];
            has_mk = 1;
            break;
        }
    }
    /* Clear any prior slot at newfd. */
    for (int i = 0; i < NS_MAX_NL_FDS; i++) {
        if (g_nl_fds[i].active && g_nl_fds[i].fd == newfd) {
            g_nl_fds[i].active = 0;
            __atomic_sub_fetch(&g_nl_active_count, 1, __ATOMIC_RELEASE);
        }
    }
    for (int i = 0; i < g_mark_cap; i++) {
        if (g_mark_fds[i].active && g_mark_fds[i].fd == newfd) {
            g_mark_fds[i].active = 0;
            __atomic_sub_fetch(&g_mark_active_count, 1, __ATOMIC_RELEASE);
        }
    }
    if (has_nl) {
        for (int i = 0; i < NS_MAX_NL_FDS; i++) {
            if (!g_nl_fds[i].active) {
                g_nl_fds[i] = nl_copy;
                g_nl_fds[i].fd = newfd;
                __atomic_add_fetch(&g_nl_active_count, 1, __ATOMIC_RELEASE);
                break;
            }
        }
    }
    if (has_mk) {
        struct ns_mark_slot *dst = mark_find_locked(newfd, 1);
        if (dst) {
            *dst = mk_copy;
            dst->fd = newfd;
        }
    }
    ns_unlock();
}

static void register_protect_fd_ino(int fd)
{
    struct stat st;
    memset(&st, 0, sizeof(st));
    if (raw_syscall(__NR_fstat, fd, (long)&st, 0, 0, 0, 0) == 0 && st.st_ino != 0)
        ns_rpc(NET_OP_PROTECT_INO, 0, (uint64_t)st.st_ino, 0, NULL, 0, NULL, 0, NULL, NULL, NULL);
}

static int iface_is_tun_name(const struct sv_net_state *st, const char *name)
{
    if (!st || !name || !name[0])
        return 0;
    for (int i = 0; i < SV_NET_MAX_IFACES; i++) {
        if (st->ifaces[i].active && strcmp(st->ifaces[i].name, name) == 0)
            return st->ifaces[i].is_tun ? 1 : 0;
    }
    return (strncmp(name, "tun", 3) == 0);
}

/* ---- Address & Route Helpers ---- */

static int extract_v4_from_v6(const uint8_t a[16], uint32_t *out_net_ip)
{
    static const uint8_t mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    for (int i = 0; i < 12; i++) {
        if (a[i] != mapped[i])
            return 0;
    }
    memcpy(out_net_ip, a + 12, 4);
    return 1;
}

static void make_v4_mapped(uint32_t net_ip, uint8_t a[16])
{
    memset(a, 0, 10);
    a[10] = 0xff;
    a[11] = 0xff;
    memcpy(a + 12, &net_ip, 4);
}

static int is_v6_loopback_or_unspec(const uint8_t a[16])
{
    for (int i = 0; i < 15; i++) {
        if (a[i] != 0)
            return 0;
    }
    return (a[15] == 0 || a[15] == 1);
}

static int is_v4_loopback_or_unspec(uint32_t net_ip)
{
    uint32_t h = ns_be32(net_ip);
    if (h == 0 || (h >> 24) == 127u)
        return 1;
    return 0;
}

static int sockaddr_is_loopback(const void *sa, unsigned len)
{
    if (!sa || len < 8)
        return 0;
    uint16_t fam = 0;
    memcpy(&fam, sa, 2);
    if (fam == AF_INET_) {
        uint32_t ip4 = 0;
        memcpy(&ip4, (const uint8_t *)sa + 4, 4);
        return is_v4_loopback_or_unspec(ip4);
    }
    if (fam == AF_INET6_ && len >= 24) {
        const uint8_t *a6 = (const uint8_t *)sa + 8;
        uint32_t ip4 = 0;
        if (extract_v4_from_v6(a6, &ip4))
            return is_v4_loopback_or_unspec(ip4);
        return is_v6_loopback_or_unspec(a6);
    }
    return 0;
}

static int sockaddr_is_explicit_loopback(const void *sa, unsigned len)
{
    if (!sa || len < 8)
        return 0;
    uint16_t fam = 0;
    memcpy(&fam, sa, 2);
    if (fam == AF_INET_) {
        uint32_t ip4 = 0;
        memcpy(&ip4, (const uint8_t *)sa + 4, 4);
        return (ns_be32(ip4) >> 24) == 127u;
    }
    if (fam == AF_INET6_ && len >= 24) {
        const uint8_t *a6 = (const uint8_t *)sa + 8;
        uint32_t ip4 = 0;
        if (extract_v4_from_v6(a6, &ip4))
            return (ns_be32(ip4) >> 24) == 127u;
        return is_v6_loopback_or_unspec(a6) && a6[15] == 1;
    }
    return 0;
}

static void net_account_io(int is_lo, int is_tx, uint64_t bytes)
{
    if (!bytes)
        return;
    struct sv_net_state *st = __atomic_load_n(&g_net_state, __ATOMIC_ACQUIRE);
    if (!st)
        st = (struct sv_net_state *)net_stack_state();
    if (!st || !g_net_state_rw)
        return;
    struct sv_net_iface *target = NULL;
    for (int i = 0; i < SV_NET_MAX_IFACES; i++) {
        struct sv_net_iface *f = &st->ifaces[i];
        if (!f->active || !(f->flags & SV_IFF_UP))
            continue;
        if (is_lo) {
            if (f->flags & SV_IFF_LOOPBACK) {
                target = f;
                break;
            }
        } else {
            if (!(f->flags & SV_IFF_LOOPBACK) && !f->is_tun) {
                target = f;
                break;
            }
        }
    }
    if (!target)
        return;
    uint64_t pkts = (bytes + 1459ull) / 1460ull;
    if (is_tx) {
        __atomic_fetch_add(&target->tx_bytes, bytes, __ATOMIC_RELAXED);
        __atomic_fetch_add(&target->tx_packets, pkts, __ATOMIC_RELAXED);
    } else {
        __atomic_fetch_add(&target->rx_bytes, bytes, __ATOMIC_RELAXED);
        __atomic_fetch_add(&target->rx_packets, pkts, __ATOMIC_RELAXED);
    }
}

static int uid_routed_to_tun(const struct sv_net_state *st)
{
    uint32_t mode = st->uid_mode;
    if (mode == 0)
        return 1;
    uint32_t uid = fake_ids_effective(0);
    uint32_t cnt = st->uid_rule_count;
    if (cnt > SV_NET_MAX_UID_RULES)
        cnt = SV_NET_MAX_UID_RULES;
    int matched = 0;
    for (uint32_t i = 0; i < cnt; i++) {
        if (uid >= st->uid_ranges[i].start && uid <= st->uid_ranges[i].stop) {
            matched = 1;
            break;
        }
    }
    if (mode == 1)
        return matched; /* allowlist: only matching UIDs go through TUN */
    return !matched;    /* disallowlist: matching UIDs bypass TUN */
}

static int is_fd_protected(const struct sv_net_state *st, int fd)
{
    if (mark_is_bypass(fd))
        return 1;
    if (!uid_routed_to_tun(st))
        return 1;
    struct stat stbuf;
    memset(&stbuf, 0, sizeof(stbuf));
    if (raw_syscall(__NR_fstat, fd, (long)&stbuf, 0, 0, 0, 0) == 0 && stbuf.st_ino != 0) {
        uint64_t ino = (uint64_t)stbuf.st_ino;
        for (int i = 0; i < SV_NET_PROTECT_CAP; i++) {
            if (st->protected_inos[i] == ino)
                return 1;
        }
    }
    return 0;
}

static const struct sv_net_iface *find_iface_by_index(const struct sv_net_state *st, uint32_t ifindex)
{
    for (int i = 0; i < SV_NET_MAX_IFACES; i++) {
        if (st->ifaces[i].active && st->ifaces[i].ifindex == ifindex)
            return &st->ifaces[i];
    }
    return NULL;
}

/* Longest-prefix match route lookup (tie-break by lowest metric). Returns
 * winning TUN ifindex (>0) if traffic should go through a TUN interface, else 0. */
static uint32_t lookup_tun_route4(const struct sv_net_state *st, uint32_t dst_net)
{
    int best_prefix = -1;
    uint32_t best_metric = 0xffffffffu;
    uint32_t best_ifindex = 0;
    for (int i = 0; i < SV_NET_MAX_ROUTES; i++) {
        const struct sv_net_route4 *r = &st->routes[i];
        if (!r->active)
            continue;
        if ((dst_net & r->mask) != (r->dst & r->mask))
            continue;
        int pfx = (int)r->prefix;
        if (pfx > best_prefix || (pfx == best_prefix && r->metric < best_metric)) {
            best_prefix = pfx;
            best_metric = r->metric;
            best_ifindex = r->ifindex;
        }
    }
    if (!best_ifindex)
        return 0;
    const struct sv_net_iface *ifc = find_iface_by_index(st, best_ifindex);
    if (!ifc || !ifc->is_tun || !(ifc->flags & SV_IFF_UP))
        return 0;
    return best_ifindex;
}

static int v6_prefix_match(const uint8_t dst[16], const uint8_t net[16], uint32_t prefix)
{
    if (prefix > 128) prefix = 128;
    uint32_t full = prefix / 8;
    uint32_t rem = prefix % 8;
    for (uint32_t i = 0; i < full; i++) {
        if (dst[i] != net[i]) return 0;
    }
    if (rem > 0) {
        uint8_t mask = (uint8_t)(0xffu << (8 - rem));
        if ((dst[full] & mask) != (net[full] & mask)) return 0;
    }
    return 1;
}

static uint32_t lookup_tun_route6(const struct sv_net_state *st, const uint8_t dst[16])
{
    int best_prefix = -1;
    uint32_t best_metric = 0xffffffffu;
    uint32_t best_ifindex = 0;
    for (int i = 0; i < SV_NET_MAX_ROUTES6; i++) {
        const struct sv_net_route6 *r = &st->routes6[i];
        if (!r->active)
            continue;
        if (!v6_prefix_match(dst, r->dst, r->prefix))
            continue;
        int pfx = (int)r->prefix;
        if (pfx > best_prefix || (pfx == best_prefix && r->metric < best_metric)) {
            best_prefix = pfx;
            best_metric = r->metric;
            best_ifindex = r->ifindex;
        }
    }
    if (!best_ifindex)
        return 0;
    const struct sv_net_iface *ifc = find_iface_by_index(st, best_ifindex);
    if (!ifc || !ifc->is_tun || !(ifc->flags & SV_IFF_UP))
        return 0;
    return best_ifindex;
}

/* Bind socket to loopback ephemeral port if not yet bound and return port (host order). */
static int ensure_loopback_bind(int fd, int sock_family, int use_v6_loop, uint16_t *port_out)
{
    unsigned char name[128];
    unsigned nlen = sizeof(name);
    if (raw_syscall(__NR_getsockname, fd, (long)name, (long)&nlen, 0, 0, 0) == 0 && nlen >= 8) {
        uint16_t fam = 0, p = 0;
        memcpy(&fam, name, 2);
        memcpy(&p, name + 2, 2);
        if (p != 0) {
            *port_out = ns_be16(p);
            return 0;
        }
    }
    if (sock_family == AF_INET_) {
        struct ns_sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET_;
        a.sin_addr = ns_be32(0x7f000001u);
        long rc = raw_syscall(__NR_bind, fd, (long)&a, sizeof(a), 0, 0, 0);
        if (rc < 0 && rc != -EINVAL)
            return (int)rc;
    } else if (sock_family == AF_INET6_) {
        struct ns_sockaddr_in6 a6;
        memset(&a6, 0, sizeof(a6));
        a6.sin6_family = AF_INET6_;
        if (use_v6_loop) {
            a6.sin6_addr[15] = 1; /* ::1 */
        } else {
            int off = 0;
            raw_syscall(__NR_setsockopt, fd, IPPROTO_IPV6_, IPV6_V6ONLY_, (long)&off, sizeof(off), 0);
            make_v4_mapped(ns_be32(0x7f000001u), a6.sin6_addr);
        }
        long rc = raw_syscall(__NR_bind, fd, (long)&a6, sizeof(a6), 0, 0, 0);
        if (rc < 0 && rc != -EINVAL)
            return (int)rc;
    } else {
        return -EAFNOSUPPORT;
    }
    nlen = sizeof(name);
    if (raw_syscall(__NR_getsockname, fd, (long)name, (long)&nlen, 0, 0, 0) < 0 || nlen < 8)
        return -EINVAL;
    uint16_t p = 0;
    memcpy(&p, name + 2, 2);
    *port_out = ns_be16(p);
    return *port_out ? 0 : -EINVAL;
}

static void fill_loopback_sockaddr(int sock_family, int use_v6_loop, uint16_t port_host,
                                   unsigned char out[128], unsigned *out_len)
{
    memset(out, 0, 128);
    if (sock_family == AF_INET_) {
        struct ns_sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET_;
        a.sin_port = ns_be16(port_host);
        a.sin_addr = ns_be32(0x7f000001u);
        memcpy(out, &a, sizeof(a));
        *out_len = sizeof(a);
    } else {
        struct ns_sockaddr_in6 a6;
        memset(&a6, 0, sizeof(a6));
        a6.sin6_family = AF_INET6_;
        a6.sin6_port = ns_be16(port_host);
        if (use_v6_loop)
            a6.sin6_addr[15] = 1;
        else
            make_v4_mapped(ns_be32(0x7f000001u), a6.sin6_addr);
        memcpy(out, &a6, sizeof(a6));
        *out_len = sizeof(a6);
    }
}

/* ---- SIOC* Virtual Interface / Route Ioctls ---- */

static int handle_sioc_ioctl(unsigned long cmd, unsigned long arg, long *out)
{
    uint32_t c32 = (uint32_t)cmd;
    if (c32 == SV_SIOCGIFCONF) {
        if (!arg) { *out = -EFAULT; return 1; }
        const struct sv_net_state *st = net_stack_state();
        if (!st) return 0;
        struct { int32_t ifc_len; int32_t _pad; uint8_t *ifc_buf; } ifc;
        memcpy(&ifc, (const void *)arg, sizeof(ifc));
        int32_t needed = 0;
        int32_t written = 0;
        for (int i = 0; i < SV_NET_MAX_IFACES; i++) {
            const struct sv_net_iface *f = &st->ifaces[i];
            if (!f->active || !(f->flags & SV_IFF_UP) || f->ipv4_addr == 0)
                continue;
            needed += 40;
            if (ifc.ifc_buf && written + 40 <= ifc.ifc_len) {
                uint8_t ifr[40];
                memset(ifr, 0, sizeof(ifr));
                memcpy(ifr, f->name, 16);
                struct ns_sockaddr_in sa;
                memset(&sa, 0, sizeof(sa));
                sa.sin_family = AF_INET_;
                sa.sin_addr = f->ipv4_addr;
                memcpy(ifr + 16, &sa, sizeof(sa));
                memcpy(ifc.ifc_buf + written, ifr, 40);
                written += 40;
            }
        }
        ifc.ifc_len = ifc.ifc_buf ? written : needed;
        memcpy((void *)arg, &ifc, sizeof(ifc));
        *out = 0;
        return 1;
    }

    int is_rt = (c32 == SV_SIOCADDRT || c32 == SV_SIOCDELRT);
    int is_if = (c32 == SV_SIOCGIFNAME || c32 == SV_SIOCGIFFLAGS || c32 == SV_SIOCSIFFLAGS ||
                 c32 == SV_SIOCGIFADDR || c32 == SV_SIOCSIFADDR ||
                 c32 == SV_SIOCGIFDSTADDR || c32 == SV_SIOCSIFDSTADDR ||
                 c32 == SV_SIOCGIFBRDADDR || c32 == SV_SIOCGIFNETMASK || c32 == SV_SIOCSIFNETMASK ||
                 c32 == SV_SIOCGIFMTU || c32 == SV_SIOCSIFMTU ||
                 c32 == SV_SIOCGIFHWADDR || c32 == SV_SIOCGIFINDEX ||
                 c32 == SV_SIOCGIFTXQLEN || c32 == SV_SIOCSIFTXQLEN);
    if (!is_rt && !is_if)
        return 0;
    if (!arg) {
        *out = -EFAULT;
        return 1;
    }

    uint8_t buf[sizeof(struct sv_net_sioc_req) + 144];
    struct sv_net_sioc_req *req = (struct sv_net_sioc_req *)buf;
    req->cmd = c32;
    if (is_if) {
        req->data_len = 40;
        memcpy(buf + sizeof(*req), (const void *)arg, 40);
    } else {
        /* 120B struct rtentry + 16B copied rt_dev string. */
        req->data_len = 136;
        memcpy(buf + sizeof(*req), (const void *)arg, 120);
        char *dev_out = (char *)(buf + sizeof(*req) + 120);
        memset(dev_out, 0, 16);
        const char *rt_dev = NULL;
        memcpy(&rt_dev, (const uint8_t *)arg + 88, sizeof(rt_dev));
        if (rt_dev) {
            size_t dlen = strnlen(rt_dev, 15);
            memcpy(dev_out, rt_dev, dlen);
        }
    }

    uint8_t rep_data[64];
    uint32_t rep_len = 0;
    long rc = ns_rpc(NET_OP_SIOC, 0, 0, 0, buf, (uint32_t)(sizeof(*req) + req->data_len),
                     rep_data, sizeof(rep_data), &rep_len, NULL, NULL);
    if (rc >= 0 && is_if && rep_len >= 40)
        memcpy((void *)arg, rep_data, 40);
    *out = rc;
    return 1;
}

/* ---- Pre-Syscall Dispatch Hook ---- */

int net_stack_pre_syscall(long number, long a[6], long *out)
{
    if (!net_stack_enabled())
        return 0;

    /* 1. Virtual AF_NETLINK / NETLINK_ROUTE socket creation. */
    if (number == __NR_socket && a[0] == AF_NETLINK_ && a[2] == NETLINK_ROUTE_) {
        struct vdev_hdr rep;
        int nfd = -1;
        uint32_t my_pid = (uint32_t)raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
        long rc = ns_rpc(NET_OP_OPEN_NETLINK, 0, (uint64_t)my_pid,
                         0, NULL, 0, NULL, 0, NULL, &rep, &nfd);
        if (rc < 0 || nfd < 0) {
            if (nfd >= 0) raw_syscall(__NR_close, nfd, 0, 0, 0, 0, 0);
            return 0; /* Fall back to host kernel if daemon unavailable. */
        }
        if (!(a[1] & SOCK_CLOEXEC_))
            raw_syscall(__NR_fcntl, nfd, F_SETFD_, 0, 0, 0, 0);
        if (a[1] & SOCK_NONBLOCK_) {
            long fl = raw_syscall(__NR_fcntl, nfd, F_GETFL_, 0, 0, 0, 0);
            if (fl >= 0)
                raw_syscall(__NR_fcntl, nfd, F_SETFL_, fl | O_NONBLOCK, 0, 0, 0);
        }
        nl_register(nfd, rep.proc_id, 0, my_pid);
        *out = nfd;
        return 1;
    }

    /* 2. Close: clear local tracking tables (let kernel perform close). */
    if (number == __NR_close) {
        nl_clear_fd((int)a[0]);
        mark_clear_fd((int)a[0]);
        inet_fd_clear(g_inet_fds, (int)a[0]);
        inet_fd_clear(g_inet_lo_fds, (int)a[0]);
        return 0;
    }

    /* 3. Virtual Netlink FD operations. */
    if (__atomic_load_n(&g_nl_active_count, __ATOMIC_RELAXED) > 0 &&
        (number == __NR_bind || number == __NR_connect ||
         number == __NR_getsockname || number == __NR_getpeername ||
         number == __NR_sendto || number == __NR_sendmsg ||
         number == __NR_setsockopt ||
         number == __NR_recvfrom || number == __NR_recvmsg)) {
        ns_lock();
        struct ns_nl_slot *nls = nl_find((int)a[0]);
        struct ns_nl_slot nl_copy;
        int is_nl = 0;
        if (nls) {
            nl_copy = *nls;
            is_nl = 1;
        }
        ns_unlock();
        if (is_nl) {
            if (number == __NR_bind) {
                uint32_t groups = 0;
                uint32_t req_pid = 0;
                if (a[1] && (unsigned long)a[2] >= sizeof(struct ns_sockaddr_nl)) {
                    struct ns_sockaddr_nl sa;
                    memcpy(&sa, (const void *)a[1], sizeof(sa));
                    groups = sa.nl_groups;
                    req_pid = sa.nl_pid;
                }
                uint32_t bound_pid = req_pid ? req_pid
                                             : (uint32_t)raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
                nl_register((int)a[0], nl_copy.nl_id, groups, bound_pid);
                if (groups != 0 || bound_pid != nl_copy.nl_pid)
                    ns_rpc(NET_OP_NL_BIND, nl_copy.nl_id, groups, bound_pid,
                           NULL, 0, NULL, 0, NULL, NULL, NULL);
                *out = 0;
                return 1;
            }
            if (number == __NR_connect) {
                if (!a[1] || (unsigned long)a[2] < sizeof(struct ns_sockaddr_nl)) {
                    *out = -EINVAL;
                    return 1;
                }
                struct ns_sockaddr_nl sa;
                memcpy(&sa, (const void *)a[1], sizeof(sa));
                if (sa.nl_family != AF_NETLINK_ && sa.nl_family != 0) {
                    *out = -EAFNOSUPPORT;
                    return 1;
                }
                *out = 0;
                return 1;
            }
            if (number == __NR_getpeername) {
                if (!a[1] || !a[2]) { *out = -EFAULT; return 1; }
                struct ns_sockaddr_nl sa = { AF_NETLINK_, 0, 0, 0 };
                unsigned cap = *(unsigned *)a[2];
                unsigned cp = cap < sizeof(sa) ? cap : (unsigned)sizeof(sa);
                memcpy((void *)a[1], &sa, cp);
                *(unsigned *)a[2] = sizeof(sa);
                *out = 0;
                return 1;
            }
            if (number == __NR_getsockname) {
                if (!a[1] || !a[2]) { *out = -EFAULT; return 1; }
                struct ns_sockaddr_nl sa;
                sa.nl_family = AF_NETLINK_;
                sa.nl_pad = 0;
                sa.nl_pid = nl_copy.nl_pid ? nl_copy.nl_pid
                                           : (uint32_t)raw_syscall(__NR_getpid, 0, 0, 0, 0, 0, 0);
                sa.nl_groups = nl_copy.nl_groups;
                unsigned cap = *(unsigned *)a[2];
                unsigned cp = cap < sizeof(sa) ? cap : (unsigned)sizeof(sa);
                memcpy((void *)a[1], &sa, cp);
                *(unsigned *)a[2] = sizeof(sa);
                *out = 0;
                return 1;
            }
            if (number == __NR_setsockopt) {
                if (a[1] == SOL_NETLINK_) {
                    *out = 0;
                    return 1;
                }
                return 0; /* SOL_SOCKET (SO_RCVBUF, etc.) passes to kernel SOCK_SEQPACKET. */
            }
            if (number == __NR_sendto) {
                *out = raw_syscall(__NR_sendto, a[0], a[1], a[2], a[3], 0, 0);
                return 1;
            }
            if (number == __NR_sendmsg) {
                if (!a[1]) { *out = -EFAULT; return 1; }
                struct ns_msghdr m;
                memcpy(&m, (const void *)a[1], sizeof(m));
                m.msg_name = NULL;
                m.msg_namelen = 0;
                *out = raw_syscall(__NR_sendmsg, a[0], (long)&m, a[2], 0, 0, 0);
                return 1;
            }
            if (number == __NR_recvfrom) {
                unsigned orig_cap = (a[4] && a[5]) ? *(unsigned *)a[5] : 0u;
                long r = raw_syscall(__NR_recvfrom, a[0], a[1], a[2], a[3], 0, 0);
                if (r >= 0 && a[4] && a[5]) {
                    struct ns_sockaddr_nl nl = { AF_NETLINK_, 0, 0, 0 };
                    unsigned cp = orig_cap < sizeof(nl) ? orig_cap : (unsigned)sizeof(nl);
                    if (cp > 0) memcpy((void *)a[4], &nl, cp);
                    *(unsigned *)a[5] = sizeof(nl);
                }
                *out = r;
                return 1;
            }
            if (number == __NR_recvmsg) {
                if (!a[1]) { *out = -EFAULT; return 1; }
                struct ns_msghdr *um = (struct ns_msghdr *)a[1];
                void *orig_name = um->msg_name;
                uint32_t orig_cap = um->msg_namelen;
                struct ns_msghdr m = *um;
                m.msg_name = NULL;
                m.msg_namelen = 0;
                long r = raw_syscall(__NR_recvmsg, a[0], (long)&m, a[2], 0, 0, 0);
                if (r >= 0) {
                    um->msg_flags = m.msg_flags;
                    um->msg_controllen = m.msg_controllen;
                    if (orig_name && orig_cap > 0) {
                        struct ns_sockaddr_nl nl = { AF_NETLINK_, 0, 0, 0 };
                        unsigned cp = orig_cap < sizeof(nl) ? orig_cap : (unsigned)sizeof(nl);
                        memcpy(orig_name, &nl, cp);
                        um->msg_namelen = sizeof(nl);
                    } else {
                        um->msg_namelen = 0;
                    }
                }
                *out = r;
                return 1;
            }
        }
    }

    /* 4. Unprivileged SO_MARK & SO_BINDTODEVICE interception (for TUN bypass). */
    if (number == __NR_setsockopt && a[1] == SOL_SOCKET_ &&
        (a[2] == SO_MARK_ || a[2] == SO_BINDTODEVICE_)) {
        int fd = (int)a[0];
        if (a[2] == SO_MARK_) {
            if (!a[3] || (unsigned long)a[4] < 4) { *out = -EINVAL; return 1; }
            uint32_t mark = 0;
            memcpy(&mark, (const void *)a[3], 4);
            ns_lock();
            struct ns_mark_slot *s = mark_find_locked(fd, 1);
            if (s) {
                s->mark = mark;
                s->bypass = (mark != 0) ? 1 : (s->bind_dev[0] != '\0' ? 1 : 0);
            }
            ns_unlock();
            if (mark != 0)
                register_protect_fd_ino(fd);
            *out = 0;
            return 1;
        }
        if (a[2] == SO_BINDTODEVICE_) {
            char dev[16];
            memset(dev, 0, sizeof(dev));
            if (a[3] && a[4] > 0) {
                size_t n = (size_t)a[4] < 15 ? (size_t)a[4] : 15;
                memcpy(dev, (const void *)a[3], n);
                dev[15] = '\0';
            }
            const struct sv_net_state *st = net_stack_state();
            int bypass = (dev[0] != '\0' && !iface_is_tun_name(st, dev)) ? 1 : 0;
            ns_lock();
            struct ns_mark_slot *s = mark_find_locked(fd, 1);
            if (s) {
                memcpy(s->bind_dev, dev, sizeof(s->bind_dev));
                s->bypass = bypass || (s->mark != 0);
            }
            ns_unlock();
            if (bypass)
                register_protect_fd_ino(fd);
            *out = 0;
            return 1;
        }
    }

    if (number == __NR_getsockopt && a[1] == SOL_SOCKET_ &&
        (a[2] == SO_MARK_ || a[2] == SO_BINDTODEVICE_)) {
        int fd = (int)a[0];
        if (!a[3] || !a[4]) { *out = -EFAULT; return 1; }
        unsigned cap = *(unsigned *)a[4];
        if (a[2] == SO_MARK_) {
            if (cap < 4) { *out = -EINVAL; return 1; }
            uint32_t mark = 0;
            ns_lock();
            struct ns_mark_slot *s = mark_find_locked(fd, 0);
            if (s) mark = s->mark;
            ns_unlock();
            memcpy((void *)a[3], &mark, 4);
            *(unsigned *)a[4] = 4;
            *out = 0;
            return 1;
        }
        if (a[2] == SO_BINDTODEVICE_) {
            char dev[16];
            memset(dev, 0, sizeof(dev));
            ns_lock();
            struct ns_mark_slot *s = mark_find_locked(fd, 0);
            if (s) memcpy(dev, s->bind_dev, sizeof(dev));
            ns_unlock();
            size_t len = dev[0] ? strlen(dev) + 1 : 0;
            if (len > cap) { *out = -EINVAL; return 1; }
            if (len > 0) memcpy((void *)a[3], dev, len);
            *(unsigned *)a[4] = (unsigned)len;
            *out = 0;
            return 1;
        }
    }

    /* 5. SIOC* virtual interface / route ioctls. */
    if (number == __NR_ioctl)
        return handle_sioc_ioctl((unsigned long)a[1], (unsigned long)a[2], out);

    /* 5b. Record loopback vs external peer on AF_INET/AF_INET6 connect() or bind(). */
    if (number == __NR_connect && inet_fd_test(g_inet_fds, (int)a[0]) && a[1] && (unsigned)a[2] >= 8u) {
        if (sockaddr_is_loopback((const void *)a[1], (unsigned)a[2]))
            inet_fd_set(g_inet_lo_fds, (int)a[0]);
        else
            inet_fd_clear(g_inet_lo_fds, (int)a[0]);
    } else if (number == __NR_bind && inet_fd_test(g_inet_fds, (int)a[0]) && a[1] && (unsigned)a[2] >= 8u) {
        if (sockaddr_is_explicit_loopback((const void *)a[1], (unsigned)a[2]))
            inet_fd_set(g_inet_lo_fds, (int)a[0]);
    }

    /* 6. Transparent TCP / UDP redirection when a TUN route is active. */
    if (number == __NR_connect || number == __NR_sendto || number == __NR_sendmsg) {
        const struct sv_net_state *st = net_stack_state();
        if (!st || !st->tun_active)
            return 0; /* Fast path: zero overhead when no TUN route is active. */

        int fd = (int)a[0];
        const void *name = NULL;
        unsigned namelen = 0;
        struct ns_msghdr msg_copy;
        if (number == __NR_connect) {
            name = (const void *)a[1];
            namelen = (unsigned)a[2];
        } else if (number == __NR_sendto) {
            name = (const void *)a[4];
            namelen = (unsigned)a[5];
        } else {
            if (!a[1]) return 0;
            memcpy(&msg_copy, (const void *)a[1], sizeof(msg_copy));
            name = msg_copy.msg_name;
            namelen = msg_copy.msg_namelen;
        }
        if (!name || namelen < 8)
            return 0;

        uint16_t fam = 0;
        memcpy(&fam, name, 2);
        if (fam != AF_INET_ && fam != AF_INET6_)
            return 0;

        int is_v6 = 0;
        uint32_t dst_v4 = 0;
        uint8_t dst_v6[16];
        uint16_t dst_port = 0;
        memset(dst_v6, 0, sizeof(dst_v6));

        if (fam == AF_INET_) {
            if (namelen < 8) return 0;
            struct ns_sockaddr_in sa4;
            memcpy(&sa4, name, 8);
            dst_v4 = sa4.sin_addr;
            dst_port = ns_be16(sa4.sin_port);
            if (is_v4_loopback_or_unspec(dst_v4))
                return 0;
        } else {
            if (namelen < 24) return 0;
            struct ns_sockaddr_in6 sa6;
            memcpy(&sa6, name, 24);
            dst_port = ns_be16(sa6.sin6_port);
            if (extract_v4_from_v6(sa6.sin6_addr, &dst_v4)) {
                if (is_v4_loopback_or_unspec(dst_v4))
                    return 0;
            } else {
                if (is_v6_loopback_or_unspec(sa6.sin6_addr))
                    return 0;
                is_v6 = 1;
                memcpy(dst_v6, sa6.sin6_addr, 16);
            }
        }
        if (dst_port == 0)
            return 0;

        uint32_t tun_if = is_v6 ? lookup_tun_route6(st, dst_v6)
                                : lookup_tun_route4(st, dst_v4);
        if (!tun_if)
            return 0;

        if (is_fd_protected(st, fd))
            return 0;

        int stype = 0;
        unsigned stlen = sizeof(stype);
        if (raw_syscall(__NR_getsockopt, fd, SOL_SOCKET_, SO_TYPE_, (long)&stype, (long)&stlen, 0) < 0)
            return 0;
        if (stype != SOCK_STREAM_ && stype != SOCK_DGRAM_)
            return 0;
        if ((number == __NR_sendto || number == __NR_sendmsg) && stype != SOCK_DGRAM_)
            return 0;

        uint16_t relay_port = 0;
        if (stype == SOCK_STREAM_) {
            relay_port = is_v6 ? st->tcp_relay_port6 : st->tcp_relay_port;
        } else if (number == __NR_connect) {
            relay_port = is_v6 ? st->udp_conn_port6 : st->udp_conn_port;
        } else {
            relay_port = is_v6 ? st->udp_encap_port6 : st->udp_encap_port;
        }
        if (!relay_port)
            return 0;

        uint16_t local_port = 0;
        int brc = ensure_loopback_bind(fd, fam, is_v6, &local_port);
        if (brc < 0) {
            *out = brc;
            return 1;
        }

        unsigned char relay_sa[128];
        unsigned relay_len = 0;
        fill_loopback_sockaddr(fam, is_v6, relay_port, relay_sa, &relay_len);

        if (number == __NR_connect) {
            struct sv_net_flow_req freq;
            memset(&freq, 0, sizeof(freq));
            freq.proto = (stype == SOCK_STREAM_) ? 6u : 17u;
            freq.is_v6 = (uint8_t)is_v6;
            freq.local_port = local_port;
            freq.dst_port = dst_port;
            freq.tun_ifindex = (uint16_t)tun_if;
            if (is_v6)
                memcpy(freq.dst_ip, dst_v6, 16);
            else
                memcpy(freq.dst_ip, &dst_v4, 4);
            long rc = ns_rpc(NET_OP_FLOW_ADD, 0, 0, 0, &freq, sizeof(freq),
                             NULL, 0, NULL, NULL, NULL);
            if (rc < 0) {
                *out = rc;
                return 1;
            }
            *out = raw_syscall(__NR_connect, fd, (long)relay_sa, relay_len, 0, 0, 0);
            return 1;
        }

        /* Unconnected UDP sendto / sendmsg: prepend 32B sv_udp_encap_hdr via scatter-gather sendmsg. */
        struct sv_udp_encap_hdr ehdr;
        memset(&ehdr, 0, sizeof(ehdr));
        ehdr.magic = SV_UDP_ENCAP_MAGIC;
        ehdr.tun_ifindex = (uint16_t)tun_if;
        ehdr.dst_port = dst_port;
        ehdr.is_v6 = (uint8_t)is_v6;
        if (is_v6)
            memcpy(ehdr.dst_ip, dst_v6, 16);
        else
            memcpy(ehdr.dst_ip, &dst_v4, 4);

        struct ns_iovec iovs[17];
        iovs[0].iov_base = &ehdr;
        iovs[0].iov_len = sizeof(ehdr);
        size_t iov_cnt = 1;
        long flags = 0;

        if (number == __NR_sendto) {
            iovs[1].iov_base = (void *)a[1];
            iovs[1].iov_len = (size_t)a[2];
            iov_cnt = 2;
            flags = a[3];
        } else {
            flags = a[2];
            size_t n = msg_copy.msg_iovlen;
            if (n > 16) n = 16;
            for (size_t i = 0; i < n; i++)
                iovs[1 + i] = msg_copy.msg_iov[i];
            iov_cnt = 1 + n;
        }
        struct ns_msghdr emsg;
        memset(&emsg, 0, sizeof(emsg));
        emsg.msg_name = relay_sa;
        emsg.msg_namelen = relay_len;
        emsg.msg_iov = iovs;
        emsg.msg_iovlen = iov_cnt;
        long sent = raw_syscall(__NR_sendmsg, fd, (long)&emsg, flags, 0, 0, 0);
        if (sent >= (long)sizeof(ehdr))
            sent -= (long)sizeof(ehdr);
        *out = sent;
        return 1;
    }

    return 0;
}

/* ---- Post-Syscall Hook (FD tracking + Peer/Local Address Restoration) ---- */

static int is_loopback_relay_port(const struct sv_net_state *st, const void *addr, unsigned len,
                                  int *is_udp_out, int *fam_out)
{
    if (!addr || len < 8)
        return 0;
    uint16_t fam = 0, port_be = 0;
    memcpy(&fam, addr, 2);
    memcpy(&port_be, (const uint8_t *)addr + 2, 2);
    uint16_t port = ns_be16(port_be);
    *fam_out = fam;
    int is_v6 = 0;
    if (fam == AF_INET_) {
        uint32_t ip = 0;
        memcpy(&ip, (const uint8_t *)addr + 4, 4);
        if (ns_be32(ip) != 0x7f000001u)
            return 0;
    } else if (fam == AF_INET6_ && len >= 24) {
        const uint8_t *a6 = (const uint8_t *)addr + 8;
        uint32_t v4 = 0;
        if (extract_v4_from_v6(a6, &v4)) {
            if (ns_be32(v4) != 0x7f000001u) return 0;
        } else {
            if (!is_v6_loopback_or_unspec(a6) || a6[15] != 1) return 0;
            is_v6 = 1;
        }
    } else {
        return 0;
    }
    if (!is_v6) {
        if (port && port == st->tcp_relay_port) { *is_udp_out = 0; return 1; }
        if (port && (port == st->udp_conn_port || port == st->udp_encap_port)) { *is_udp_out = 1; return 1; }
    } else {
        if (port && port == st->tcp_relay_port6) { *is_udp_out = 0; return 1; }
        if (port && (port == st->udp_conn_port6 || port == st->udp_encap_port6)) { *is_udp_out = 1; return 1; }
    }
    return 0;
}

static void write_restored_addr(void *dst, unsigned len, int fam, int is_v6,
                                const uint8_t ip[16], uint16_t port_host)
{
    uint16_t port_be = ns_be16(port_host);
    if (fam == AF_INET_ && len >= 8 && !is_v6) {
        memcpy((uint8_t *)dst + 2, &port_be, 2);
        memcpy((uint8_t *)dst + 4, ip, 4);
    } else if (fam == AF_INET6_ && len >= 24) {
        memcpy((uint8_t *)dst + 2, &port_be, 2);
        if (is_v6) {
            memcpy((uint8_t *)dst + 8, ip, 16);
        } else {
            uint32_t v4 = 0;
            memcpy(&v4, ip, 4);
            make_v4_mapped(v4, (uint8_t *)dst + 8);
        }
    }
}

static uint16_t query_local_port(int fd)
{
    unsigned char buf[128];
    unsigned len = sizeof(buf);
    if (raw_syscall(__NR_getsockname, fd, (long)buf, (long)&len, 0, 0, 0) < 0 || len < 8)
        return 0;
    uint16_t p = 0;
    memcpy(&p, buf + 2, 2);
    return ns_be16(p);
}

void net_stack_post_syscall(long number, long a[6], long ret, unsigned name_cap)
{
    if (!net_stack_enabled() || ret < 0)
        return;

    /* Keep FD tracking tables consistent across socket/accept/dup/fcntl. */
    if (number == __NR_socket) {
        nl_clear_fd((int)ret);
        mark_clear_fd((int)ret);
        if (a[0] == AF_INET_ || a[0] == AF_INET6_) {
            inet_fd_set(g_inet_fds, (int)ret);
            inet_fd_clear(g_inet_lo_fds, (int)ret);
        } else {
            inet_fd_clear(g_inet_fds, (int)ret);
            inet_fd_clear(g_inet_lo_fds, (int)ret);
        }
        return;
    }
    if (number == __NR_accept || number == __NR_accept4) {
        if (inet_fd_test(g_inet_fds, (int)a[0])) {
            inet_fd_set(g_inet_fds, (int)ret);
            if (a[1] && a[2] && *(unsigned *)a[2] >= 8u &&
                sockaddr_is_loopback((const void *)a[1], *(unsigned *)a[2]))
                inet_fd_set(g_inet_lo_fds, (int)ret);
            else
                inet_fd_clear(g_inet_lo_fds, (int)ret);
        } else {
            inet_fd_clear(g_inet_fds, (int)ret);
            inet_fd_clear(g_inet_lo_fds, (int)ret);
        }
        return;
    }
    if (number == __NR_dup || number == __NR_dup3 ||
        (number == __NR_fcntl && (a[1] == F_DUPFD_ || a[1] == F_DUPFD_CLOEXEC_))) {
        dup_tracked_fd((int)a[0], (int)ret);
        if (inet_fd_test(g_inet_fds, (int)a[0])) {
            inet_fd_set(g_inet_fds, (int)ret);
            if (inet_fd_test(g_inet_lo_fds, (int)a[0]))
                inet_fd_set(g_inet_lo_fds, (int)ret);
            else
                inet_fd_clear(g_inet_lo_fds, (int)ret);
        } else {
            inet_fd_clear(g_inet_fds, (int)ret);
            inet_fd_clear(g_inet_lo_fds, (int)ret);
        }
        return;
    }

    /* Zero-IPC live byte/packet accounting for AF_INET/AF_INET6 traffic. */
    if ((number == __NR_sendto || number == __NR_sendmsg ||
         number == __NR_write || number == __NR_writev) &&
        ret > 0 && inet_fd_test(g_inet_fds, (int)a[0])) {
        int is_lo = inet_fd_test(g_inet_lo_fds, (int)a[0]);
        if (number == __NR_sendto && a[4] && (unsigned)a[5] >= 8u)
            is_lo = sockaddr_is_loopback((const void *)a[4], (unsigned)a[5]);
        else if (number == __NR_sendmsg && a[1]) {
            const struct ns_msghdr *m = (const struct ns_msghdr *)a[1];
            if (m->msg_name && m->msg_namelen >= 8u)
                is_lo = sockaddr_is_loopback(m->msg_name, m->msg_namelen);
        }
        net_account_io(is_lo, 1, (uint64_t)ret);
        return;
    }
    if ((number == __NR_read || number == __NR_readv) &&
        ret > 0 && inet_fd_test(g_inet_fds, (int)a[0])) {
        net_account_io(inet_fd_test(g_inet_lo_fds, (int)a[0]), 0, (uint64_t)ret);
        return;
    }
    if (number == __NR_connect && inet_fd_test(g_inet_fds, (int)a[0])) {
        int is_lo = inet_fd_test(g_inet_lo_fds, (int)a[0]);
        net_account_io(is_lo, 1, 60);
        net_account_io(is_lo, 0, 60);
        return;
    }
    if ((number == __NR_recvfrom || number == __NR_recvmsg) &&
        ret > 0 && inet_fd_test(g_inet_fds, (int)a[0])) {
        int is_lo = inet_fd_test(g_inet_lo_fds, (int)a[0]);
        if (number == __NR_recvfrom && a[4] && a[5] && *(unsigned *)a[5] >= 8u)
            is_lo = sockaddr_is_loopback((const void *)a[4], *(unsigned *)a[5]);
        else if (number == __NR_recvmsg && a[1]) {
            const struct ns_msghdr *m = (const struct ns_msghdr *)a[1];
            if (m->msg_name && m->msg_namelen >= 8u)
                is_lo = sockaddr_is_loopback(m->msg_name, m->msg_namelen);
        }
        net_account_io(is_lo, 0, (uint64_t)ret);
    }

    /* Virtual netlink recvfrom/recvmsg: synthesize kernel sockaddr_nl (nl_pid = 0). */
    if ((number == __NR_recvfrom || number == __NR_recvmsg) &&
        __atomic_load_n(&g_nl_active_count, __ATOMIC_RELAXED) > 0) {
        ns_lock();
        int is_nl = nl_find((int)a[0]) != NULL;
        ns_unlock();
        if (is_nl) {
            struct ns_sockaddr_nl nl = { AF_NETLINK_, 0, 0, 0 };
            if (number == __NR_recvfrom && a[4] && a[5]) {
                unsigned cap = *(unsigned *)a[5];
                unsigned cp = cap < sizeof(nl) ? cap : (unsigned)sizeof(nl);
                memcpy((void *)a[4], &nl, cp);
                *(unsigned *)a[5] = sizeof(nl);
            } else if (number == __NR_recvmsg && a[1]) {
                struct ns_msghdr *m = (struct ns_msghdr *)a[1];
                if (m->msg_name && m->msg_namelen > 0) {
                    unsigned cp = m->msg_namelen < sizeof(nl) ? m->msg_namelen : (unsigned)sizeof(nl);
                    memcpy(m->msg_name, &nl, cp);
                    m->msg_namelen = sizeof(nl);
                }
            }
            return;
        }
    }

    const struct sv_net_state *st = __atomic_load_n(&g_net_state, __ATOMIC_ACQUIRE);
    if (!st || !st->tun_active)
        return;

    /* getpeername on redirected TCP / connected UDP -> return original destination. */
    if (number == __NR_getpeername && a[1] && a[2]) {
        unsigned alen = *(unsigned *)a[2];
        if (alen > name_cap) alen = name_cap;
        int is_udp = 0, fam = 0;
        if (is_loopback_relay_port(st, (const void *)a[1], alen, &is_udp, &fam)) {
            uint16_t lport = query_local_port((int)a[0]);
            if (lport) {
                for (int i = 0; i < SV_NET_FLOW_CAP; i++) {
                    const struct sv_net_flow_slot *f = &st->flows[i];
                    if (f->active && f->local_port == lport &&
                        f->proto == (is_udp ? 17u : 6u)) {
                        write_restored_addr((void *)a[1], alen, fam, f->is_v6, f->dst_ip, f->dst_port);
                        break;
                    }
                }
            }
        }
        return;
    }

    /* getsockname on redirected TCP / UDP -> report TUN virtual IP instead of 127.0.0.1. */
    if (number == __NR_getsockname && a[1] && a[2]) {
        unsigned alen = *(unsigned *)a[2];
        if (alen > name_cap) alen = name_cap;
        if (alen >= 8) {
            uint16_t fam = 0, port_be = 0;
            memcpy(&fam, (const void *)a[1], 2);
            memcpy(&port_be, (const uint8_t *)a[1] + 2, 2);
            uint16_t lport = ns_be16(port_be);
            int is_loop = 0;
            if (fam == AF_INET_) {
                uint32_t ip4 = 0;
                memcpy(&ip4, (const uint8_t *)a[1] + 4, 4);
                is_loop = (ns_be32(ip4) == 0x7f000001u);
            } else if (fam == AF_INET6_ && alen >= 24) {
                const uint8_t *a6 = (const uint8_t *)a[1] + 8;
                uint32_t ip4 = 0;
                if (extract_v4_from_v6(a6, &ip4))
                    is_loop = (ns_be32(ip4) == 0x7f000001u);
                else
                    is_loop = (is_v6_loopback_or_unspec(a6) && a6[15] == 1);
            }
            if (lport && is_loop) {
                for (int i = 0; i < SV_NET_FLOW_CAP; i++) {
                    const struct sv_net_flow_slot *f = &st->flows[i];
                    if (f->active && f->local_port == lport) {
                        write_restored_addr((void *)a[1], alen, fam, f->is_v6, f->tun_ip, lport);
                        break;
                    }
                }
            }
        }
        return;
    }

    /* recvfrom / recvmsg on redirected UDP -> restore real remote source IP:port. */
    if (number == __NR_recvfrom || number == __NR_recvmsg) {
        void *src = NULL;
        unsigned slen = 0;
        if (number == __NR_recvfrom && a[4] && a[5]) {
            src = (void *)a[4];
            slen = *(unsigned *)a[5];
        } else if (number == __NR_recvmsg && a[1]) {
            struct ns_msghdr *m = (struct ns_msghdr *)a[1];
            src = m->msg_name;
            slen = m->msg_namelen;
        }
        if (!src || slen < 8)
            return;
        int is_udp = 0, fam = 0;
        if (!is_loopback_relay_port(st, src, slen, &is_udp, &fam) || !is_udp)
            return;
        uint16_t lport = query_local_port((int)a[0]);
        if (!lport)
            return;
        const struct sv_net_udp_reply *best = NULL;
        uint32_t best_seq = 0;
        for (int i = 0; i < SV_NET_UDP_REP_CAP; i++) {
            const struct sv_net_udp_reply *r = &st->udp_replies[i];
            if (r->seq != 0 && r->local_port == lport && r->seq >= best_seq) {
                best_seq = r->seq;
                best = r;
            }
        }
        if (best) {
            write_restored_addr(src, slen, fam, best->is_v6, best->src_ip, best->src_port);
        } else {
            /* Fallback to connected flow entry. */
            for (int i = 0; i < SV_NET_FLOW_CAP; i++) {
                const struct sv_net_flow_slot *f = &st->flows[i];
                if (f->active && f->local_port == lport && f->proto == 17u) {
                    write_restored_addr(src, slen, fam, f->is_v6, f->dst_ip, f->dst_port);
                    break;
                }
            }
        }
    }
}

/* ---- Virtual /proc/net and /sys/class/net Views ---- */

static size_t fmt_str(char *dst, size_t cap, size_t pos, const char *s)
{
    while (*s && pos < cap) dst[pos++] = *s++;
    return pos;
}

static size_t fmt_u64(char *dst, size_t cap, size_t pos, uint64_t v)
{
    char tmp[24];
    int d = 0;
    do { tmp[d++] = (char)('0' + (v % 10)); v /= 10; } while (v);
    while (d > 0 && pos < cap) dst[pos++] = tmp[--d];
    return pos;
}

static size_t fmt_hex(char *dst, size_t cap, size_t pos, uint64_t v, int width, int upper)
{
    const char *hx = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char tmp[16];
    for (int i = width - 1; i >= 0; i--) {
        tmp[i] = hx[v & 0xfu];
        v >>= 4;
    }
    for (int i = 0; i < width && pos < cap; i++)
        dst[pos++] = tmp[i];
    return pos;
}

static long make_memfd_text(const char *name, const char *buf, size_t len, int flags)
{
    long mfd = raw_syscall(__NR_memfd_create, (long)name,
                           (flags & O_CLOEXEC) ? 1 : 0, 0, 0, 0, 0);
    if (mfd < 0)
        return mfd;
    size_t done = 0;
    while (done < len) {
        long w = raw_syscall(__NR_write, mfd, (long)(buf + done), (long)(len - done), 0, 0, 0);
        if (w <= 0) {
            raw_syscall(__NR_close, mfd, 0, 0, 0, 0, 0);
            return w ? w : -EIO;
        }
        done += (size_t)w;
    }
    raw_syscall(__NR_lseek, mfd, 0, 0, 0, 0, 0);
    return mfd;
}

static long synth_reg_stat(long number, long a[6], size_t sz, int is_dir)
{
    if (number == __NR_faccessat || number == __NR_faccessat2) {
        if (a[2] & 2 /* W_OK */) return -EACCES;
        if (!is_dir && (a[2] & 1 /* X_OK */)) return -EACCES;
        return 0;
    }
    uint32_t mode = is_dir ? 0040555u : 0100444u;
    if (number == __NR_newfstatat) {
        if (!a[2]) return -EFAULT;
        unsigned char *sb = (unsigned char *)a[2];
        memset(sb, 0, 128);
        uint64_t dev = 1, ino = 0x53564e0000000001ULL + (uint64_t)sz;
        uint32_t nlink = is_dir ? 2u : 1u, blksize = 4096u;
        uint64_t usz = (uint64_t)sz;
        memcpy(sb + 0, &dev, 8);
        memcpy(sb + 8, &ino, 8);
        memcpy(sb + 16, &mode, 4);
        memcpy(sb + 20, &nlink, 4);
        memcpy(sb + 48, &usz, 8);
        memcpy(sb + 56, &blksize, 4);
        return 0;
    }
    if (number == __NR_statx) {
        if (!a[4]) return -EFAULT;
        unsigned char *sx = (unsigned char *)a[4];
        memset(sx, 0, 256);
        uint32_t mask = 0x7ffu, blksize = 4096u, nlink = is_dir ? 2u : 1u, dmin = 1u;
        uint16_t m16 = (uint16_t)mode;
        uint64_t usz = (uint64_t)sz;
        memcpy(sx + 0, &mask, 4);
        memcpy(sx + 4, &blksize, 4);
        memcpy(sx + 16, &nlink, 4);
        memcpy(sx + 28, &m16, 2);
        memcpy(sx + 40, &usz, 8);
        memcpy(sx + 140, &dmin, 4);
        return 0;
    }
    return -ENOENT;
}

static const char *match_proc_net_leaf(const char *p)
{
    if (strncmp(p, "/proc/", 6) != 0)
        return NULL;
    const char *c = p + 6;
    if (strncmp(c, "net/", 4) == 0)
        return c + 4;
    if (strncmp(c, "self/net/", 9) == 0)
        return c + 9;
    if (strncmp(c, "thread-self/net/", 16) == 0)
        return c + 16;
    if (*c >= '1' && *c <= '9') {
        while (*c >= '0' && *c <= '9') c++;
        if (strncmp(c, "/net/", 5) == 0)
            return c + 5;
    }
    return NULL;
}

long net_stack_proc_call(long number, long a[6], const char *guest_path)
{
    if (!net_stack_enabled() || !guest_path || guest_path[0] != '/')
        return -ENOENT;
    /* Fast bail-out: only /proc/... and /sys/class/net... are handled here. */
    if (guest_path[1] != 'p' && guest_path[1] != 's')
        return -ENOENT;

    /* 1. /proc[/<pid>|self]/net/{dev,route,if_inet6} */
    const char *leaf = match_proc_net_leaf(guest_path);
    if (leaf && (!strcmp(leaf, "dev") || !strcmp(leaf, "route") || !strcmp(leaf, "if_inet6"))) {
        const struct sv_net_state *st = net_stack_state();
        if (!st)
            return -ENOENT;
        char buf[4096];
        size_t pos = 0;
        if (!strcmp(leaf, "dev")) {
            pos = fmt_str(buf, sizeof(buf), pos,
                "Inter-|   Receive                                                |  Transmit\n"
                " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n");
            for (int i = 0; i < SV_NET_MAX_IFACES; i++) {
                const struct sv_net_iface *f = &st->ifaces[i];
                if (!f->active) continue;
                size_t nlen = strlen(f->name);
                for (size_t sp = nlen; sp < 6 && pos < sizeof(buf); sp++) buf[pos++] = ' ';
                pos = fmt_str(buf, sizeof(buf), pos, f->name);
                pos = fmt_str(buf, sizeof(buf), pos, ": ");
                pos = fmt_u64(buf, sizeof(buf), pos, __atomic_load_n(&f->rx_bytes, __ATOMIC_RELAXED));
                pos = fmt_str(buf, sizeof(buf), pos, " ");
                pos = fmt_u64(buf, sizeof(buf), pos, __atomic_load_n(&f->rx_packets, __ATOMIC_RELAXED));
                pos = fmt_str(buf, sizeof(buf), pos, " 0 0 0 0 0 0 ");
                pos = fmt_u64(buf, sizeof(buf), pos, __atomic_load_n(&f->tx_bytes, __ATOMIC_RELAXED));
                pos = fmt_str(buf, sizeof(buf), pos, " ");
                pos = fmt_u64(buf, sizeof(buf), pos, __atomic_load_n(&f->tx_packets, __ATOMIC_RELAXED));
                pos = fmt_str(buf, sizeof(buf), pos, " 0 0 0 0 0 0\n");
            }
        } else if (!strcmp(leaf, "route")) {
            pos = fmt_str(buf, sizeof(buf), pos,
                "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n");
            for (int i = 0; i < SV_NET_MAX_ROUTES; i++) {
                const struct sv_net_route4 *r = &st->routes[i];
                if (!r->active) continue;
                const struct sv_net_iface *f = find_iface_by_index(st, r->ifindex);
                if (!f) continue;
                uint32_t rflags = 0x0001u | (r->gw ? 0x0002u : 0u);
                pos = fmt_str(buf, sizeof(buf), pos, f->name);
                pos = fmt_str(buf, sizeof(buf), pos, "\t");
                pos = fmt_hex(buf, sizeof(buf), pos, r->dst, 8, 1);
                pos = fmt_str(buf, sizeof(buf), pos, "\t");
                pos = fmt_hex(buf, sizeof(buf), pos, r->gw, 8, 1);
                pos = fmt_str(buf, sizeof(buf), pos, "\t");
                pos = fmt_hex(buf, sizeof(buf), pos, rflags, 4, 1);
                pos = fmt_str(buf, sizeof(buf), pos, "\t0\t0\t");
                pos = fmt_u64(buf, sizeof(buf), pos, r->metric);
                pos = fmt_str(buf, sizeof(buf), pos, "\t");
                pos = fmt_hex(buf, sizeof(buf), pos, r->mask, 8, 1);
                pos = fmt_str(buf, sizeof(buf), pos, "\t0\t0\t0\n");
            }
        } else {
            for (int i = 0; i < SV_NET_MAX_IFACES; i++) {
                const struct sv_net_iface *f = &st->ifaces[i];
                if (!f->active || !f->has_v6) continue;
                for (int b = 0; b < 16; b++)
                    pos = fmt_hex(buf, sizeof(buf), pos, f->ipv6_addr[b], 2, 0);
                pos = fmt_str(buf, sizeof(buf), pos, " ");
                pos = fmt_hex(buf, sizeof(buf), pos, f->ifindex, 2, 0);
                pos = fmt_str(buf, sizeof(buf), pos, " ");
                pos = fmt_hex(buf, sizeof(buf), pos, f->ipv6_prefix, 2, 0);
                uint32_t scope = (f->flags & SV_IFF_LOOPBACK) ? 0x10u : 0x00u;
                pos = fmt_str(buf, sizeof(buf), pos, " ");
                pos = fmt_hex(buf, sizeof(buf), pos, scope, 2, 0);
                pos = fmt_str(buf, sizeof(buf), pos, " 80 ");
                pos = fmt_str(buf, sizeof(buf), pos, f->name);
                pos = fmt_str(buf, sizeof(buf), pos, "\n");
            }
        }
        if (number == __NR_openat) {
            if (a[2] & (O_WRONLY | O_RDWR))
                return -EACCES;
            return make_memfd_text(leaf, buf, pos, (int)a[2]);
        }
        return synth_reg_stat(number, a, pos, 0);
    }

    /* 2. /sys/class/net/<iface>/{ifindex,mtu,flags,operstate,carrier,address,type,tx_queue_len} */
    if (strncmp(guest_path, "/sys/class/net/", 15) == 0) {
        const char *rest = guest_path + 15;
        const char *slash = strchr(rest, '/');
        if (!slash || slash == rest)
            return -ENOENT;
        size_t nlen = (size_t)(slash - rest);
        if (nlen >= 16)
            return -ENOENT;
        char ifname[16];
        memcpy(ifname, rest, nlen);
        ifname[nlen] = '\0';
        const char *attr = slash + 1;
        const struct sv_net_state *st = net_stack_state();
        if (!st)
            return -ENOENT;
        const struct sv_net_iface *f = NULL;
        for (int i = 0; i < SV_NET_MAX_IFACES; i++) {
            if (st->ifaces[i].active && strcmp(st->ifaces[i].name, ifname) == 0) {
                f = &st->ifaces[i];
                break;
            }
        }
        if (!f)
            return -ENOENT;

        char buf[64];
        size_t pos = 0;
        if (!strcmp(attr, "ifindex")) {
            pos = fmt_u64(buf, sizeof(buf), pos, f->ifindex);
            pos = fmt_str(buf, sizeof(buf), pos, "\n");
        } else if (!strcmp(attr, "mtu")) {
            pos = fmt_u64(buf, sizeof(buf), pos, f->mtu);
            pos = fmt_str(buf, sizeof(buf), pos, "\n");
        } else if (!strcmp(attr, "flags")) {
            pos = fmt_str(buf, sizeof(buf), pos, "0x");
            pos = fmt_hex(buf, sizeof(buf), pos, f->flags, 4, 0);
            pos = fmt_str(buf, sizeof(buf), pos, "\n");
        } else if (!strcmp(attr, "operstate")) {
            const char *s = (f->flags & SV_IFF_UP) ? ((f->flags & SV_IFF_LOOPBACK) ? "unknown\n" : "up\n") : "down\n";
            pos = fmt_str(buf, sizeof(buf), pos, s);
        } else if (!strcmp(attr, "carrier")) {
            pos = fmt_str(buf, sizeof(buf), pos, (f->flags & SV_IFF_UP) ? "1\n" : "0\n");
        } else if (!strcmp(attr, "type")) {
            uint32_t t = (f->flags & SV_IFF_LOOPBACK) ? 772u : (f->is_tun ? 65534u : 1u);
            pos = fmt_u64(buf, sizeof(buf), pos, t);
            pos = fmt_str(buf, sizeof(buf), pos, "\n");
        } else if (!strcmp(attr, "tx_queue_len")) {
            pos = fmt_str(buf, sizeof(buf), pos, "1000\n");
        } else if (!strcmp(attr, "address")) {
            for (int b = 0; b < 6; b++) {
                if (b > 0) pos = fmt_str(buf, sizeof(buf), pos, ":");
                pos = fmt_hex(buf, sizeof(buf), pos, f->mac[b], 2, 0);
            }
            pos = fmt_str(buf, sizeof(buf), pos, "\n");
        } else if (strncmp(attr, "statistics/", 11) == 0) {
            const char *st_attr = attr + 11;
            if (!strcmp(st_attr, "rx_bytes")) {
                pos = fmt_u64(buf, sizeof(buf), pos, __atomic_load_n(&f->rx_bytes, __ATOMIC_RELAXED));
                pos = fmt_str(buf, sizeof(buf), pos, "\n");
            } else if (!strcmp(st_attr, "tx_bytes")) {
                pos = fmt_u64(buf, sizeof(buf), pos, __atomic_load_n(&f->tx_bytes, __ATOMIC_RELAXED));
                pos = fmt_str(buf, sizeof(buf), pos, "\n");
            } else if (!strcmp(st_attr, "rx_packets")) {
                pos = fmt_u64(buf, sizeof(buf), pos, __atomic_load_n(&f->rx_packets, __ATOMIC_RELAXED));
                pos = fmt_str(buf, sizeof(buf), pos, "\n");
            } else if (!strcmp(st_attr, "tx_packets")) {
                pos = fmt_u64(buf, sizeof(buf), pos, __atomic_load_n(&f->tx_packets, __ATOMIC_RELAXED));
                pos = fmt_str(buf, sizeof(buf), pos, "\n");
            } else if (!strcmp(st_attr, "rx_errors") || !strcmp(st_attr, "tx_errors") ||
                       !strcmp(st_attr, "rx_dropped") || !strcmp(st_attr, "tx_dropped") ||
                       !strcmp(st_attr, "multicast") || !strcmp(st_attr, "collisions") ||
                       !strcmp(st_attr, "rx_frame_errors") || !strcmp(st_attr, "rx_fifo_errors") ||
                       !strcmp(st_attr, "tx_fifo_errors") || !strcmp(st_attr, "tx_carrier_errors")) {
                pos = fmt_str(buf, sizeof(buf), pos, "0\n");
            } else {
                return -ENOENT;
            }
        } else {
            return -ENOENT;
        }
        if (number == __NR_openat) {
            if (a[2] & (O_WRONLY | O_RDWR))
                return -EACCES;
            const char *mname = strchr(attr, '/');
            return make_memfd_text(mname ? mname + 1 : attr, buf, pos, (int)a[2]);
        }
        return synth_reg_stat(number, a, pos, 0);
    }

    return -ENOENT;
}
