/* SPDX-License-Identifier: MIT */
/* svbox-net: Generic userspace virtual network & TUN stack daemon for svbox.
 *
 * Provides unprivileged (no root, no CAP_NET_ADMIN, no CLONE_NEWNET) containers
 * with:
 *  - Virtual network interfaces (lo, eth0, dynamic tunN) & shared state memfd
 *  - Virtual /dev/net/tun (AF_UNIX SOCK_SEQPACKET data FD + TUNSETIFF/TUNGETIFF)
 *  - Virtual AF_NETLINK/NETLINK_ROUTE (GET/NEW/DEL LINK/ADDR/ROUTE/RULE)
 *  - Virtual SIOC* socket ioctls
 *  - Transparent TCP/UDP redirection into active TUN routes with per-socket
 *    SO_MARK / SO_BINDTODEVICE / UID-range / socket-inode bypass
 *  - Generic DNS-over-TUN RPC for resolvers */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "net_internal.h"

/* Netlink wire definitions (avoiding host <linux/netlink.h> vs <sys/socket.h> clashes). */
#define NL_ALIGN(x) (((x) + 3u) & ~3u)
#define NL_MSG_ERROR    2u
#define NL_MSG_DONE     3u
#define NL_F_REQUEST    0x0001u
#define NL_F_MULTI      0x0002u
#define NL_F_ACK        0x0004u
#define NL_F_DUMP       0x0300u

#define NL_RTM_NEWLINK  16u
#define NL_RTM_DELLINK  17u
#define NL_RTM_GETLINK  18u
#define NL_RTM_SETLINK  19u
#define NL_RTM_NEWADDR  20u
#define NL_RTM_DELADDR  21u
#define NL_RTM_GETADDR  22u
#define NL_RTM_NEWROUTE 24u
#define NL_RTM_DELROUTE 25u
#define NL_RTM_GETROUTE 26u
#define NL_RTM_NEWRULE  32u
#define NL_RTM_DELRULE  33u
#define NL_RTM_GETRULE  34u

#define NL_IFLA_ADDRESS   1u
#define NL_IFLA_BROADCAST 2u
#define NL_IFLA_IFNAME    3u
#define NL_IFLA_MTU       4u
#define NL_IFLA_TXQLEN    13u
#define NL_IFLA_OPERSTATE 16u

#define NL_IFA_ADDRESS    1u
#define NL_IFA_LOCAL      2u
#define NL_IFA_LABEL      3u
#define NL_IFA_BROADCAST  4u
#define NL_IFA_CACHEINFO  6u
#define NL_IFA_FLAGS      8u

#define NL_RTA_DST        1u
#define NL_RTA_OIF        4u
#define NL_RTA_GATEWAY    5u
#define NL_RTA_PRIORITY   6u
#define NL_RTA_TABLE      15u

#define NL_RTMGRP_LINK        0x0001u
#define NL_RTMGRP_IPV4_IFADDR 0x0010u
#define NL_RTMGRP_IPV4_ROUTE  0x0040u
#define NL_RTMGRP_IPV6_IFADDR 0x0100u

struct nl_hdr {
    uint32_t len;
    uint16_t type;
    uint16_t flags;
    uint32_t seq;
    uint32_t pid;
};

struct nl_err {
    int32_t       error;
    struct nl_hdr msg;
};

struct nl_ifinfo {
    uint8_t  family;
    uint8_t  pad;
    uint16_t type;
    int32_t  index;
    uint32_t flags;
    uint32_t change;
};

struct nl_ifaddr {
    uint8_t  family;
    uint8_t  prefixlen;
    uint8_t  flags;
    uint8_t  scope;
    uint32_t index;
};

struct nl_rtmsg {
    uint8_t  family;
    uint8_t  dst_len;
    uint8_t  src_len;
    uint8_t  tos;
    uint8_t  table;
    uint8_t  protocol;
    uint8_t  scope;
    uint8_t  type;
    uint32_t flags;
};

struct nl_rta {
    uint16_t len;
    uint16_t type;
};

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

uint64_t net_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static uint32_t prefix_to_mask4(uint32_t prefix)
{
    if (prefix == 0) return 0u;
    if (prefix >= 32) return 0xffffffffu;
    return htonl(~((1u << (32u - prefix)) - 1u));
}

static uint32_t mask4_to_prefix(uint32_t mask_net)
{
    uint32_t m = ntohl(mask_net);
    uint32_t p = 0;
    while (m & 0x80000000u) { p++; m <<= 1; }
    return p;
}

/* ---- Control Wire Helpers ---- */

static int send_all(int fd, const void *buf, size_t len, int send_fd)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t sent = 0;
    while (sent < len) {
        struct iovec iov = { (void *)(p + sent), len - sent };
        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        union {
            struct cmsghdr align;
            char data[CMSG_SPACE(sizeof(int))];
        } cbuf;
        if (sent == 0 && send_fd >= 0) {
            memset(&cbuf, 0, sizeof(cbuf));
            msg.msg_control = cbuf.data;
            msg.msg_controllen = sizeof(cbuf.data);
            struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
            c->cmsg_level = SOL_SOCKET;
            c->cmsg_type = SCM_RIGHTS;
            c->cmsg_len = CMSG_LEN(sizeof(int));
            memcpy(CMSG_DATA(c), &send_fd, sizeof(int));
        }
        ssize_t w = sendmsg(fd, &msg, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

static int recv_all(int fd, void *buf, size_t len)
{
    uint8_t *p = (uint8_t *)buf;
    size_t got = 0;
    while (got < len) {
        ssize_t r = recv(fd, p + got, len - got, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

int net_send_ctl_reply(int fd, uint32_t op, int32_t status, uint32_t proc_id,
                       uint64_t arg0, const void *payload, uint32_t payload_len, int send_fd)
{
    struct vdev_hdr rep;
    memset(&rep, 0, sizeof(rep));
    rep.magic = VDEV_PROTO_MAGIC;
    rep.op = op;
    rep.status = status;
    rep.payload_len = payload_len;
    rep.proc_id = proc_id;
    rep.fd_count = (send_fd >= 0) ? 1u : 0u;
    rep.arg0 = arg0;
    if (send_all(fd, &rep, sizeof(rep), send_fd) < 0)
        return -1;
    if (payload_len > 0 && send_all(fd, payload, payload_len, -1) < 0)
        return -1;
    return 0;
}

/* ---- Interface & Route State Management ---- */

struct sv_net_iface *net_find_iface_by_idx(struct net_daemon *d, uint32_t ifindex)
{
    for (int i = 0; i < SV_NET_MAX_IFACES; i++) {
        if (d->st->ifaces[i].active && d->st->ifaces[i].ifindex == ifindex)
            return &d->st->ifaces[i];
    }
    return NULL;
}

static struct sv_net_iface *find_iface_by_name(struct net_daemon *d, const char *name)
{
    if (!name || !name[0]) return NULL;
    for (int i = 0; i < SV_NET_MAX_IFACES; i++) {
        if (d->st->ifaces[i].active && strcmp(d->st->ifaces[i].name, name) == 0)
            return &d->st->ifaces[i];
    }
    return NULL;
}

struct tun_dev *net_find_tun_by_ifindex(struct net_daemon *d, uint32_t ifindex)
{
    for (int i = 0; i < NET_MAX_TUNS; i++) {
        if (d->tuns[i].active && d->tuns[i].ifindex == ifindex && d->tuns[i].data_fd >= 0)
            return &d->tuns[i];
    }
    return NULL;
}

static struct sv_net_iface *alloc_iface(struct net_daemon *d, const char *name,
                                        uint32_t flags, uint32_t mtu, int is_tun)
{
    for (int i = 0; i < SV_NET_MAX_IFACES; i++) {
        if (!d->st->ifaces[i].active) {
            struct sv_net_iface *f = &d->st->ifaces[i];
            memset(f, 0, sizeof(*f));
            f->active = 1;
            f->ifindex = d->next_ifindex++;
            strncpy(f->name, name, sizeof(f->name) - 1);
            f->flags = flags;
            f->mtu = mtu;
            f->is_tun = (uint8_t)is_tun;
            if (!is_tun && !(flags & SV_IFF_LOOPBACK)) {
                f->mac[0] = 0x02;
                f->mac[5] = (uint8_t)(f->ifindex & 0xffu);
            }
            return f;
        }
    }
    return NULL;
}

void net_recompute_tun_active(struct net_daemon *d)
{
    uint32_t active = 0;
    for (int i = 0; i < SV_NET_MAX_ROUTES && !active; i++) {
        if (!d->st->routes[i].active) continue;
        struct sv_net_iface *f = net_find_iface_by_idx(d, d->st->routes[i].ifindex);
        if (f && f->is_tun && (f->flags & SV_IFF_UP))
            active = 1;
    }
    for (int i = 0; i < SV_NET_MAX_ROUTES6 && !active; i++) {
        if (!d->st->routes6[i].active) continue;
        struct sv_net_iface *f = net_find_iface_by_idx(d, d->st->routes6[i].ifindex);
        if (f && f->is_tun && (f->flags & SV_IFF_UP))
            active = 1;
    }
    d->st->tun_active = active;
    __atomic_add_fetch(&d->st->seq, 1u, __ATOMIC_RELEASE);
}

void net_sync_flow_slot(struct net_daemon *d, int idx)
{
    if (idx < 0 || idx >= SV_NET_FLOW_CAP)
        return;
    struct sv_net_flow_slot *dst = &d->st->flows[idx];
    const struct pending_flow *src = &d->flows[idx];
    if (!src->active) {
        __atomic_store_n(&dst->active, 0u, __ATOMIC_RELEASE);
    } else {
        dst->local_port = src->local_port;
        dst->dst_port = src->dst_port;
        dst->proto = src->proto;
        dst->is_v6 = src->is_v6;
        dst->tun_ifindex = src->tun_ifindex;
        memcpy(dst->dst_ip, src->dst_ip, 16);
        memcpy(dst->tun_ip, src->tun_ip, 16);
        __atomic_store_n(&dst->active, 1u, __ATOMIC_RELEASE);
    }
}

void net_sync_flow_table(struct net_daemon *d)
{
    for (int i = 0; i < SV_NET_FLOW_CAP; i++)
        net_sync_flow_slot(d, i);
}

static int route4_add(struct net_daemon *d, uint32_t dst_net, uint32_t prefix,
                      uint32_t gw_net, uint32_t ifindex, uint32_t metric, uint32_t table)
{
    if (prefix > 32) prefix = 32;
    uint32_t mask = prefix_to_mask4(prefix);
    dst_net &= mask;
    int free_idx = -1;
    for (int i = 0; i < SV_NET_MAX_ROUTES; i++) {
        struct sv_net_route4 *r = &d->st->routes[i];
        if (r->active && r->dst == dst_net && r->prefix == prefix &&
            r->ifindex == ifindex && r->metric == metric) {
            r->gw = gw_net;
            r->table = table ? table : 254u;
            net_recompute_tun_active(d);
            return 0;
        }
        if (!r->active && free_idx < 0)
            free_idx = i;
    }
    if (free_idx < 0)
        return -ENOSPC;
    struct sv_net_route4 *r = &d->st->routes[free_idx];
    r->active = 1;
    r->dst = dst_net;
    r->mask = mask;
    r->gw = gw_net;
    r->ifindex = ifindex;
    r->metric = metric;
    r->prefix = prefix;
    r->table = table ? table : 254u;
    net_recompute_tun_active(d);
    return 0;
}

static int route4_del(struct net_daemon *d, uint32_t dst_net, uint32_t prefix, uint32_t ifindex)
{
    if (prefix > 32) prefix = 32;
    uint32_t mask = prefix_to_mask4(prefix);
    dst_net &= mask;
    int removed = 0;
    for (int i = 0; i < SV_NET_MAX_ROUTES; i++) {
        struct sv_net_route4 *r = &d->st->routes[i];
        if (!r->active) continue;
        if (r->dst == dst_net && r->prefix == prefix &&
            (ifindex == 0 || r->ifindex == ifindex)) {
            r->active = 0;
            removed++;
        }
    }
    net_recompute_tun_active(d);
    return removed ? 0 : -ESRCH;
}

static int route6_add(struct net_daemon *d, const uint8_t dst[16], uint32_t prefix,
                      const uint8_t gw[16], uint32_t ifindex, uint32_t metric)
{
    if (prefix > 128) prefix = 128;
    int free_idx = -1;
    for (int i = 0; i < SV_NET_MAX_ROUTES6; i++) {
        struct sv_net_route6 *r = &d->st->routes6[i];
        if (r->active && r->prefix == prefix && r->ifindex == ifindex &&
            memcmp(r->dst, dst, 16) == 0) {
            memcpy(r->gw, gw, 16);
            r->metric = metric;
            net_recompute_tun_active(d);
            return 0;
        }
        if (!r->active && free_idx < 0)
            free_idx = i;
    }
    if (free_idx < 0)
        return -ENOSPC;
    struct sv_net_route6 *r = &d->st->routes6[free_idx];
    r->active = 1;
    r->ifindex = ifindex;
    r->metric = metric;
    r->prefix = prefix;
    memcpy(r->dst, dst, 16);
    memcpy(r->gw, gw, 16);
    net_recompute_tun_active(d);
    return 0;
}

static int route6_del(struct net_daemon *d, const uint8_t dst[16], uint32_t prefix, uint32_t ifindex)
{
    int removed = 0;
    for (int i = 0; i < SV_NET_MAX_ROUTES6; i++) {
        struct sv_net_route6 *r = &d->st->routes6[i];
        if (!r->active) continue;
        if (r->prefix == prefix && memcmp(r->dst, dst, 16) == 0 &&
            (ifindex == 0 || r->ifindex == ifindex)) {
            r->active = 0;
            removed++;
        }
    }
    net_recompute_tun_active(d);
    return removed ? 0 : -ESRCH;
}

static void routes_clear_iface(struct net_daemon *d, uint32_t ifindex)
{
    for (int i = 0; i < SV_NET_MAX_ROUTES; i++) {
        if (d->st->routes[i].active && d->st->routes[i].ifindex == ifindex)
            d->st->routes[i].active = 0;
    }
    for (int i = 0; i < SV_NET_MAX_ROUTES6; i++) {
        if (d->st->routes6[i].active && d->st->routes6[i].ifindex == ifindex)
            d->st->routes6[i].active = 0;
    }
    net_recompute_tun_active(d);
}

/* ---- Netlink Message Builder & Multicast Notifier ---- */

static size_t nl_put_rta(uint8_t *buf, size_t off, size_t cap,
                         uint16_t type, const void *data, size_t dlen)
{
    size_t rlen = sizeof(struct nl_rta) + dlen;
    size_t alen = NL_ALIGN(rlen);
    if (off + alen > cap) return off;
    struct nl_rta rta = { (uint16_t)rlen, type };
    memcpy(buf + off, &rta, sizeof(rta));
    if (dlen > 0) memcpy(buf + off + sizeof(rta), data, dlen);
    if (alen > rlen) memset(buf + off + rlen, 0, alen - rlen);
    return off + alen;
}

static size_t nl_build_link_msg(uint8_t *buf, size_t cap, uint16_t msg_type,
                                uint16_t flags, uint32_t seq, uint32_t pid,
                                const struct sv_net_iface *f)
{
    if (cap < sizeof(struct nl_hdr) + sizeof(struct nl_ifinfo) + 128)
        return 0;
    size_t off = sizeof(struct nl_hdr);
    struct nl_ifinfo ii;
    memset(&ii, 0, sizeof(ii));
    ii.family = AF_UNSPEC;
    ii.type = (f->flags & SV_IFF_LOOPBACK) ? 772u : (f->is_tun ? 65534u : 1u);
    ii.index = (int32_t)f->ifindex;
    ii.flags = f->flags;
    ii.change = 0;
    memcpy(buf + off, &ii, sizeof(ii));
    off += sizeof(ii);

    off = nl_put_rta(buf, off, cap, NL_IFLA_IFNAME, f->name, strlen(f->name) + 1);
    off = nl_put_rta(buf, off, cap, NL_IFLA_MTU, &f->mtu, 4);
    uint32_t txq = 1000u;
    off = nl_put_rta(buf, off, cap, NL_IFLA_TXQLEN, &txq, 4);
    uint8_t oper = (f->flags & SV_IFF_UP) ? ((f->flags & SV_IFF_LOOPBACK) ? 0u : 6u) : 2u;
    off = nl_put_rta(buf, off, cap, NL_IFLA_OPERSTATE, &oper, 1);
    if (!f->is_tun) {
        off = nl_put_rta(buf, off, cap, NL_IFLA_ADDRESS, f->mac, 6);
        uint8_t bcast[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
        if (f->flags & SV_IFF_BROADCAST)
            off = nl_put_rta(buf, off, cap, NL_IFLA_BROADCAST, bcast, 6);
    }

    struct nl_hdr nh = { (uint32_t)off, msg_type, flags, seq, pid };
    memcpy(buf, &nh, sizeof(nh));
    return NL_ALIGN(off);
}

static size_t nl_build_addr4_msg(uint8_t *buf, size_t cap, uint16_t msg_type,
                                 uint16_t flags, uint32_t seq, uint32_t pid,
                                 const struct sv_net_iface *f)
{
    if (!f->ipv4_addr || cap < 128) return 0;
    size_t off = sizeof(struct nl_hdr);
    struct nl_ifaddr ia;
    memset(&ia, 0, sizeof(ia));
    ia.family = AF_INET;
    ia.prefixlen = (uint8_t)f->ipv4_prefix;
    ia.flags = 0x80u; /* IFA_F_PERMANENT */
    ia.scope = (f->flags & SV_IFF_LOOPBACK) ? 254u : 0u;
    ia.index = f->ifindex;
    memcpy(buf + off, &ia, sizeof(ia));
    off += sizeof(ia);

    off = nl_put_rta(buf, off, cap, NL_IFA_ADDRESS, &f->ipv4_addr, 4);
    off = nl_put_rta(buf, off, cap, NL_IFA_LOCAL, &f->ipv4_addr, 4);
    if (f->flags & SV_IFF_BROADCAST) {
        uint32_t bcast = f->ipv4_addr | ~f->ipv4_mask;
        off = nl_put_rta(buf, off, cap, NL_IFA_BROADCAST, &bcast, 4);
    }
    off = nl_put_rta(buf, off, cap, NL_IFA_LABEL, f->name, strlen(f->name) + 1);
    uint32_t ifa_flags32 = 0x80u; /* IFA_F_PERMANENT */
    off = nl_put_rta(buf, off, cap, NL_IFA_FLAGS, &ifa_flags32, 4);
    uint32_t cacheinfo[4] = { 0xffffffffu, 0xffffffffu, 1u, 1u };
    off = nl_put_rta(buf, off, cap, NL_IFA_CACHEINFO, cacheinfo, sizeof(cacheinfo));

    struct nl_hdr nh = { (uint32_t)off, msg_type, flags, seq, pid };
    memcpy(buf, &nh, sizeof(nh));
    return NL_ALIGN(off);
}

static size_t nl_build_addr6_msg(uint8_t *buf, size_t cap, uint16_t msg_type,
                                 uint16_t flags, uint32_t seq, uint32_t pid,
                                 const struct sv_net_iface *f)
{
    if (!f->has_v6 || cap < 128) return 0;
    size_t off = sizeof(struct nl_hdr);
    struct nl_ifaddr ia;
    memset(&ia, 0, sizeof(ia));
    ia.family = AF_INET6;
    ia.prefixlen = (uint8_t)f->ipv6_prefix;
    ia.flags = 0x80u;
    ia.scope = (f->flags & SV_IFF_LOOPBACK) ? 254u : 0u;
    ia.index = f->ifindex;
    memcpy(buf + off, &ia, sizeof(ia));
    off += sizeof(ia);

    off = nl_put_rta(buf, off, cap, NL_IFA_ADDRESS, f->ipv6_addr, 16);
    uint32_t ifa_flags32 = 0x80u;
    off = nl_put_rta(buf, off, cap, NL_IFA_FLAGS, &ifa_flags32, 4);
    uint32_t cacheinfo[4] = { 0xffffffffu, 0xffffffffu, 1u, 1u };
    off = nl_put_rta(buf, off, cap, NL_IFA_CACHEINFO, cacheinfo, sizeof(cacheinfo));
    struct nl_hdr nh = { (uint32_t)off, msg_type, flags, seq, pid };
    memcpy(buf, &nh, sizeof(nh));
    return NL_ALIGN(off);
}

static size_t nl_build_route4_msg(uint8_t *buf, size_t cap, uint16_t flags,
                                  uint32_t seq, uint32_t pid, const struct sv_net_route4 *r)
{
    if (cap < 128) return 0;
    size_t off = sizeof(struct nl_hdr);
    struct nl_rtmsg rm;
    memset(&rm, 0, sizeof(rm));
    rm.family = AF_INET;
    rm.dst_len = (uint8_t)r->prefix;
    rm.table = (uint8_t)(r->table <= 255u ? r->table : 254u);
    rm.protocol = 3u; /* RTPROT_BOOT */
    rm.scope = r->gw ? 0u : 253u; /* UNIVERSE or LINK */
    rm.type = 1u; /* RTN_UNICAST */
    memcpy(buf + off, &rm, sizeof(rm));
    off += sizeof(rm);

    uint32_t tbl = r->table ? r->table : 254u;
    off = nl_put_rta(buf, off, cap, NL_RTA_TABLE, &tbl, 4);
    if (r->prefix > 0)
        off = nl_put_rta(buf, off, cap, NL_RTA_DST, &r->dst, 4);
    if (r->gw != 0)
        off = nl_put_rta(buf, off, cap, NL_RTA_GATEWAY, &r->gw, 4);
    off = nl_put_rta(buf, off, cap, NL_RTA_OIF, &r->ifindex, 4);
    if (r->metric > 0)
        off = nl_put_rta(buf, off, cap, NL_RTA_PRIORITY, &r->metric, 4);

    struct nl_hdr nh = { (uint32_t)off, NL_RTM_NEWROUTE, flags, seq, pid };
    memcpy(buf, &nh, sizeof(nh));
    return NL_ALIGN(off);
}

static size_t nl_build_route6_msg(uint8_t *buf, size_t cap, uint16_t flags,
                                  uint32_t seq, uint32_t pid, const struct sv_net_route6 *r)
{
    if (cap < 160) return 0;
    size_t off = sizeof(struct nl_hdr);
    struct nl_rtmsg rm;
    memset(&rm, 0, sizeof(rm));
    rm.family = AF_INET6;
    rm.dst_len = (uint8_t)r->prefix;
    rm.table = 254u;
    rm.protocol = 3u;
    rm.scope = 0u;
    rm.type = 1u;
    memcpy(buf + off, &rm, sizeof(rm));
    off += sizeof(rm);

    uint32_t tbl = 254u;
    off = nl_put_rta(buf, off, cap, NL_RTA_TABLE, &tbl, 4);
    if (r->prefix > 0)
        off = nl_put_rta(buf, off, cap, NL_RTA_DST, r->dst, 16);
    off = nl_put_rta(buf, off, cap, NL_RTA_OIF, &r->ifindex, 4);
    if (r->metric > 0)
        off = nl_put_rta(buf, off, cap, NL_RTA_PRIORITY, &r->metric, 4);

    struct nl_hdr nh = { (uint32_t)off, NL_RTM_NEWROUTE, flags, seq, pid };
    memcpy(buf, &nh, sizeof(nh));
    return NL_ALIGN(off);
}

static void nl_broadcast_link(struct net_daemon *d, uint16_t msg_type, const struct sv_net_iface *f)
{
    uint8_t msg[256];
    size_t len = nl_build_link_msg(msg, sizeof(msg), msg_type, 0, 0, 0, f);
    if (!len) return;
    for (int i = 0; i < NET_MAX_NLS; i++) {
        if (d->nls[i].active && (d->nls[i].groups & NL_RTMGRP_LINK) && d->nls[i].fd >= 0)
            (void)send(d->nls[i].fd, msg, len, MSG_NOSIGNAL | MSG_DONTWAIT);
    }
}

static void nl_broadcast_addr4(struct net_daemon *d, uint16_t msg_type, const struct sv_net_iface *f)
{
    if (!f || !f->ipv4_addr) return;
    uint8_t msg[256];
    size_t len = nl_build_addr4_msg(msg, sizeof(msg), msg_type, 0, 0, 0, f);
    if (!len) return;
    for (int i = 0; i < NET_MAX_NLS; i++) {
        if (d->nls[i].active && (d->nls[i].groups & NL_RTMGRP_IPV4_IFADDR) && d->nls[i].fd >= 0)
            (void)send(d->nls[i].fd, msg, len, MSG_NOSIGNAL | MSG_DONTWAIT);
    }
}

static void nl_broadcast_addr6(struct net_daemon *d, uint16_t msg_type, const struct sv_net_iface *f)
{
    if (!f || !f->has_v6) return;
    uint8_t msg[256];
    size_t len = nl_build_addr6_msg(msg, sizeof(msg), msg_type, 0, 0, 0, f);
    if (!len) return;
    for (int i = 0; i < NET_MAX_NLS; i++) {
        if (d->nls[i].active && (d->nls[i].groups & NL_RTMGRP_IPV6_IFADDR) && d->nls[i].fd >= 0)
            (void)send(d->nls[i].fd, msg, len, MSG_NOSIGNAL | MSG_DONTWAIT);
    }
}

static void nl_send_ack(int fd, const struct nl_hdr *req, uint32_t pid, int err)
{
    struct {
        struct nl_hdr h;
        struct nl_err e;
    } pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.h.len = sizeof(pkt);
    pkt.h.type = NL_MSG_ERROR;
    pkt.h.seq = req->seq;
    pkt.h.pid = pid;
    pkt.e.error = err;
    pkt.e.msg = *req;
    (void)send(fd, &pkt, sizeof(pkt), MSG_NOSIGNAL | MSG_DONTWAIT);
}

static void nl_handle_packet(struct net_daemon *d, struct nl_client *nc,
                             const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off + sizeof(struct nl_hdr) <= len) {
        struct nl_hdr req;
        memcpy(&req, buf + off, sizeof(req));
        if (req.len < sizeof(req) || off + req.len > len)
            break;
        const uint8_t *body = buf + off + sizeof(req);
        size_t blen = req.len - sizeof(req);
        uint32_t pid = req.pid ? req.pid : nc->pid;

        if (req.type == NL_RTM_GETLINK) {
            uint8_t out[8192];
            size_t opos = 0;
            int is_dump = (req.flags & NL_F_DUMP) == NL_F_DUMP;
            int32_t want_idx = 0;
            char want_name[16] = {0};
            if (!is_dump && blen >= sizeof(struct nl_ifinfo)) {
                struct nl_ifinfo ii;
                memcpy(&ii, body, sizeof(ii));
                want_idx = ii.index;
                size_t roff = sizeof(ii);
                while (roff + sizeof(struct nl_rta) <= blen) {
                    struct nl_rta rta;
                    memcpy(&rta, body + roff, sizeof(rta));
                    if (rta.len < sizeof(rta) || roff + rta.len > blen) break;
                    if (rta.type == NL_IFLA_IFNAME) {
                        size_t n = rta.len - sizeof(rta);
                        if (n >= sizeof(want_name)) n = sizeof(want_name) - 1;
                        memcpy(want_name, body + roff + sizeof(rta), n);
                        want_name[n] = '\0';
                    }
                    roff += NL_ALIGN(rta.len);
                }
            }
            int found = 0;
            for (int i = 0; i < SV_NET_MAX_IFACES; i++) {
                const struct sv_net_iface *f = &d->st->ifaces[i];
                if (!f->active) continue;
                if (!is_dump) {
                    if (want_idx > 0 && (int32_t)f->ifindex != want_idx) continue;
                    if (want_name[0] && strcmp(f->name, want_name) != 0) continue;
                }
                size_t n = nl_build_link_msg(out + opos, sizeof(out) - opos - 32,
                                             NL_RTM_NEWLINK, is_dump ? NL_F_MULTI : 0u,
                                             req.seq, pid, f);
                opos += n;
                found = 1;
                if (!is_dump) break;
            }
            if (is_dump) {
                struct nl_hdr done = { sizeof(struct nl_hdr) + 4, NL_MSG_DONE, NL_F_MULTI, req.seq, pid };
                int32_t zero = 0;
                memcpy(out + opos, &done, sizeof(done)); opos += sizeof(done);
                memcpy(out + opos, &zero, 4); opos += 4;
                (void)send(nc->fd, out, opos, MSG_NOSIGNAL | MSG_DONTWAIT);
            } else if (found) {
                (void)send(nc->fd, out, opos, MSG_NOSIGNAL | MSG_DONTWAIT);
            } else {
                nl_send_ack(nc->fd, &req, pid, -ENODEV);
            }
        } else if (req.type == NL_RTM_GETADDR) {
            uint8_t out[8192];
            size_t opos = 0;
            uint8_t want_fam = (blen >= 1) ? body[0] : AF_UNSPEC;
            for (int i = 0; i < SV_NET_MAX_IFACES; i++) {
                const struct sv_net_iface *f = &d->st->ifaces[i];
                if (!f->active) continue;
                if ((want_fam == AF_UNSPEC || want_fam == AF_INET) && f->ipv4_addr) {
                    opos += nl_build_addr4_msg(out + opos, sizeof(out) - opos - 32,
                                               NL_RTM_NEWADDR, NL_F_MULTI, req.seq, pid, f);
                }
                if ((want_fam == AF_UNSPEC || want_fam == AF_INET6) && f->has_v6) {
                    opos += nl_build_addr6_msg(out + opos, sizeof(out) - opos - 32,
                                               NL_RTM_NEWADDR, NL_F_MULTI, req.seq, pid, f);
                }
            }
            struct nl_hdr done = { sizeof(struct nl_hdr) + 4, NL_MSG_DONE, NL_F_MULTI, req.seq, pid };
            int32_t zero = 0;
            memcpy(out + opos, &done, sizeof(done)); opos += sizeof(done);
            memcpy(out + opos, &zero, 4); opos += 4;
            (void)send(nc->fd, out, opos, MSG_NOSIGNAL | MSG_DONTWAIT);
        } else if (req.type == NL_RTM_GETROUTE) {
            uint8_t out[8192];
            size_t opos = 0;
            uint8_t want_fam = (blen >= 1) ? body[0] : AF_UNSPEC;
            if (want_fam == AF_UNSPEC || want_fam == AF_INET) {
                for (int i = 0; i < SV_NET_MAX_ROUTES; i++) {
                    if (!d->st->routes[i].active) continue;
                    if (opos + 160 > sizeof(out)) break;
                    opos += nl_build_route4_msg(out + opos, sizeof(out) - opos - 32,
                                                NL_F_MULTI, req.seq, pid, &d->st->routes[i]);
                }
            }
            if (want_fam == AF_UNSPEC || want_fam == AF_INET6) {
                for (int i = 0; i < SV_NET_MAX_ROUTES6; i++) {
                    if (!d->st->routes6[i].active) continue;
                    if (opos + 192 > sizeof(out)) break;
                    opos += nl_build_route6_msg(out + opos, sizeof(out) - opos - 32,
                                                NL_F_MULTI, req.seq, pid, &d->st->routes6[i]);
                }
            }
            struct nl_hdr done = { sizeof(struct nl_hdr) + 4, NL_MSG_DONE, NL_F_MULTI, req.seq, pid };
            int32_t zero = 0;
            memcpy(out + opos, &done, sizeof(done)); opos += sizeof(done);
            memcpy(out + opos, &zero, 4); opos += 4;
            (void)send(nc->fd, out, opos, MSG_NOSIGNAL | MSG_DONTWAIT);
        } else if (req.type == NL_RTM_GETRULE) {
            uint8_t out[64];
            struct nl_hdr done = { sizeof(struct nl_hdr) + 4, NL_MSG_DONE, NL_F_MULTI, req.seq, pid };
            int32_t zero = 0;
            memcpy(out, &done, sizeof(done));
            memcpy(out + sizeof(done), &zero, 4);
            (void)send(nc->fd, out, sizeof(done) + 4, MSG_NOSIGNAL | MSG_DONTWAIT);
        } else if (req.type == NL_RTM_NEWLINK || req.type == NL_RTM_SETLINK || req.type == NL_RTM_DELLINK) {
            int err = 0;
            if (blen >= sizeof(struct nl_ifinfo)) {
                struct nl_ifinfo ii;
                memcpy(&ii, body, sizeof(ii));
                char name[16] = {0};
                uint32_t new_mtu = 0;
                size_t roff = sizeof(ii);
                while (roff + sizeof(struct nl_rta) <= blen) {
                    struct nl_rta rta;
                    memcpy(&rta, body + roff, sizeof(rta));
                    if (rta.len < sizeof(rta) || roff + rta.len > blen) break;
                    const uint8_t *val = body + roff + sizeof(rta);
                    size_t vlen = rta.len - sizeof(rta);
                    if (rta.type == NL_IFLA_IFNAME && vlen > 0) {
                        size_t n = vlen < 15 ? vlen : 15;
                        memcpy(name, val, n);
                        name[n] = '\0';
                    } else if (rta.type == NL_IFLA_MTU && vlen >= 4) {
                        memcpy(&new_mtu, val, 4);
                    }
                    roff += NL_ALIGN(rta.len);
                }
                struct sv_net_iface *f = ii.index > 0 ? net_find_iface_by_idx(d, (uint32_t)ii.index)
                                                      : find_iface_by_name(d, name);
                if (!f) {
                    err = -ENODEV;
                } else if (req.type == NL_RTM_DELLINK) {
                    routes_clear_iface(d, f->ifindex);
                    f->flags &= ~(SV_IFF_UP | SV_IFF_RUNNING);
                    net_recompute_tun_active(d);
                    nl_broadcast_link(d, NL_RTM_DELLINK, f);
                } else {
                    if (ii.change) {
                        f->flags = (f->flags & ~ii.change) | (ii.flags & ii.change);
                    } else if (ii.flags & SV_IFF_UP) {
                        f->flags |= SV_IFF_UP;
                    }
                    if (f->flags & SV_IFF_UP)
                        f->flags |= SV_IFF_RUNNING;
                    else
                        f->flags &= ~SV_IFF_RUNNING;
                    if (new_mtu >= 576u && new_mtu <= 65535u)
                        f->mtu = new_mtu;
                    net_recompute_tun_active(d);
                    nl_broadcast_link(d, NL_RTM_NEWLINK, f);
                }
            }
            if (req.flags & NL_F_ACK) nl_send_ack(nc->fd, &req, pid, err);
        } else if (req.type == NL_RTM_NEWADDR || req.type == NL_RTM_DELADDR) {
            int err = 0;
            if (blen >= sizeof(struct nl_ifaddr)) {
                struct nl_ifaddr ia;
                memcpy(&ia, body, sizeof(ia));
                struct sv_net_iface *f = net_find_iface_by_idx(d, ia.index);
                if (!f) {
                    err = -ENODEV;
                } else {
                    uint8_t addr[16];
                    int has_addr = 0;
                    memset(addr, 0, sizeof(addr));
                    size_t roff = sizeof(ia);
                    while (roff + sizeof(struct nl_rta) <= blen) {
                        struct nl_rta rta;
                        memcpy(&rta, body + roff, sizeof(rta));
                        if (rta.len < sizeof(rta) || roff + rta.len > blen) break;
                        const uint8_t *val = body + roff + sizeof(rta);
                        size_t vlen = rta.len - sizeof(rta);
                        if ((rta.type == NL_IFA_LOCAL || rta.type == NL_IFA_ADDRESS) &&
                            ((ia.family == AF_INET && vlen >= 4) || (ia.family == AF_INET6 && vlen >= 16))) {
                            memcpy(addr, val, ia.family == AF_INET ? 4u : 16u);
                            has_addr = 1;
                            if (rta.type == NL_IFA_LOCAL) break;
                        }
                        roff += NL_ALIGN(rta.len);
                    }
                    if (has_addr && ia.family == AF_INET) {
                        uint32_t ip4 = 0;
                        memcpy(&ip4, addr, 4);
                        if (req.type == NL_RTM_NEWADDR) {
                            f->ipv4_addr = ip4;
                            f->ipv4_prefix = ia.prefixlen <= 32 ? ia.prefixlen : 32;
                            f->ipv4_mask = prefix_to_mask4(f->ipv4_prefix);
                            if (f->ipv4_prefix > 0 && f->ipv4_prefix < 32)
                                route4_add(d, ip4, f->ipv4_prefix, 0, f->ifindex, 0, 254u);
                        } else {
                            if (f->ipv4_prefix > 0 && f->ipv4_prefix < 32)
                                route4_del(d, f->ipv4_addr, f->ipv4_prefix, f->ifindex);
                            f->ipv4_addr = 0;
                            f->ipv4_mask = 0;
                            f->ipv4_prefix = 0;
                        }
                        net_recompute_tun_active(d);
                    } else if (has_addr && ia.family == AF_INET6) {
                        if (req.type == NL_RTM_NEWADDR) {
                            memcpy(f->ipv6_addr, addr, 16);
                            f->ipv6_prefix = ia.prefixlen <= 128 ? ia.prefixlen : 128;
                            f->has_v6 = 1;
                            if (f->ipv6_prefix > 0 && f->ipv6_prefix < 128) {
                                uint8_t zero[16] = {0};
                                route6_add(d, addr, f->ipv6_prefix, zero, f->ifindex, 0);
                            }
                        } else {
                            f->has_v6 = 0;
                            memset(f->ipv6_addr, 0, 16);
                            f->ipv6_prefix = 0;
                        }
                        net_recompute_tun_active(d);
                    }
                }
            }
            if (req.flags & NL_F_ACK) nl_send_ack(nc->fd, &req, pid, err);
        } else if (req.type == NL_RTM_NEWROUTE || req.type == NL_RTM_DELROUTE) {
            int err = 0;
            if (blen >= sizeof(struct nl_rtmsg)) {
                struct nl_rtmsg rm;
                memcpy(&rm, body, sizeof(rm));
                uint8_t dst[16] = {0}, gw[16] = {0};
                uint32_t oif = 0, prio = 0, tbl = rm.table;
                size_t roff = sizeof(rm);
                while (roff + sizeof(struct nl_rta) <= blen) {
                    struct nl_rta rta;
                    memcpy(&rta, body + roff, sizeof(rta));
                    if (rta.len < sizeof(rta) || roff + rta.len > blen) break;
                    const uint8_t *val = body + roff + sizeof(rta);
                    size_t vlen = rta.len - sizeof(rta);
                    if (rta.type == NL_RTA_DST && vlen >= (rm.family == AF_INET6 ? 16u : 4u))
                        memcpy(dst, val, rm.family == AF_INET6 ? 16u : 4u);
                    else if (rta.type == NL_RTA_GATEWAY && vlen >= (rm.family == AF_INET6 ? 16u : 4u))
                        memcpy(gw, val, rm.family == AF_INET6 ? 16u : 4u);
                    else if (rta.type == NL_RTA_OIF && vlen >= 4)
                        memcpy(&oif, val, 4);
                    else if (rta.type == NL_RTA_PRIORITY && vlen >= 4)
                        memcpy(&prio, val, 4);
                    else if (rta.type == NL_RTA_TABLE && vlen >= 4)
                        memcpy(&tbl, val, 4);
                    roff += NL_ALIGN(rta.len);
                }
                if (rm.family == AF_INET) {
                    uint32_t d4 = 0, g4 = 0;
                    memcpy(&d4, dst, 4);
                    memcpy(&g4, gw, 4);
                    if (req.type == NL_RTM_NEWROUTE && oif > 0)
                        err = route4_add(d, d4, rm.dst_len, g4, oif, prio, tbl);
                    else if (req.type == NL_RTM_DELROUTE)
                        err = route4_del(d, d4, rm.dst_len, oif);
                } else if (rm.family == AF_INET6) {
                    if (req.type == NL_RTM_NEWROUTE && oif > 0)
                        err = route6_add(d, dst, rm.dst_len, gw, oif, prio);
                    else if (req.type == NL_RTM_DELROUTE)
                        err = route6_del(d, dst, rm.dst_len, oif);
                }
            }
            if (req.flags & NL_F_ACK) nl_send_ack(nc->fd, &req, pid, err);
        } else {
            /* Accept RTM_NEWRULE / RTM_DELRULE and other non-fatal netlink ops cleanly. */
            if (req.flags & NL_F_ACK)
                nl_send_ack(nc->fd, &req, pid, 0);
        }

        off += NL_ALIGN(req.len);
    }
}

/* ---- TUN Data Path ---- */

int net_tun_send_packet(struct net_daemon *d, uint32_t ifindex, const uint8_t *pkt, size_t len)
{
    struct tun_dev *td = net_find_tun_by_ifindex(d, ifindex);
    if (!td || td->data_fd < 0)
        return -1;
    struct sv_net_iface *f = net_find_iface_by_idx(d, ifindex);

    if (td->flags & SV_IFF_NO_PI) {
        ssize_t w = send(td->data_fd, pkt, len, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (w < 0) return -1;
    } else {
        uint8_t pi[4] = { 0, 0, 0x08, 0x00 };
        if (len >= 1 && (pkt[0] >> 4) == 6u) {
            pi[2] = 0x86; pi[3] = 0xdd;
        }
        struct iovec iov[2] = { { pi, 4 }, { (void *)pkt, len } };
        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = iov;
        msg.msg_iovlen = 2;
        ssize_t w = sendmsg(td->data_fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (w < 0) return -1;
    }
    if (f) {
        f->rx_packets++;
        f->rx_bytes += len;
    }
    return 0;
}

static void tun_on_readable(struct net_daemon *d, int tidx, uint32_t events)
{
    struct tun_dev *td = &d->tuns[tidx];
    if (!td->active) return;

    uint8_t buf[NET_MAX_PKT_SIZE];
    int closed = 0;
    for (int budget = 0; budget < 64; budget++) {
        ssize_t n = recv(td->data_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n > 0) {
            const uint8_t *pkt = buf;
            size_t plen = (size_t)n;
            if (!(td->flags & SV_IFF_NO_PI)) {
                if (plen <= 4u) continue;
                pkt += 4;
                plen -= 4;
            }
            if (td->ifindex) {
                struct sv_net_iface *f = net_find_iface_by_idx(d, td->ifindex);
                if (f) {
                    f->tx_packets++;
                    f->tx_bytes += plen;
                }
                stack_on_tun_packet(d, td->ifindex, pkt, plen);
            }
        } else if (n == 0) {
            closed = 1;
            break;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        } else {
            closed = 1;
            break;
        }
    }

    if (closed || (events & (EPOLLHUP | EPOLLRDHUP | EPOLLERR))) {
        uint32_t old_if = td->ifindex;
        epoll_ctl(d->ep_fd, EPOLL_CTL_DEL, td->data_fd, NULL);
        close(td->data_fd);
        td->data_fd = -1;
        td->active = 0;
        td->ifindex = 0;

        /* Only tear down virtual interface if no other queue shares it. */
        if (old_if && !net_find_tun_by_ifindex(d, old_if)) {
            struct sv_net_iface *f = net_find_iface_by_idx(d, old_if);
            if (f) {
                if (d->log_level >= 2)
                    fprintf(stderr, "[svbox-net] TUN '%s' (ifindex=%u) closed, tearing down\n",
                            f->name, old_if);
                stack_on_tun_closed(d, old_if);
                routes_clear_iface(d, old_if);
                f->flags = 0;
                nl_broadcast_link(d, NL_RTM_DELLINK, f);
                f->active = 0;
                net_recompute_tun_active(d);
            }
        }
    }
}

/* ---- Control Socket RPC Handlers ---- */

static int handle_tun_ioctl(struct net_daemon *d, uint32_t tun_id,
                            const struct vdev_ioctl_req *req,
                            const uint8_t *in_data, uint8_t *out_data, uint32_t *out_len)
{
    *out_len = 0;
    struct tun_dev *td = NULL;
    for (int i = 0; i < NET_MAX_TUNS; i++) {
        if (d->tuns[i].active && d->tuns[i].tun_id == tun_id) {
            td = &d->tuns[i];
            break;
        }
    }
    if (!td)
        return -EBADFD;

    uint32_t cmd = (uint32_t)req->cmd;
    if (cmd == SV_TUNSETIFF) {
        if (req->in_len < 40) return -EINVAL;
        uint8_t ifr[40];
        memcpy(ifr, in_data, 40);
        char req_name[16];
        memcpy(req_name, ifr, 16);
        req_name[15] = '\0';
        uint16_t flags = 0;
        memcpy(&flags, ifr + 16, 2);

        char resolved[16];
        if (!req_name[0] || strstr(req_name, "%d") != NULL) {
            const char *pfx = "tun";
            char tmp_pfx[12] = "tun";
            const char *pct = strstr(req_name, "%d");
            if (pct && pct > req_name) {
                size_t pl = (size_t)(pct - req_name);
                if (pl >= sizeof(tmp_pfx)) pl = sizeof(tmp_pfx) - 1;
                memcpy(tmp_pfx, req_name, pl);
                tmp_pfx[pl] = '\0';
                pfx = tmp_pfx;
            }
            resolved[0] = '\0';
            for (int n = 0; n < 64; n++) {
                snprintf(resolved, sizeof(resolved), "%s%d", pfx, n);
                if (!find_iface_by_name(d, resolved))
                    break;
                resolved[0] = '\0';
            }
            if (!resolved[0]) return -ENOSPC;
        } else {
            strncpy(resolved, req_name, sizeof(resolved) - 1);
            resolved[15] = '\0';
        }

        struct sv_net_iface *f = find_iface_by_name(d, resolved);
        if (!f) {
            f = alloc_iface(d, resolved,
                            SV_IFF_POINTOPOINT | SV_IFF_NOARP | SV_IFF_MULTICAST,
                            1500u, 1);
            if (!f) return -ENOSPC;
            if (d->log_level >= 2)
                fprintf(stderr, "[svbox-net] TUNSETIFF created '%s' (ifindex=%u flags=0x%x)\n",
                        f->name, f->ifindex, flags);
            nl_broadcast_link(d, NL_RTM_NEWLINK, f);
        } else if (!f->is_tun) {
            return -EINVAL;
        }
        td->ifindex = f->ifindex;
        td->flags = flags;
        memset(ifr, 0, 16);
        strncpy((char *)ifr, f->name, 15);
        memcpy(out_data, ifr, 40);
        *out_len = 40;
        net_recompute_tun_active(d);
        return 0;
    }
    if (cmd == SV_TUNGETIFF) {
        if (!td->ifindex) return -EBADFD;
        struct sv_net_iface *f = net_find_iface_by_idx(d, td->ifindex);
        if (!f) return -ENODEV;
        uint8_t ifr[40];
        memset(ifr, 0, sizeof(ifr));
        strncpy((char *)ifr, f->name, 15);
        uint16_t fl = (uint16_t)td->flags;
        memcpy(ifr + 16, &fl, 2);
        memcpy(out_data, ifr, 40);
        *out_len = 40;
        return 0;
    }
    if (cmd == SV_TUNGETFEATURES) {
        uint32_t feat = SV_IFF_TUN | SV_IFF_NO_PI | SV_IFF_MULTI_QUEUE;
        memcpy(out_data, &feat, 4);
        *out_len = 4;
        return 0;
    }
    if (cmd == SV_TUNGETVNETHDRSZ) {
        uint32_t zero = 0;
        memcpy(out_data, &zero, 4);
        *out_len = 4;
        return 0;
    }
    if (cmd == SV_TUNSETPERSIST || cmd == SV_TUNSETOWNER || cmd == SV_TUNSETGROUP ||
        cmd == SV_TUNSETVNETHDRSZ || cmd == SV_TUNSETQUEUE) {
        return 0;
    }
    return -ENOTTY;
}

static int handle_sioc(struct net_daemon *d, const struct sv_net_sioc_req *sreq,
                       const uint8_t *data, uint8_t *out_data, uint32_t *out_len)
{
    *out_len = 0;
    uint32_t cmd = sreq->cmd;
    if (cmd == SV_SIOCADDRT || cmd == SV_SIOCDELRT) {
        if (sreq->data_len < 136) return -EINVAL;
        /* rtentry offsets (LP64): dst=8, gw=24, mask=40, flags=56, metric=80, dev_str=120 */
        struct sockaddr_in dst, gw, mask;
        memcpy(&dst, data + 8, sizeof(dst));
        memcpy(&gw, data + 24, sizeof(gw));
        memcpy(&mask, data + 40, sizeof(mask));
        int16_t metric = 0;
        memcpy(&metric, data + 80, 2);
        char dev[16];
        memcpy(dev, data + 120, 16);
        dev[15] = '\0';
        struct sv_net_iface *f = dev[0] ? find_iface_by_name(d, dev) : NULL;
        uint32_t pfx = mask4_to_prefix(mask.sin_addr.s_addr);
        if (cmd == SV_SIOCADDRT) {
            if (!f) {
                /* Pick first UP non-loopback iface if dev omitted */
                for (int i = 0; i < SV_NET_MAX_IFACES; i++) {
                    if (d->st->ifaces[i].active && !(d->st->ifaces[i].flags & SV_IFF_LOOPBACK) &&
                        (d->st->ifaces[i].flags & SV_IFF_UP)) {
                        f = &d->st->ifaces[i];
                        break;
                    }
                }
            }
            if (!f) return -ENODEV;
            uint32_t m = metric > 0 ? (uint32_t)(metric - 1) : 0u;
            return route4_add(d, dst.sin_addr.s_addr, pfx, gw.sin_addr.s_addr, f->ifindex, m, 254u);
        }
        return route4_del(d, dst.sin_addr.s_addr, pfx, f ? f->ifindex : 0u);
    }

    if (sreq->data_len < 40) return -EINVAL;
    uint8_t ifr[40];
    memcpy(ifr, data, 40);
    if (cmd == SV_SIOCGIFNAME) {
        int32_t idx = 0;
        memcpy(&idx, ifr + 16, 4);
        struct sv_net_iface *f = net_find_iface_by_idx(d, (uint32_t)idx);
        if (!f) return -ENODEV;
        memset(ifr, 0, 16);
        strncpy((char *)ifr, f->name, 15);
        memcpy(out_data, ifr, 40);
        *out_len = 40;
        return 0;
    }

    char name[16];
    memcpy(name, ifr, 16);
    name[15] = '\0';
    struct sv_net_iface *f = find_iface_by_name(d, name);
    if (!f) return -ENODEV;

    switch (cmd) {
    case SV_SIOCGIFFLAGS: {
        int16_t fl = (int16_t)f->flags;
        memcpy(ifr + 16, &fl, 2);
        break;
    }
    case SV_SIOCSIFFLAGS: {
        uint16_t fl = 0;
        memcpy(&fl, ifr + 16, 2);
        f->flags = fl;
        if (f->flags & SV_IFF_UP) f->flags |= SV_IFF_RUNNING;
        else f->flags &= ~SV_IFF_RUNNING;
        net_recompute_tun_active(d);
        nl_broadcast_link(d, NL_RTM_NEWLINK, f);
        break;
    }
    case SV_SIOCGIFADDR:
    case SV_SIOCGIFDSTADDR: {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = f->ipv4_addr;
        memcpy(ifr + 16, &sa, sizeof(sa));
        break;
    }
    case SV_SIOCSIFADDR: {
        struct sockaddr_in sa;
        memcpy(&sa, ifr + 16, sizeof(sa));
        f->ipv4_addr = sa.sin_addr.s_addr;
        if (f->ipv4_prefix == 0) {
            f->ipv4_prefix = 24;
            f->ipv4_mask = prefix_to_mask4(24);
        }
        if (f->ipv4_prefix > 0 && f->ipv4_prefix < 32)
            route4_add(d, f->ipv4_addr, f->ipv4_prefix, 0, f->ifindex, 0, 254u);
        net_recompute_tun_active(d);
        nl_broadcast_addr4(d, NL_RTM_NEWADDR, f);
        break;
    }
    case SV_SIOCSIFDSTADDR:
        break;
    case SV_SIOCGIFNETMASK: {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = f->ipv4_mask;
        memcpy(ifr + 16, &sa, sizeof(sa));
        break;
    }
    case SV_SIOCSIFNETMASK: {
        struct sockaddr_in sa;
        memcpy(&sa, ifr + 16, sizeof(sa));
        uint32_t old_pfx = f->ipv4_prefix;
        if (f->ipv4_addr && old_pfx > 0 && old_pfx < 32)
            route4_del(d, f->ipv4_addr, old_pfx, f->ifindex);
        f->ipv4_mask = sa.sin_addr.s_addr;
        f->ipv4_prefix = mask4_to_prefix(f->ipv4_mask);
        if (f->ipv4_addr && f->ipv4_prefix > 0 && f->ipv4_prefix < 32)
            route4_add(d, f->ipv4_addr, f->ipv4_prefix, 0, f->ifindex, 0, 254u);
        net_recompute_tun_active(d);
        break;
    }
    case SV_SIOCGIFBRDADDR: {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = f->ipv4_addr | ~f->ipv4_mask;
        memcpy(ifr + 16, &sa, sizeof(sa));
        break;
    }
    case SV_SIOCGIFMTU: {
        int32_t mtu = (int32_t)f->mtu;
        memcpy(ifr + 16, &mtu, 4);
        break;
    }
    case SV_SIOCSIFMTU: {
        int32_t mtu = 0;
        memcpy(&mtu, ifr + 16, 4);
        if (mtu < 576 || mtu > 65535) return -EINVAL;
        f->mtu = (uint32_t)mtu;
        net_recompute_tun_active(d);
        break;
    }
    case SV_SIOCGIFHWADDR: {
        uint16_t fam = (f->flags & SV_IFF_LOOPBACK) ? 772u : (f->is_tun ? 65534u : 1u);
        memset(ifr + 16, 0, 16);
        memcpy(ifr + 16, &fam, 2);
        memcpy(ifr + 18, f->mac, 6);
        break;
    }
    case SV_SIOCGIFINDEX: {
        int32_t idx = (int32_t)f->ifindex;
        memcpy(ifr + 16, &idx, 4);
        break;
    }
    case SV_SIOCGIFTXQLEN: {
        int32_t qlen = 1000;
        memcpy(ifr + 16, &qlen, 4);
        break;
    }
    case SV_SIOCSIFTXQLEN: {
        int32_t qlen = 0;
        memcpy(&qlen, ifr + 16, 4);
        if (qlen < 0) return -EINVAL;
        break;
    }
    default:
        return -ENOTTY;
    }
    memcpy(out_data, ifr, 40);
    *out_len = 40;
    return 0;
}

static void handle_ctl_client(struct net_daemon *d, int cfd)
{
    struct vdev_hdr hdr;
    if (recv_all(cfd, &hdr, sizeof(hdr)) < 0 || hdr.magic != VDEV_PROTO_MAGIC ||
        hdr.payload_len > 16384u) {
        close(cfd);
        return;
    }
    uint8_t pbuf[16384];
    if (hdr.payload_len > 0 && recv_all(cfd, pbuf, hdr.payload_len) < 0) {
        close(cfd);
        return;
    }

    if (hdr.op == VDEV_OP_OPEN) {
        int slot = -1;
        for (int i = 0; i < NET_MAX_TUNS; i++) {
            if (!d->tuns[i].active) { slot = i; break; }
        }
        if (slot < 0) {
            net_send_ctl_reply(cfd, hdr.op, -EMFILE, 0, 0, NULL, 0, -1);
            close(cfd);
            return;
        }
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) < 0) {
            net_send_ctl_reply(cfd, hdr.op, -errno, 0, 0, NULL, 0, -1);
            close(cfd);
            return;
        }
        int bufsz = 524288;
        setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
        setsockopt(sv[0], SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
        setsockopt(sv[1], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
        setsockopt(sv[1], SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
        int fl = fcntl(sv[1], F_GETFL, 0);
        if (fl >= 0) fcntl(sv[1], F_SETFL, fl | O_NONBLOCK);

        struct tun_dev *td = &d->tuns[slot];
        memset(td, 0, sizeof(*td));
        td->active = 1;
        td->tun_id = d->next_tun_id++;
        td->data_fd = sv[1];
        td->tag.kind = EP_TUN_DATA;
        td->tag.idx = slot;
        td->tag.fd = sv[1];

        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN | EPOLLRDHUP | EPOLLHUP;
        ev.data.ptr = &td->tag;
        if (epoll_ctl(d->ep_fd, EPOLL_CTL_ADD, sv[1], &ev) < 0) {
            close(sv[0]); close(sv[1]);
            td->active = 0;
            net_send_ctl_reply(cfd, hdr.op, -errno, 0, 0, NULL, 0, -1);
            close(cfd);
            return;
        }

        struct vdev_open_rep rep = {
            .proc_id = td->tun_id,
            .major = 10,
            .minor = 200,
            .memfd_size = 0,
        };
        net_send_ctl_reply(cfd, hdr.op, 0, td->tun_id, 0, &rep, sizeof(rep), sv[0]);
        close(sv[0]);
        close(cfd);
        return;
    }

    if (hdr.op == VDEV_OP_IOCTL) {
        if (hdr.payload_len < sizeof(struct vdev_ioctl_req)) {
            net_send_ctl_reply(cfd, hdr.op, -EINVAL, hdr.proc_id, 0, NULL, 0, -1);
            close(cfd);
            return;
        }
        struct vdev_ioctl_req ireq;
        memcpy(&ireq, pbuf, sizeof(ireq));
        uint8_t out[128];
        uint32_t out_len = 0;
        int rc = handle_tun_ioctl(d, hdr.proc_id, &ireq, pbuf + sizeof(ireq), out, &out_len);
        net_send_ctl_reply(cfd, hdr.op, rc, hdr.proc_id, 0, out, out_len, -1);
        close(cfd);
        return;
    }

    if (hdr.op == NET_OP_GET_STATE) {
        net_send_ctl_reply(cfd, hdr.op, 0, 0, (uint64_t)sizeof(struct sv_net_state),
                           NULL, 0, d->state_memfd);
        close(cfd);
        return;
    }

    if (hdr.op == NET_OP_OPEN_NETLINK) {
        int slot = -1;
        for (int i = 0; i < NET_MAX_NLS; i++) {
            if (!d->nls[i].active) { slot = i; break; }
        }
        if (slot < 0) {
            net_send_ctl_reply(cfd, hdr.op, -EMFILE, 0, 0, NULL, 0, -1);
            close(cfd);
            return;
        }
        int sv[2];
        if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) < 0) {
            net_send_ctl_reply(cfd, hdr.op, -errno, 0, 0, NULL, 0, -1);
            close(cfd);
            return;
        }
        int fl = fcntl(sv[1], F_GETFL, 0);
        if (fl >= 0) fcntl(sv[1], F_SETFL, fl | O_NONBLOCK);

        struct nl_client *nc = &d->nls[slot];
        memset(nc, 0, sizeof(*nc));
        nc->active = 1;
        nc->nl_id = d->next_nl_id++;
        nc->pid = (uint32_t)hdr.arg0;
        nc->fd = sv[1];
        nc->tag.kind = EP_NL_SOCK;
        nc->tag.idx = slot;
        nc->tag.fd = sv[1];

        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN | EPOLLRDHUP | EPOLLHUP;
        ev.data.ptr = &nc->tag;
        if (epoll_ctl(d->ep_fd, EPOLL_CTL_ADD, sv[1], &ev) < 0) {
            close(sv[0]); close(sv[1]);
            nc->active = 0;
            net_send_ctl_reply(cfd, hdr.op, -errno, 0, 0, NULL, 0, -1);
            close(cfd);
            return;
        }
        net_send_ctl_reply(cfd, hdr.op, 0, nc->nl_id, 0, NULL, 0, sv[0]);
        close(sv[0]);
        close(cfd);
        return;
    }

    if (hdr.op == NET_OP_NL_BIND) {
        for (int i = 0; i < NET_MAX_NLS; i++) {
            if (d->nls[i].active && d->nls[i].nl_id == hdr.proc_id) {
                d->nls[i].groups = (uint32_t)hdr.arg0;
                if (hdr.arg1 != 0)
                    d->nls[i].pid = (uint32_t)hdr.arg1;
                break;
            }
        }
        net_send_ctl_reply(cfd, hdr.op, 0, hdr.proc_id, 0, NULL, 0, -1);
        close(cfd);
        return;
    }

    if (hdr.op == NET_OP_FLOW_ADD) {
        if (hdr.payload_len < sizeof(struct sv_net_flow_req)) {
            net_send_ctl_reply(cfd, hdr.op, -EINVAL, 0, 0, NULL, 0, -1);
            close(cfd);
            return;
        }
        struct sv_net_flow_req fr;
        memcpy(&fr, pbuf, sizeof(fr));
        struct sv_net_iface *ifc = net_find_iface_by_idx(d, fr.tun_ifindex);
        if (!ifc || !ifc->is_tun) {
            net_send_ctl_reply(cfd, hdr.op, -ENETUNREACH, 0, 0, NULL, 0, -1);
            close(cfd);
            return;
        }
        int slot = -1, free_s = -1;
        uint64_t oldest = UINT64_MAX;
        int oldest_s = 0;
        for (int i = 0; i < SV_NET_FLOW_CAP; i++) {
            if (d->flows[i].active && d->flows[i].proto == fr.proto &&
                d->flows[i].local_port == fr.local_port && d->flows[i].is_v6 == fr.is_v6) {
                slot = i; break;
            }
            if (!d->flows[i].active && free_s < 0) free_s = i;
            if (d->flows[i].active && d->flows[i].last_ms < oldest) {
                oldest = d->flows[i].last_ms; oldest_s = i;
            }
        }
        if (slot < 0) slot = (free_s >= 0) ? free_s : oldest_s;
        struct pending_flow *fl = &d->flows[slot];
        memset(fl, 0, sizeof(*fl));
        fl->active = 1;
        fl->proto = fr.proto;
        fl->is_v6 = fr.is_v6;
        fl->local_port = fr.local_port;
        fl->dst_port = fr.dst_port;
        fl->tun_ifindex = fr.tun_ifindex;
        memcpy(fl->dst_ip, fr.dst_ip, 16);
        if (fr.is_v6) {
            if (ifc->has_v6) memcpy(fl->tun_ip, ifc->ipv6_addr, 16);
            else { fl->tun_ip[0] = 0xfd; fl->tun_ip[15] = 1; }
        } else {
            uint32_t lip = ifc->ipv4_addr ? ifc->ipv4_addr : htonl(0xac130001u);
            memcpy(fl->tun_ip, &lip, 4);
        }
        fl->last_ms = net_now_ms();
        fl->encap = 0;
        net_sync_flow_slot(d, slot);
        net_send_ctl_reply(cfd, hdr.op, 0, 0, 0, NULL, 0, -1);
        close(cfd);
        return;
    }

    if (hdr.op == NET_OP_SIOC) {
        if (hdr.payload_len < sizeof(struct sv_net_sioc_req)) {
            net_send_ctl_reply(cfd, hdr.op, -EINVAL, 0, 0, NULL, 0, -1);
            close(cfd);
            return;
        }
        struct sv_net_sioc_req sreq;
        memcpy(&sreq, pbuf, sizeof(sreq));
        uint8_t out[64];
        uint32_t out_len = 0;
        int rc = handle_sioc(d, &sreq, pbuf + sizeof(sreq), out, &out_len);
        net_send_ctl_reply(cfd, hdr.op, rc, 0, 0, out, out_len, -1);
        close(cfd);
        return;
    }

    if (hdr.op == NET_OP_PROTECT_INO) {
        uint64_t ino = hdr.arg0;
        if (ino != 0) {
            int exists = 0;
            for (int i = 0; i < SV_NET_PROTECT_CAP; i++) {
                if (d->st->protected_inos[i] == ino) { exists = 1; break; }
            }
            if (!exists) {
                uint32_t pos = d->st->protect_cursor % SV_NET_PROTECT_CAP;
                d->st->protected_inos[pos] = ino;
                d->st->protect_cursor = pos + 1u;
            }
        }
        net_send_ctl_reply(cfd, hdr.op, 0, 0, 0, NULL, 0, -1);
        close(cfd);
        return;
    }

    if (hdr.op == NET_OP_IFACE_CFG && hdr.payload_len >= sizeof(struct sv_net_ifcfg_req)) {
        struct sv_net_ifcfg_req r;
        memcpy(&r, pbuf, sizeof(r));
        r.ifname[15] = '\0';
        struct sv_net_iface *f = find_iface_by_name(d, r.ifname);
        int rc = 0;
        if (!f) {
            rc = -ENODEV;
        } else if (r.action == SV_IFCFG_SET_FLAGS) {
            f->flags = r.flags;
            if (f->flags & SV_IFF_UP) f->flags |= SV_IFF_RUNNING;
            else f->flags &= ~SV_IFF_RUNNING;
            net_recompute_tun_active(d);
            nl_broadcast_link(d, NL_RTM_NEWLINK, f);
        } else if (r.action == SV_IFCFG_SET_MTU) {
            if (r.mtu >= 576u && r.mtu <= 65535u) f->mtu = r.mtu;
            else rc = -EINVAL;
            net_recompute_tun_active(d);
        } else if (r.action == SV_IFCFG_ADD_ADDR4) {
            f->ipv4_addr = r.ipv4_addr;
            f->ipv4_prefix = r.prefix <= 32 ? r.prefix : 32;
            f->ipv4_mask = prefix_to_mask4(f->ipv4_prefix);
            if (f->ipv4_prefix > 0 && f->ipv4_prefix < 32)
                route4_add(d, f->ipv4_addr, f->ipv4_prefix, 0, f->ifindex, 0, 254u);
            net_recompute_tun_active(d);
            nl_broadcast_addr4(d, NL_RTM_NEWADDR, f);
        } else if (r.action == SV_IFCFG_DEL_ADDR4 || r.action == SV_IFCFG_CLEAR_ADDRS) {
            if (f->ipv4_addr)
                nl_broadcast_addr4(d, NL_RTM_DELADDR, f);
            if (f->ipv4_addr && f->ipv4_prefix > 0 && f->ipv4_prefix < 32)
                route4_del(d, f->ipv4_addr, f->ipv4_prefix, f->ifindex);
            f->ipv4_addr = 0; f->ipv4_mask = 0; f->ipv4_prefix = 0;
            if (r.action == SV_IFCFG_CLEAR_ADDRS) {
                if (f->has_v6)
                    nl_broadcast_addr6(d, NL_RTM_DELADDR, f);
                f->has_v6 = 0; memset(f->ipv6_addr, 0, 16); f->ipv6_prefix = 0;
            }
            net_recompute_tun_active(d);
        } else if (r.action == SV_IFCFG_ADD_ADDR6) {
            memcpy(f->ipv6_addr, r.ipv6_addr, 16);
            f->ipv6_prefix = r.prefix <= 128 ? r.prefix : 128;
            f->has_v6 = 1;
            nl_broadcast_addr6(d, NL_RTM_NEWADDR, f);
            net_recompute_tun_active(d);
        } else if (r.action == SV_IFCFG_DEL_ADDR6) {
            f->has_v6 = 0; memset(f->ipv6_addr, 0, 16); f->ipv6_prefix = 0;
            net_recompute_tun_active(d);
        } else {
            rc = -EINVAL;
        }
        net_send_ctl_reply(cfd, hdr.op, rc, 0, 0, NULL, 0, -1);
        close(cfd);
        return;
    }

    if (hdr.op == NET_OP_ROUTE_CFG && hdr.payload_len >= sizeof(struct sv_net_rtcfg_req)) {
        struct sv_net_rtcfg_req r;
        memcpy(&r, pbuf, sizeof(r));
        r.ifname[15] = '\0';
        struct sv_net_iface *f = find_iface_by_name(d, r.ifname);
        int rc = 0;
        if (!f && r.action != SV_RTCFG_DEL4 && r.action != SV_RTCFG_DEL6) {
            rc = -ENODEV;
        } else if (r.action == SV_RTCFG_ADD4) {
            rc = route4_add(d, r.dst_v4, r.prefix, r.gw_v4, f->ifindex, r.metric, r.table);
        } else if (r.action == SV_RTCFG_DEL4) {
            rc = route4_del(d, r.dst_v4, r.prefix, f ? f->ifindex : 0u);
        } else if (r.action == SV_RTCFG_ADD6) {
            rc = route6_add(d, r.dst_v6, r.prefix, r.gw_v6, f->ifindex, r.metric);
        } else if (r.action == SV_RTCFG_DEL6) {
            rc = route6_del(d, r.dst_v6, r.prefix, f ? f->ifindex : 0u);
        } else if (r.action == SV_RTCFG_CLEAR_IFACE) {
            routes_clear_iface(d, f->ifindex);
        } else {
            rc = -EINVAL;
        }
        net_send_ctl_reply(cfd, hdr.op, rc, 0, 0, NULL, 0, -1);
        close(cfd);
        return;
    }

    if (hdr.op == NET_OP_UID_RULES && hdr.payload_len >= sizeof(struct sv_net_uid_rules_req)) {
        struct sv_net_uid_rules_req r;
        memcpy(&r, pbuf, sizeof(r));
        uint32_t cnt = r.count > SV_NET_MAX_UID_RULES ? SV_NET_MAX_UID_RULES : r.count;
        d->st->uid_mode = r.mode;
        d->st->uid_rule_count = cnt;
        memcpy(d->st->uid_ranges, r.ranges, cnt * sizeof(struct sv_net_uid_range));
        __atomic_add_fetch(&d->st->seq, 1u, __ATOMIC_RELEASE);
        net_send_ctl_reply(cfd, hdr.op, 0, 0, 0, NULL, 0, -1);
        close(cfd);
        return;
    }

    if (hdr.op == NET_OP_SET_DNS && hdr.payload_len >= sizeof(struct sv_net_dns_req)) {
        struct sv_net_dns_req r;
        memcpy(&r, pbuf, sizeof(r));
        uint32_t cnt = r.count > SV_NET_MAX_DNS ? SV_NET_MAX_DNS : r.count;
        d->st->dns_count = cnt;
        memset(d->st->dns_v4, 0, sizeof(d->st->dns_v4));
        for (uint32_t i = 0; i < cnt; i++)
            d->st->dns_v4[i] = r.servers_v4[i];
        __atomic_add_fetch(&d->st->seq, 1u, __ATOMIC_RELEASE);
        net_send_ctl_reply(cfd, hdr.op, 0, 0, 0, NULL, 0, -1);
        close(cfd);
        return;
    }

    if (hdr.op == NET_OP_DNS_QUERY && hdr.payload_len > sizeof(struct sv_net_dns_query_req)) {
        struct sv_net_dns_query_req qreq;
        memcpy(&qreq, pbuf, sizeof(qreq));
        int rc = stack_start_dns_query(d, cfd, hdr.proc_id, &qreq,
                                       pbuf + sizeof(qreq), hdr.payload_len - sizeof(qreq));
        if (rc < 0) {
            net_send_ctl_reply(cfd, hdr.op, rc, hdr.proc_id, 0, NULL, 0, -1);
            close(cfd);
        }
        /* Keep cfd open until DNS reply arrives from TUN or times out! */
        return;
    }

    net_send_ctl_reply(cfd, hdr.op, -ENOSYS, hdr.proc_id, 0, NULL, 0, -1);
    close(cfd);
}

/* ---- Loopback Relay Socket Setup ---- */

static int open_loop_tcp(int is_v6, uint16_t *port_out)
{
    int fd = socket(is_v6 ? AF_INET6 : AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (is_v6) {
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
        struct sockaddr_in6 a;
        memset(&a, 0, sizeof(a));
        a.sin6_family = AF_INET6;
        a.sin6_addr = in6addr_loopback;
        if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0 || listen(fd, 512) < 0) {
            close(fd); return -1;
        }
        socklen_t len = sizeof(a);
        getsockname(fd, (struct sockaddr *)&a, &len);
        *port_out = ntohs(a.sin6_port);
    } else {
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0 || listen(fd, 512) < 0) {
            close(fd); return -1;
        }
        socklen_t len = sizeof(a);
        getsockname(fd, (struct sockaddr *)&a, &len);
        *port_out = ntohs(a.sin_port);
    }
    return fd;
}

static int open_loop_udp(int is_v6, uint16_t *port_out)
{
    int fd = socket(is_v6 ? AF_INET6 : AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int bufsz = 524288;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof(bufsz));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof(bufsz));
    if (is_v6) {
        int one = 1;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
        struct sockaddr_in6 a;
        memset(&a, 0, sizeof(a));
        a.sin6_family = AF_INET6;
        a.sin6_addr = in6addr_loopback;
        if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) { close(fd); return -1; }
        socklen_t len = sizeof(a);
        getsockname(fd, (struct sockaddr *)&a, &len);
        *port_out = ntohs(a.sin6_port);
    } else {
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) { close(fd); return -1; }
        socklen_t len = sizeof(a);
        getsockname(fd, (struct sockaddr *)&a, &len);
        *port_out = ntohs(a.sin_port);
    }
    return fd;
}

static void add_ep(struct net_daemon *d, int fd, struct ep_tag *tag, int kind, int idx)
{
    if (fd < 0) return;
    tag->kind = kind;
    tag->idx = idx;
    tag->fd = fd;
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.ptr = tag;
    epoll_ctl(d->ep_fd, EPOLL_CTL_ADD, fd, &ev);
}

/* Parse "NAME:IP/PREFIX[:GW[:MAC]]" */
static void add_cli_iface(struct net_daemon *d, const char *spec)
{
    char copy[128];
    strncpy(copy, spec, sizeof(copy) - 1);
    copy[sizeof(copy) - 1] = '\0';
    char *p1 = strchr(copy, ':');
    if (!p1) return;
    *p1++ = '\0';
    char *p2 = strchr(p1, ':');
    char *gw_str = NULL, *mac_str = NULL;
    if (p2) {
        *p2++ = '\0';
        gw_str = p2;
        char *p3 = strchr(p2, ':');
        if (p3) { *p3++ = '\0'; mac_str = p3; }
    }
    char *slash = strchr(p1, '/');
    uint32_t prefix = 24;
    if (slash) {
        *slash++ = '\0';
        prefix = (uint32_t)atoi(slash);
        if (prefix > 32) prefix = 32;
    }
    struct in_addr ip4;
    if (inet_pton(AF_INET, p1, &ip4) != 1)
        return;

    struct sv_net_iface *f = alloc_iface(
        d, copy, SV_IFF_UP | SV_IFF_RUNNING | SV_IFF_BROADCAST | SV_IFF_MULTICAST, 1500u, 0);
    if (!f) return;
    f->ipv4_addr = ip4.s_addr;
    f->ipv4_prefix = prefix;
    f->ipv4_mask = prefix_to_mask4(prefix);
    if (mac_str) {
        unsigned m[6];
        if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
            for (int i = 0; i < 6; i++) f->mac[i] = (uint8_t)m[i];
        }
    }
    if (prefix > 0 && prefix < 32)
        route4_add(d, ip4.s_addr, prefix, 0, f->ifindex, 0, 254u);
    if (gw_str && gw_str[0]) {
        struct in_addr gw;
        if (inet_pton(AF_INET, gw_str, &gw) == 1)
            route4_add(d, 0, 0, gw.s_addr, f->ifindex, 100u, 254u);
    }
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --sock PATH [--iface NAME:IP/PFX[:GW[:MAC]]] [--dns IP] [--log-level N]\n",
        prog);
}

int main(int argc, char **argv)
{
    const char *sock_path = NULL;
    const char *ifaces_cli[8];
    int iface_cnt = 0;
    const char *dns_cli[SV_NET_MAX_DNS];
    int dns_cnt = 0;
    int log_level = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--sock") == 0 && i + 1 < argc) {
            sock_path = argv[++i];
        } else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc && iface_cnt < 8) {
            ifaces_cli[iface_cnt++] = argv[++i];
        } else if (strcmp(argv[i], "--dns") == 0 && i + 1 < argc && dns_cnt < SV_NET_MAX_DNS) {
            dns_cli[dns_cnt++] = argv[++i];
        } else if (strcmp(argv[i], "--log-level") == 0 && i + 1 < argc) {
            log_level = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 1;
        }
    }
    if (!sock_path) {
        usage(argv[0]);
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    static struct net_daemon daemon_inst;
    struct net_daemon *d = &daemon_inst;
    memset(d, 0, sizeof(*d));
    d->log_level = log_level;
    d->next_ifindex = 1;
    d->next_tun_id = 1;
    d->next_nl_id = 1;
    for (int i = 0; i < NET_MAX_TCP_CONNS; i++) d->conns[i].relay_fd = -1;
    for (int i = 0; i < NET_MAX_TUNS; i++) d->tuns[i].data_fd = -1;
    for (int i = 0; i < NET_MAX_NLS; i++) d->nls[i].fd = -1;

    /* Create single-writer shared state memfd. */
    d->state_memfd = (int)syscall(__NR_memfd_create, "svbox_net_state", 1 /* MFD_CLOEXEC */);
    if (d->state_memfd < 0) {
        perror("memfd_create");
        return 1;
    }
    if (ftruncate(d->state_memfd, (off_t)sizeof(struct sv_net_state)) < 0) {
        perror("ftruncate");
        return 1;
    }
    d->st = (struct sv_net_state *)mmap(NULL, sizeof(struct sv_net_state),
                                        PROT_READ | PROT_WRITE, MAP_SHARED, d->state_memfd, 0);
    if (d->st == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    memset(d->st, 0, sizeof(struct sv_net_state));
    d->st->magic = SV_NET_STATE_MAGIC;
    d->st->version = SV_NET_STATE_VERSION;

    /* Populate default loopback + configured or default eth0 interfaces. */
    struct sv_net_iface *lo = alloc_iface(d, "lo", SV_IFF_UP | SV_IFF_LOOPBACK | SV_IFF_RUNNING, 65536u, 0);
    lo->ipv4_addr = htonl(0x7f000001u);
    lo->ipv4_prefix = 8;
    lo->ipv4_mask = prefix_to_mask4(8);
    lo->has_v6 = 1;
    lo->ipv6_addr[15] = 1;
    lo->ipv6_prefix = 128;

    if (iface_cnt == 0) {
        add_cli_iface(d, "eth0:10.0.2.15/24:10.0.2.2:02:00:00:00:00:01");
    } else {
        for (int i = 0; i < iface_cnt; i++)
            add_cli_iface(d, ifaces_cli[i]);
    }
    for (int i = 0; i < dns_cnt; i++) {
        struct in_addr a;
        if (inet_pton(AF_INET, dns_cli[i], &a) == 1)
            d->st->dns_v4[d->st->dns_count++] = a.s_addr;
    }

    /* Open loopback TCP/UDP relays. */
    d->tcp4_listen_fd = open_loop_tcp(0, &d->st->tcp_relay_port);
    d->tcp6_listen_fd = open_loop_tcp(1, &d->st->tcp_relay_port6);
    d->udp4_conn_fd   = open_loop_udp(0, &d->st->udp_conn_port);
    d->udp4_encap_fd  = open_loop_udp(0, &d->st->udp_encap_port);
    d->udp6_conn_fd   = open_loop_udp(1, &d->st->udp_conn_port6);
    d->udp6_encap_fd  = open_loop_udp(1, &d->st->udp_encap_port6);
    if (d->tcp4_listen_fd < 0 || d->udp4_conn_fd < 0 || d->udp4_encap_fd < 0) {
        perror("open loopback relays");
        return 1;
    }

    /* Open Unix control/vdev listener. */
    unlink(sock_path);
    d->ctl_listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (d->ctl_listen_fd < 0) {
        perror("socket AF_UNIX");
        return 1;
    }
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, sock_path, sizeof(sa.sun_path) - 1);
    if (bind(d->ctl_listen_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
        listen(d->ctl_listen_fd, 512) < 0) {
        perror("bind/listen net.sock");
        return 1;
    }
    chmod(sock_path, 0666);

    d->ep_fd = epoll_create1(EPOLL_CLOEXEC);
    if (d->ep_fd < 0) {
        perror("epoll_create1");
        return 1;
    }
    add_ep(d, d->ctl_listen_fd,  &d->ctl_tag,        EP_CTL_LISTEN,  0);
    add_ep(d, d->tcp4_listen_fd, &d->tcp4_tag,       EP_TCP4_LISTEN, 0);
    add_ep(d, d->tcp6_listen_fd, &d->tcp6_tag,       EP_TCP6_LISTEN, 0);
    add_ep(d, d->udp4_conn_fd,   &d->udp4_conn_tag,  EP_UDP4_CONN,   0);
    add_ep(d, d->udp4_encap_fd,  &d->udp4_encap_tag, EP_UDP4_ENCAP,  0);
    add_ep(d, d->udp6_conn_fd,   &d->udp6_conn_tag,  EP_UDP6_CONN,   0);
    add_ep(d, d->udp6_encap_fd,  &d->udp6_encap_tag, EP_UDP6_ENCAP,  0);

    stack_init(d);
    if (log_level >= 1) {
        fprintf(stderr, "[svbox-net] listening on %s (tcp4=%u udp4=%u/%u tcp6=%u)\n",
                sock_path, d->st->tcp_relay_port, d->st->udp_conn_port,
                d->st->udp_encap_port, d->st->tcp_relay_port6);
        fflush(stderr);
    }

    struct epoll_event events[256];
    uint64_t last_tick = net_now_ms();
    while (!g_stop) {
        int n = epoll_wait(d->ep_fd, events, 256, 15);
        for (int i = 0; i < n; i++) {
            struct ep_tag *tag = (struct ep_tag *)events[i].data.ptr;
            if (!tag) continue;
            switch (tag->kind) {
            case EP_CTL_LISTEN: {
                for (;;) {
                    int cfd = accept4(d->ctl_listen_fd, NULL, NULL, SOCK_CLOEXEC);
                    if (cfd < 0) break;
                    /* Clear O_NONBLOCK explicitly (some kernels inherit listener flags on accept4). */
                    int fl = fcntl(cfd, F_GETFL, 0);
                    if (fl >= 0 && (fl & O_NONBLOCK))
                        fcntl(cfd, F_SETFL, fl & ~O_NONBLOCK);
                    struct timeval tv = { 2, 0 };
                    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
                    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
                    handle_ctl_client(d, cfd);
                }
                break;
            }
            case EP_TCP4_LISTEN:
                stack_on_tcp_accept(d, d->tcp4_listen_fd, 0);
                break;
            case EP_TCP6_LISTEN:
                stack_on_tcp_accept(d, d->tcp6_listen_fd, 1);
                break;
            case EP_UDP4_CONN:
                stack_on_udp_relay_readable(d, d->udp4_conn_fd, 0, 0);
                break;
            case EP_UDP4_ENCAP:
                stack_on_udp_relay_readable(d, d->udp4_encap_fd, 0, 1);
                break;
            case EP_UDP6_CONN:
                stack_on_udp_relay_readable(d, d->udp6_conn_fd, 1, 0);
                break;
            case EP_UDP6_ENCAP:
                stack_on_udp_relay_readable(d, d->udp6_encap_fd, 1, 1);
                break;
            case EP_TUN_DATA:
                tun_on_readable(d, tag->idx, events[i].events);
                break;
            case EP_NL_SOCK: {
                struct nl_client *nc = &d->nls[tag->idx];
                if (!nc->active) break;
                uint8_t nbuf[8192];
                int closed = 0;
                for (;;) {
                    ssize_t r = recv(nc->fd, nbuf, sizeof(nbuf), MSG_DONTWAIT);
                    if (r > 0) {
                        nl_handle_packet(d, nc, nbuf, (size_t)r);
                    } else if (r == 0) {
                        closed = 1; break;
                    } else if (errno == EINTR) {
                        continue;
                    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break;
                    } else {
                        closed = 1; break;
                    }
                }
                if (closed || (events[i].events & (EPOLLHUP | EPOLLRDHUP | EPOLLERR))) {
                    epoll_ctl(d->ep_fd, EPOLL_CTL_DEL, nc->fd, NULL);
                    close(nc->fd);
                    nc->fd = -1;
                    nc->active = 0;
                }
                break;
            }
            case EP_TCP_RELAY:
                stack_on_tcp_relay_event(d, tag->idx, events[i].events);
                break;
            default:
                break;
            }
        }
        uint64_t now = net_now_ms();
        if (now >= last_tick + 10u) {
            stack_tick(d);
            last_tick = now;
        }
    }

    unlink(sock_path);
    return 0;
}
