/* SPDX-License-Identifier: MIT */
/* Userspace IPv4/IPv6 + TCP (RFC 793/7323) + UDP + ICMP engine for svbox-net.
 *
 * Bridges guest loopback relay sockets (AF_INET/AF_INET6) to raw L3 packets
 * flowing over virtual TUN devices (AF_UNIX SOCK_SEQPACKET). */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "net_internal.h"

#define TCP_FIN 0x01u
#define TCP_SYN 0x02u
#define TCP_RST 0x04u
#define TCP_PSH 0x08u
#define TCP_ACK 0x10u

static inline int seq_lt(uint32_t a, uint32_t b) { return (int32_t)(a - b) < 0; }
static inline int seq_le(uint32_t a, uint32_t b) { return (int32_t)(a - b) <= 0; }
static inline int seq_gt(uint32_t a, uint32_t b) { return (int32_t)(a - b) > 0; }
static inline int seq_ge(uint32_t a, uint32_t b) { return (int32_t)(a - b) >= 0; }

static inline uint16_t rd_be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
static inline uint32_t rd_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}
static inline void wr_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xffu);
}
static inline void wr_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)((v >> 16) & 0xffu);
    p[2] = (uint8_t)((v >> 8) & 0xffu);
    p[3] = (uint8_t)(v & 0xffu);
}

static uint32_t csum_add(uint32_t sum, const uint8_t *buf, size_t len)
{
    while (len >= 2) {
        sum += ((uint32_t)buf[0] << 8) | buf[1];
        buf += 2;
        len -= 2;
    }
    if (len == 1)
        sum += (uint32_t)buf[0] << 8;
    return sum;
}

static uint16_t csum_finish(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)(~sum & 0xffffu);
}

static uint16_t l4_checksum(int is_v6, const uint8_t src[16], const uint8_t dst[16],
                            uint8_t proto, const uint8_t *seg, size_t seg_len)
{
    uint32_t sum = 0;
    if (!is_v6) {
        sum = csum_add(sum, src, 4);
        sum = csum_add(sum, dst, 4);
        uint8_t ph[4] = { 0, proto, (uint8_t)(seg_len >> 8), (uint8_t)(seg_len & 0xffu) };
        sum = csum_add(sum, ph, 4);
    } else {
        sum = csum_add(sum, src, 16);
        sum = csum_add(sum, dst, 16);
        uint8_t ph[8] = {
            (uint8_t)(seg_len >> 24), (uint8_t)((seg_len >> 16) & 0xffu),
            (uint8_t)((seg_len >> 8) & 0xffu), (uint8_t)(seg_len & 0xffu),
            0, 0, 0, proto
        };
        sum = csum_add(sum, ph, 8);
    }
    sum = csum_add(sum, seg, seg_len);
    uint16_t c = csum_finish(sum);
    if (proto == 17u && c == 0)
        c = 0xffffu;
    return c;
}

static int send_l3_packet(struct net_daemon *d, uint32_t ifindex, int is_v6,
                          const uint8_t src[16], const uint8_t dst[16],
                          uint8_t proto, const uint8_t *l4, size_t l4_len)
{
    uint8_t pkt[NET_MAX_PKT_SIZE];
    size_t ip_len = is_v6 ? 40u : 20u;
    if (ip_len + l4_len > sizeof(pkt))
        return -1;

    if (!is_v6) {
        memset(pkt, 0, 20);
        pkt[0] = 0x45;
        wr_be16(pkt + 2, (uint16_t)(20u + l4_len));
        wr_be16(pkt + 4, ++d->next_ip_id);
        wr_be16(pkt + 6, 0x4000u); /* DF */
        pkt[8] = 64; /* TTL */
        pkt[9] = proto;
        memcpy(pkt + 12, src, 4);
        memcpy(pkt + 16, dst, 4);
        wr_be16(pkt + 10, csum_finish(csum_add(0, pkt, 20)));
    } else {
        memset(pkt, 0, 40);
        pkt[0] = 0x60;
        wr_be16(pkt + 4, (uint16_t)l4_len);
        pkt[6] = proto;
        pkt[7] = 64; /* Hop limit */
        memcpy(pkt + 8, src, 16);
        memcpy(pkt + 24, dst, 16);
    }
    memcpy(pkt + ip_len, l4, l4_len);
    return net_tun_send_packet(d, ifindex, pkt, ip_len + l4_len);
}

/* ---- TCP Connection Lifecycle & Helpers ---- */

static inline uint32_t tcp_hash_bucket(int is_v6, uint16_t local_port,
                                       uint16_t remote_port, const uint8_t remote_ip[16])
{
    uint32_t h = ((uint32_t)local_port << 16) | (uint32_t)remote_port;
    h ^= (uint32_t)is_v6 * 0x9e3779b9u;
    uint32_t w0 = 0;
    memcpy(&w0, remote_ip, 4);
    h ^= w0;
    if (is_v6) {
        uint32_t w1 = 0, w2 = 0, w3 = 0;
        memcpy(&w1, remote_ip + 4, 4);
        memcpy(&w2, remote_ip + 8, 4);
        memcpy(&w3, remote_ip + 12, 4);
        h ^= w1 * 0x85ebca6bu;
        h ^= w2 * 0xc2b2ae35u;
        h ^= w3;
    }
    h ^= h >> 16;
    h *= 0x7feb352du;
    h ^= h >> 15;
    return h & (NET_TCP_HASH_BUCKETS - 1u);
}

static void tcp_hash_insert(struct net_daemon *d, struct tcp_conn *c)
{
    uint32_t b = tcp_hash_bucket(c->is_v6, c->local_port, c->remote_port, c->remote_ip);
    c->hash_next = d->tcp_buckets[b];
    d->tcp_buckets[b] = c->idx;
}

static void tcp_hash_remove(struct net_daemon *d, struct tcp_conn *c)
{
    uint32_t b = tcp_hash_bucket(c->is_v6, c->local_port, c->remote_port, c->remote_ip);
    int *pp = &d->tcp_buckets[b];
    while (*pp >= 0) {
        int cur = *pp;
        if (cur == c->idx) {
            *pp = c->hash_next;
            c->hash_next = -1;
            return;
        }
        pp = &d->conns[cur].hash_next;
    }
    c->hash_next = -1;
}

static struct tcp_conn *tcp_hash_find(struct net_daemon *d, int is_v6,
                                      uint16_t local_port, uint16_t remote_port,
                                      const uint8_t remote_ip[16])
{
    size_t ip_cmp_len = is_v6 ? 16u : 4u;
    uint32_t b = tcp_hash_bucket(is_v6, local_port, remote_port, remote_ip);
    for (int idx = d->tcp_buckets[b]; idx >= 0; idx = d->conns[idx].hash_next) {
        struct tcp_conn *cand = &d->conns[idx];
        if (cand->active && cand->is_v6 == (uint8_t)is_v6 &&
            cand->local_port == local_port && cand->remote_port == remote_port &&
            memcmp(cand->remote_ip, remote_ip, ip_cmp_len) == 0) {
            return cand;
        }
    }
    return NULL;
}

static void tcp_free_ooo(struct tcp_conn *c)
{
    for (int i = 0; i < NET_TCP_OOO_MAX; i++) {
        if (c->ooo[i].used) {
            free(c->ooo[i].data);
            c->ooo[i].data = NULL;
            c->ooo[i].used = 0;
        }
    }
}

static void tcp_update_epoll(struct net_daemon *d, struct tcp_conn *c)
{
    if (c->relay_fd < 0)
        return;
    uint32_t ev = EPOLLRDHUP | EPOLLHUP | EPOLLERR;
    if ((c->state == TCP_ST_ESTABLISHED || c->state == TCP_ST_CLOSE_WAIT) &&
        !c->app_eof && (c->snd_write - c->snd_una) < NET_TCP_BUF_SIZE - 4096u) {
        ev |= EPOLLIN;
    }
    if (c->rx_len > 0)
        ev |= EPOLLOUT;

    struct epoll_event e;
    memset(&e, 0, sizeof(e));
    e.events = ev;
    e.data.ptr = &c->tag;
    epoll_ctl(d->ep_fd, EPOLL_CTL_MOD, c->relay_fd, &e);
    c->ep_out_armed = (ev & EPOLLOUT) ? 1 : 0;
}

static void tcp_destroy(struct net_daemon *d, struct tcp_conn *c, int abort_rst)
{
    if (!c->active)
        return;
    tcp_hash_remove(d, c);
    if (d->active_conns > 0)
        d->active_conns--;
    if (c->relay_fd >= 0) {
        epoll_ctl(d->ep_fd, EPOLL_CTL_DEL, c->relay_fd, NULL);
        if (abort_rst) {
            struct linger lg = { 1, 0 };
            setsockopt(c->relay_fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));
        }
        close(c->relay_fd);
        c->relay_fd = -1;
    }
    tcp_free_ooo(c);
    free(c->tx_buf);
    free(c->rx_buf);
    c->tx_buf = NULL;
    c->rx_buf = NULL;
    /* Clear flow entry for this TCP local_port so getsockname/getpeername stay tidy. */
    for (int i = 0; i < SV_NET_FLOW_CAP; i++) {
        if (d->flows[i].active && d->flows[i].proto == 6u &&
            d->flows[i].local_port == c->local_port &&
            d->flows[i].is_v6 == c->is_v6) {
            d->flows[i].active = 0;
            net_sync_flow_slot(d, i);
        }
    }
    c->active = 0;
    c->state = TCP_ST_CLOSED;
}

static uint16_t tcp_advertised_wnd(const struct tcp_conn *c)
{
    uint32_t avail = (c->rx_len < NET_TCP_BUF_SIZE) ? (NET_TCP_BUF_SIZE - c->rx_len) : 0u;
    uint32_t scaled = avail >> c->our_wscale;
    if (scaled > 0xffffu)
        scaled = 0xffffu;
    return (uint16_t)scaled;
}

static int tcp_send_seg(struct net_daemon *d, struct tcp_conn *c, uint8_t flags,
                        uint32_t seq, const uint8_t *payload, size_t plen)
{
    uint8_t seg[NET_MAX_PKT_SIZE];
    size_t hdr_len = (flags & TCP_SYN) ? 28u : 20u;
    if (hdr_len + plen > sizeof(seg))
        return -1;
    memset(seg, 0, hdr_len);
    wr_be16(seg + 0, c->local_port);
    wr_be16(seg + 2, c->remote_port);
    wr_be32(seg + 4, seq);
    wr_be32(seg + 8, (flags & TCP_ACK) ? c->rcv_nxt : 0u);
    seg[12] = (uint8_t)((hdr_len / 4u) << 4);
    seg[13] = flags;
    uint16_t wnd = (flags & TCP_SYN) ? 0xffffu : tcp_advertised_wnd(c);
    wr_be16(seg + 14, wnd);
    if (wnd == 0 && !(flags & (TCP_SYN | TCP_RST)))
        c->zero_wnd_sent = 1;
    else if (wnd > 0)
        c->zero_wnd_sent = 0;

    if (flags & TCP_SYN) {
        /* MSS option (4B) + NOP (1B) + Window Scale (3B) = 8B */
        struct sv_net_iface *ifc = net_find_iface_by_idx(d, c->tun_ifindex);
        uint32_t mtu = (ifc && ifc->mtu >= 576u) ? ifc->mtu : 1500u;
        uint32_t mss = mtu - (c->is_v6 ? 60u : 40u);
        if (mss > 1460u) mss = 1460u;
        if (mss < 536u) mss = 536u;
        seg[20] = 2; seg[21] = 4; wr_be16(seg + 22, (uint16_t)mss);
        seg[24] = 1; /* NOP */
        seg[25] = 3; seg[26] = 3; seg[27] = c->our_wscale;
    }
    if (plen > 0)
        memcpy(seg + hdr_len, payload, plen);
    wr_be16(seg + 16, l4_checksum(c->is_v6, c->local_ip, c->remote_ip, 6u, seg, hdr_len + plen));
    c->last_activity_ms = net_now_ms();
    return send_l3_packet(d, c->tun_ifindex, c->is_v6, c->local_ip, c->remote_ip,
                          6u, seg, hdr_len + plen);
}

static void tcp_send_raw_rst(struct net_daemon *d, uint32_t ifindex, int is_v6,
                             const uint8_t src[16], const uint8_t dst[16],
                             uint16_t sport, uint16_t dport,
                             uint32_t seq, uint32_t ack, int with_ack)
{
    uint8_t seg[20];
    memset(seg, 0, sizeof(seg));
    wr_be16(seg + 0, sport);
    wr_be16(seg + 2, dport);
    wr_be32(seg + 4, seq);
    wr_be32(seg + 8, with_ack ? ack : 0u);
    seg[12] = 0x50;
    seg[13] = with_ack ? (TCP_RST | TCP_ACK) : TCP_RST;
    wr_be16(seg + 16, l4_checksum(is_v6, src, dst, 6u, seg, sizeof(seg)));
    send_l3_packet(d, ifindex, is_v6, src, dst, 6u, seg, sizeof(seg));
}

static void tcp_read_tx_ring(const struct tcp_conn *c, uint32_t rel_off, uint8_t *dst, size_t len)
{
    uint32_t start = (c->tx_head + rel_off) % NET_TCP_BUF_SIZE;
    size_t first = NET_TCP_BUF_SIZE - start;
    if (first >= len) {
        memcpy(dst, c->tx_buf + start, len);
    } else {
        memcpy(dst, c->tx_buf + start, first);
        memcpy(dst + first, c->tx_buf, len - first);
    }
}

static void tcp_pump_tx(struct net_daemon *d, struct tcp_conn *c)
{
    if (c->state != TCP_ST_ESTABLISHED && c->state != TCP_ST_CLOSE_WAIT &&
        c->state != TCP_ST_FIN_WAIT_1 && c->state != TCP_ST_LAST_ACK)
        return;

    uint32_t mss = c->peer_mss ? c->peer_mss : 1460u;

    while (seq_lt(c->snd_nxt, c->snd_write)) {
        uint32_t in_flight = c->snd_nxt - c->snd_una;
        uint32_t eff_wnd = c->peer_wnd ? c->peer_wnd : (in_flight == 0 ? 1u : 0u);
        if (in_flight >= eff_wnd)
            break;
        uint32_t can_send = eff_wnd - in_flight;
        uint32_t unsent = c->snd_write - c->snd_nxt;
        uint32_t chunk = unsent < can_send ? unsent : can_send;
        if (chunk > mss)
            chunk = mss;
        uint8_t tmp[4096];
        if (chunk > sizeof(tmp)) chunk = sizeof(tmp);
        tcp_read_tx_ring(c, c->snd_nxt - c->snd_una, tmp, chunk);
        uint8_t fl = TCP_ACK | (chunk == unsent ? TCP_PSH : 0u);
        if (tcp_send_seg(d, c, fl, c->snd_nxt, tmp, chunk) < 0)
            break;
        c->snd_nxt += chunk;
        if (c->rtx_deadline_ms == 0)
            c->rtx_deadline_ms = net_now_ms() + c->rto_ms;
    }

    if (c->app_eof && !c->fin_sent && c->snd_nxt == c->snd_write) {
        if (tcp_send_seg(d, c, TCP_FIN | TCP_ACK, c->snd_nxt, NULL, 0) < 0)
            return;
        c->fin_sent = 1;
        c->fin_seq = c->snd_nxt;
        c->snd_nxt += 1u;
        if (c->state == TCP_ST_ESTABLISHED)
            c->state = TCP_ST_FIN_WAIT_1;
        else if (c->state == TCP_ST_CLOSE_WAIT)
            c->state = TCP_ST_LAST_ACK;
        if (c->rtx_deadline_ms == 0)
            c->rtx_deadline_ms = net_now_ms() + c->rto_ms;
    }
}

static void tcp_retransmit_una(struct net_daemon *d, struct tcp_conn *c)
{
    if (c->state == TCP_ST_SYN_SENT) {
        tcp_send_seg(d, c, TCP_SYN, c->snd_una, NULL, 0);
        return;
    }
    uint32_t data_end = c->fin_sent ? c->fin_seq : c->snd_nxt;
    if (seq_lt(c->snd_una, data_end)) {
        uint32_t mss = c->peer_mss ? c->peer_mss : 1460u;
        uint32_t rem = data_end - c->snd_una;
        uint32_t chunk = rem < mss ? rem : mss;
        uint8_t tmp[4096];
        if (chunk > sizeof(tmp)) chunk = sizeof(tmp);
        tcp_read_tx_ring(c, 0, tmp, chunk);
        tcp_send_seg(d, c, TCP_ACK | TCP_PSH, c->snd_una, tmp, chunk);
    } else if (c->fin_sent && seq_le(c->snd_una, c->fin_seq)) {
        tcp_send_seg(d, c, TCP_FIN | TCP_ACK, c->fin_seq, NULL, 0);
    }
}

static void tcp_flush_rx_to_relay(struct net_daemon *d, struct tcp_conn *c)
{
    while (c->rx_len > 0 && c->relay_fd >= 0) {
        uint32_t contig = NET_TCP_BUF_SIZE - c->rx_head;
        if (contig > c->rx_len)
            contig = c->rx_len;
        ssize_t w = send(c->relay_fd, c->rx_buf + c->rx_head, contig, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (w > 0) {
            c->rx_head = (c->rx_head + (uint32_t)w) % NET_TCP_BUF_SIZE;
            c->rx_len -= (uint32_t)w;
        } else if (w < 0 && errno == EINTR) {
            continue;
        } else if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        } else {
            /* Guest closed relay socket abruptly. */
            tcp_send_seg(d, c, TCP_RST | TCP_ACK, c->snd_nxt, NULL, 0);
            tcp_destroy(d, c, 0);
            return;
        }
    }
    if (c->rx_len == 0 && c->peer_fin && !c->peer_fin_shutdown && c->relay_fd >= 0) {
        c->peer_fin_shutdown = 1;
        shutdown(c->relay_fd, SHUT_WR);
    }
    if (c->zero_wnd_sent && tcp_advertised_wnd(c) > 0 &&
        (c->state == TCP_ST_ESTABLISHED || c->state == TCP_ST_FIN_WAIT_1 ||
         c->state == TCP_ST_FIN_WAIT_2)) {
        tcp_send_seg(d, c, TCP_ACK, c->snd_nxt, NULL, 0);
    }
    tcp_update_epoll(d, c);
}

static void tcp_append_rx(struct tcp_conn *c, const uint8_t *data, uint32_t len)
{
    if (len == 0) return;
    uint32_t avail = NET_TCP_BUF_SIZE - c->rx_len;
    if (len > avail) len = avail;
    uint32_t tail = (c->rx_head + c->rx_len) % NET_TCP_BUF_SIZE;
    uint32_t first = NET_TCP_BUF_SIZE - tail;
    if (first >= len) {
        memcpy(c->rx_buf + tail, data, len);
    } else {
        memcpy(c->rx_buf + tail, data, first);
        memcpy(c->rx_buf, data + first, len - first);
    }
    c->rx_len += len;
}

static void tcp_drain_ooo(struct tcp_conn *c)
{
    int progress = 1;
    while (progress) {
        progress = 0;
        for (int i = 0; i < NET_TCP_OOO_MAX; i++) {
            if (!c->ooo[i].used) continue;
            uint32_t s = c->ooo[i].seq;
            uint32_t l = c->ooo[i].len;
            if (seq_le(s + l, c->rcv_nxt)) {
                free(c->ooo[i].data);
                c->ooo[i].data = NULL;
                c->ooo[i].used = 0;
                progress = 1;
                continue;
            }
            if (seq_le(s, c->rcv_nxt)) {
                uint32_t skip = c->rcv_nxt - s;
                uint32_t take = l - skip;
                uint32_t avail = NET_TCP_BUF_SIZE - c->rx_len;
                if (take > avail) take = avail;
                if (take > 0) {
                    tcp_append_rx(c, c->ooo[i].data + skip, take);
                    c->rcv_nxt += take;
                }
                free(c->ooo[i].data);
                c->ooo[i].data = NULL;
                c->ooo[i].used = 0;
                progress = 1;
            }
        }
    }
}

static void tcp_store_ooo(struct tcp_conn *c, uint32_t seq, const uint8_t *data, uint32_t len)
{
    if (len == 0 || len > 8192u) return;
    int slot = -1;
    for (int i = 0; i < NET_TCP_OOO_MAX; i++) {
        if (c->ooo[i].used && c->ooo[i].seq == seq && c->ooo[i].len >= len)
            return;
        if (!c->ooo[i].used && slot < 0)
            slot = i;
    }
    if (slot < 0) return;
    uint8_t *copy = (uint8_t *)malloc(len);
    if (!copy) return;
    memcpy(copy, data, len);
    c->ooo[slot].used = 1;
    c->ooo[slot].seq = seq;
    c->ooo[slot].len = len;
    c->ooo[slot].data = copy;
}

static void tcp_parse_options(struct tcp_conn *c, const uint8_t *opts, size_t olen)
{
    size_t i = 0;
    while (i < olen) {
        uint8_t kind = opts[i];
        if (kind == 0) break;
        if (kind == 1) { i++; continue; }
        if (i + 1 >= olen) break;
        uint8_t len = opts[i + 1];
        if (len < 2 || i + len > olen) break;
        if (kind == 2 && len == 4) {
            uint16_t mss = rd_be16(opts + i + 2);
            if (mss >= 536u && mss <= 1460u)
                c->peer_mss = mss;
        } else if (kind == 3 && len == 3) {
            uint8_t ws = opts[i + 2];
            if (ws > 14u) ws = 14u;
            c->peer_wscale = ws;
        }
        i += len;
    }
}

static void tcp_read_from_relay(struct net_daemon *d, struct tcp_conn *c)
{
    if (c->relay_fd < 0 || c->app_eof)
        return;
    if (c->state != TCP_ST_ESTABLISHED && c->state != TCP_ST_CLOSE_WAIT)
        return;
    for (;;) {
        uint32_t used = c->snd_write - c->snd_una;
        if (used >= NET_TCP_BUF_SIZE)
            break;
        uint32_t space = NET_TCP_BUF_SIZE - used;
        uint32_t woff = (c->tx_head + used) % NET_TCP_BUF_SIZE;
        uint32_t contig = NET_TCP_BUF_SIZE - woff;
        if (contig > space) contig = space;
        if (contig > 32768u) contig = 32768u;
        ssize_t n = recv(c->relay_fd, c->tx_buf + woff, contig, MSG_DONTWAIT);
        if (n > 0) {
            c->snd_write += (uint32_t)n;
        } else if (n == 0) {
            c->app_eof = 1;
            break;
        } else if (errno == EINTR) {
            continue;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        } else {
            tcp_send_seg(d, c, TCP_RST | TCP_ACK, c->snd_nxt, NULL, 0);
            tcp_destroy(d, c, 0);
            return;
        }
    }
    tcp_pump_tx(d, c);
    tcp_update_epoll(d, c);
}

/* ---- Inbound TCP Segment Handler (TUN -> svbox-net) ---- */

static void stack_handle_tcp(struct net_daemon *d, uint32_t ifindex, int is_v6,
                             const uint8_t src_ip[16], const uint8_t dst_ip[16],
                             const uint8_t *seg, size_t seg_len)
{
    if (seg_len < 20u)
        return;
    size_t doff = (size_t)((seg[12] >> 4) & 0xfu) * 4u;
    if (doff < 20u || doff > seg_len)
        return;

    uint16_t sport = rd_be16(seg + 0);
    uint16_t dport = rd_be16(seg + 2);
    uint32_t seq   = rd_be32(seg + 4);
    uint32_t ack   = rd_be32(seg + 8);
    uint8_t  flags = seg[13];
    uint16_t rwnd  = rd_be16(seg + 14);
    const uint8_t *payload = seg + doff;
    uint32_t plen = (uint32_t)(seg_len - doff);

    struct tcp_conn *c = tcp_hash_find(d, is_v6, dport, sport, src_ip);
    if (!c) {
        if (!(flags & TCP_RST)) {
            if (flags & TCP_ACK)
                tcp_send_raw_rst(d, ifindex, is_v6, dst_ip, src_ip, dport, sport, ack, 0, 0);
            else
                tcp_send_raw_rst(d, ifindex, is_v6, dst_ip, src_ip, dport, sport, 0,
                                 seq + plen + ((flags & TCP_SYN) ? 1u : 0u) + ((flags & TCP_FIN) ? 1u : 0u), 1);
        }
        return;
    }

    c->last_activity_ms = net_now_ms();

    if (flags & TCP_RST) {
        tcp_destroy(d, c, 1);
        return;
    }

    if (c->state == TCP_ST_SYN_SENT) {
        if ((flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK) && ack == c->snd_nxt) {
            c->snd_una = ack;
            c->rcv_nxt = seq + 1u;
            c->peer_wscale = 0;
            if (doff > 20u)
                tcp_parse_options(c, seg + 20, doff - 20u);
            c->peer_wnd = (uint32_t)rwnd << c->peer_wscale;
            if (c->peer_wnd == 0) c->peer_wnd = 65535u;
            c->state = TCP_ST_ESTABLISHED;
            c->rtx_deadline_ms = 0;
            c->rto_ms = 200u;
            c->rtx_retries = 0;
            tcp_send_seg(d, c, TCP_ACK, c->snd_nxt, NULL, 0);
            /* Immediately pump any guest data already buffered in kernel loopback socket. */
            tcp_read_from_relay(d, c);
        } else {
            tcp_send_raw_rst(d, ifindex, is_v6, dst_ip, src_ip, dport, sport, ack, 0, 0);
        }
        return;
    }

    if (c->state == TCP_ST_TIME_WAIT) {
        if (flags & TCP_FIN) {
            tcp_send_seg(d, c, TCP_ACK, c->snd_nxt, NULL, 0);
            c->tw_deadline_ms = net_now_ms() + 2000u;
        }
        return;
    }

    /* Process ACK */
    if (flags & TCP_ACK) {
        uint32_t new_wnd = (uint32_t)rwnd << c->peer_wscale;
        if (seq_gt(ack, c->snd_una) && seq_le(ack, c->snd_nxt)) {
            uint32_t old_una = c->snd_una;
            uint32_t data_end = c->fin_sent ? c->fin_seq : c->snd_nxt;
            uint32_t data_ack_end = seq_lt(ack, data_end) ? ack : data_end;
            if (seq_gt(data_ack_end, old_una)) {
                uint32_t acked_data = data_ack_end - old_una;
                c->tx_head = (c->tx_head + acked_data) % NET_TCP_BUF_SIZE;
            }
            c->snd_una = ack;
            c->peer_wnd = new_wnd;
            c->dup_acks = 0;
            c->rto_ms = 200u;
            c->rtx_retries = 0;
            c->rtx_deadline_ms = (c->snd_una == c->snd_nxt) ? 0 : (net_now_ms() + c->rto_ms);

            if (c->fin_sent && seq_ge(ack, c->fin_seq + 1u)) {
                if (c->state == TCP_ST_FIN_WAIT_1) {
                    c->state = TCP_ST_FIN_WAIT_2;
                } else if (c->state == TCP_ST_CLOSING) {
                    c->state = TCP_ST_TIME_WAIT;
                    c->tw_deadline_ms = net_now_ms() + 2000u;
                } else if (c->state == TCP_ST_LAST_ACK) {
                    tcp_destroy(d, c, 0);
                    return;
                }
            }
        } else if (ack == c->snd_una) {
            c->peer_wnd = new_wnd;
            if (plen == 0 && !(flags & TCP_FIN) && seq_lt(c->snd_una, c->snd_nxt)) {
                c->dup_acks++;
                if (c->dup_acks == 3) {
                    tcp_retransmit_una(d, c);
                    c->rtx_deadline_ms = net_now_ms() + c->rto_ms;
                }
            }
        }
    }

    int need_ack = 0;
    /* Process payload */
    if (plen > 0) {
        if (seq_le(seq + plen, c->rcv_nxt)) {
            /* Duplicate/old segment: ACK current rcv_nxt. */
            need_ack = 1;
        } else if (seq_le(seq, c->rcv_nxt)) {
            uint32_t skip = c->rcv_nxt - seq;
            uint32_t take = plen - skip;
            uint32_t avail = NET_TCP_BUF_SIZE - c->rx_len;
            if (take > avail) take = avail;
            if (take > 0) {
                tcp_append_rx(c, payload + skip, take);
                c->rcv_nxt += take;
            }
            tcp_drain_ooo(c);
            need_ack = 1;
        } else {
            /* Out-of-order segment: buffer and send immediate dup-ACK. */
            tcp_store_ooo(c, seq, payload, plen);
            need_ack = 1;
        }
    }

    /* Process FIN */
    if ((flags & TCP_FIN) && seq + plen == c->rcv_nxt) {
        c->rcv_nxt += 1u;
        c->peer_fin = 1;
        need_ack = 1;
        if (c->state == TCP_ST_ESTABLISHED) {
            c->state = TCP_ST_CLOSE_WAIT;
        } else if (c->state == TCP_ST_FIN_WAIT_1) {
            c->state = (c->fin_sent && seq_ge(c->snd_una, c->fin_seq + 1u))
                ? TCP_ST_TIME_WAIT : TCP_ST_CLOSING;
            if (c->state == TCP_ST_TIME_WAIT)
                c->tw_deadline_ms = net_now_ms() + 2000u;
        } else if (c->state == TCP_ST_FIN_WAIT_2) {
            c->state = TCP_ST_TIME_WAIT;
            c->tw_deadline_ms = net_now_ms() + 2000u;
        }
    }

    if (need_ack)
        tcp_send_seg(d, c, TCP_ACK, c->snd_nxt, NULL, 0);

    tcp_flush_rx_to_relay(d, c);
    if (!c->active)
        return;
    tcp_read_from_relay(d, c);
    if (c->active)
        tcp_pump_tx(d, c);
}

/* ---- Inbound UDP Datagram Handler (TUN -> svbox-net -> Guest / DNS) ---- */

static void stack_handle_udp(struct net_daemon *d, uint32_t ifindex, int is_v6,
                             const uint8_t src_ip[16], const uint8_t dst_ip[16],
                             const uint8_t *seg, size_t seg_len)
{
    (void)ifindex;
    (void)dst_ip;
    if (seg_len < 8u)
        return;
    uint16_t sport = rd_be16(seg + 0);
    uint16_t dport = rd_be16(seg + 2);
    uint16_t ulen  = rd_be16(seg + 4);
    if (ulen < 8u || ulen > seg_len)
        return;
    const uint8_t *payload = seg + 8;
    size_t plen = (size_t)(ulen - 8u);

    /* 1. Check pending internal NET_OP_DNS_QUERY requests first. */
    if (!is_v6) {
        for (int i = 0; i < NET_MAX_DNS_REQS; i++) {
            struct dns_pending *q = &d->dns_reqs[i];
            if (q->active && q->local_port == dport) {
                net_send_ctl_reply(q->ctl_fd, NET_OP_DNS_QUERY, 0, q->proc_id, 0,
                                   payload, (uint32_t)plen, -1);
                close(q->ctl_fd);
                q->ctl_fd = -1;
                q->active = 0;
                return;
            }
        }
    }

    /* 2. Match guest UDP flow / encap port and deliver payload back to guest loopback port. */
    struct pending_flow *fl = NULL;
    for (int i = 0; i < SV_NET_FLOW_CAP; i++) {
        if (d->flows[i].active && d->flows[i].proto == 17u &&
            d->flows[i].local_port == dport && d->flows[i].is_v6 == (uint8_t)is_v6) {
            fl = &d->flows[i];
            break;
        }
    }
    if (!fl)
        return;
    fl->last_ms = net_now_ms();

    /* Record real remote source address in shared memory for recvfrom()/recvmsg(). */
    uint32_t slot = (uint32_t)(dport % SV_NET_UDP_REP_CAP);
    struct sv_net_udp_reply *rep = &d->st->udp_replies[slot];
    rep->local_port = dport;
    rep->src_port = sport;
    rep->is_v6 = (uint8_t)is_v6;
    memset(rep->src_ip, 0, 16);
    memcpy(rep->src_ip, src_ip, is_v6 ? 16u : 4u);
    __atomic_store_n(&rep->seq, ++d->udp_rep_seq, __ATOMIC_RELEASE);

    int relay_fd = fl->encap
        ? (is_v6 ? d->udp6_encap_fd : d->udp4_encap_fd)
        : (is_v6 ? d->udp6_conn_fd  : d->udp4_conn_fd);
    if (relay_fd < 0)
        return;

    if (!is_v6) {
        struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_port = htons(dport);
        dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        (void)sendto(relay_fd, payload, plen, MSG_DONTWAIT,
                     (const struct sockaddr *)&dst, sizeof(dst));
    } else {
        struct sockaddr_in6 dst6;
        memset(&dst6, 0, sizeof(dst6));
        dst6.sin6_family = AF_INET6;
        dst6.sin6_port = htons(dport);
        dst6.sin6_addr = in6addr_loopback;
        (void)sendto(relay_fd, payload, plen, MSG_DONTWAIT,
                     (const struct sockaddr *)&dst6, sizeof(dst6));
    }
}

/* ---- Inbound ICMPv4 Echo Handler ---- */

static void stack_handle_icmp4(struct net_daemon *d, uint32_t ifindex,
                               const uint8_t src_ip[16], const uint8_t dst_ip[16],
                               const uint8_t *icmp, size_t len)
{
    if (len < 8u || icmp[0] != 8u /* ECHO_REQUEST */)
        return;
    uint8_t rep[2048];
    if (len > sizeof(rep)) return;
    memcpy(rep, icmp, len);
    rep[0] = 0; /* ECHO_REPLY */
    rep[2] = 0; rep[3] = 0;
    wr_be16(rep + 2, csum_finish(csum_add(0, rep, len)));
    send_l3_packet(d, ifindex, 0, dst_ip, src_ip, 1u, rep, len);
}

/* ---- Public Entry Points ---- */

void stack_init(struct net_daemon *d)
{
    d->next_ip_id = 1;
    d->next_dns_port = 50000;
    d->active_conns = 0;
    d->conn_alloc_cursor = 0;
    for (int i = 0; i < NET_TCP_HASH_BUCKETS; i++)
        d->tcp_buckets[i] = -1;
    for (int i = 0; i < NET_MAX_TCP_CONNS; i++)
        d->conns[i].hash_next = -1;
}

void stack_on_tun_packet(struct net_daemon *d, uint32_t ifindex, const uint8_t *pkt, size_t len)
{
    if (len < 20u)
        return;
    uint8_t ver = pkt[0] >> 4;
    if (ver == 4u) {
        size_t ihl = (size_t)(pkt[0] & 0x0fu) * 4u;
        uint16_t tot = rd_be16(pkt + 2);
        if (ihl < 20u || tot < ihl || tot > len)
            return;
        uint8_t proto = pkt[9];
        uint8_t src[16], dst[16];
        memset(src, 0, 16); memset(dst, 0, 16);
        memcpy(src, pkt + 12, 4);
        memcpy(dst, pkt + 16, 4);
        if (proto == 6u)
            stack_handle_tcp(d, ifindex, 0, src, dst, pkt + ihl, (size_t)(tot - ihl));
        else if (proto == 17u)
            stack_handle_udp(d, ifindex, 0, src, dst, pkt + ihl, (size_t)(tot - ihl));
        else if (proto == 1u)
            stack_handle_icmp4(d, ifindex, src, dst, pkt + ihl, (size_t)(tot - ihl));
    } else if (ver == 6u && len >= 40u) {
        uint16_t plen = rd_be16(pkt + 4);
        if (40u + plen > len)
            return;
        uint8_t nh = pkt[6];
        if (nh == 6u)
            stack_handle_tcp(d, ifindex, 1, pkt + 8, pkt + 24, pkt + 40, plen);
        else if (nh == 17u)
            stack_handle_udp(d, ifindex, 1, pkt + 8, pkt + 24, pkt + 40, plen);
    }
}

void stack_on_tcp_accept(struct net_daemon *d, int listen_fd, int is_v6)
{
    for (;;) {
        struct sockaddr_storage ss;
        socklen_t slen = sizeof(ss);
        int cfd = accept4(listen_fd, (struct sockaddr *)&ss, &slen, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cfd < 0)
            break;

        int one = 1;
        setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        uint16_t peer_port = 0;
        if (ss.ss_family == AF_INET)
            peer_port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
        else if (ss.ss_family == AF_INET6)
            peer_port = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);

        /* Look up registered TCP flow for peer_port */
        struct pending_flow *fl = NULL;
        for (int i = 0; i < SV_NET_FLOW_CAP; i++) {
            if (d->flows[i].active && d->flows[i].proto == 6u &&
                d->flows[i].local_port == peer_port &&
                d->flows[i].is_v6 == (uint8_t)is_v6) {
                fl = &d->flows[i];
                break;
            }
        }
        if (!fl) {
            close(cfd);
            continue;
        }

        int slot = -1;
        for (int n = 0; n < NET_MAX_TCP_CONNS; n++) {
            int i = (d->conn_alloc_cursor + n) % NET_MAX_TCP_CONNS;
            if (!d->conns[i].active) {
                slot = i;
                d->conn_alloc_cursor = (i + 1) % NET_MAX_TCP_CONNS;
                break;
            }
        }
        if (slot < 0) {
            close(cfd);
            continue;
        }

        uint8_t *txb = (uint8_t *)malloc(NET_TCP_BUF_SIZE);
        uint8_t *rxb = (uint8_t *)malloc(NET_TCP_BUF_SIZE);
        if (!txb || !rxb) {
            free(txb); free(rxb);
            close(cfd);
            continue;
        }

        struct tcp_conn *c = &d->conns[slot];
        memset(c, 0, sizeof(*c));
        c->active = 1;
        c->idx = slot;
        c->hash_next = -1;
        c->relay_fd = cfd;
        c->tag.kind = EP_TCP_RELAY;
        c->tag.idx = slot;
        c->tag.fd = cfd;
        c->state = TCP_ST_SYN_SENT;
        c->is_v6 = fl->is_v6;
        c->tun_ifindex = fl->tun_ifindex;
        c->local_port = peer_port;
        c->remote_port = fl->dst_port;
        memcpy(c->local_ip, fl->tun_ip, 16);
        memcpy(c->remote_ip, fl->dst_ip, 16);

        uint32_t isn = (uint32_t)(net_now_ms() * 2654435761u) ^ ((uint32_t)peer_port << 16) ^ (uint32_t)slot;
        c->snd_una = isn;
        c->snd_nxt = isn + 1u;
        c->snd_write = isn + 1u;
        c->peer_mss = is_v6 ? 1440u : 1460u;
        c->peer_wnd = 65535u;
        c->our_wscale = 6u;
        c->tx_buf = txb;
        c->rx_buf = rxb;
        c->rto_ms = 200u;
        c->rtx_deadline_ms = net_now_ms() + c->rto_ms;
        c->last_activity_ms = net_now_ms();
        tcp_hash_insert(d, c);
        d->active_conns++;

        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLRDHUP | EPOLLHUP | EPOLLERR;
        ev.data.ptr = &c->tag;
        if (epoll_ctl(d->ep_fd, EPOLL_CTL_ADD, cfd, &ev) < 0) {
            tcp_destroy(d, c, 1);
            continue;
        }

        /* Kick off 3-way TCP handshake over TUN immediately. */
        tcp_send_seg(d, c, TCP_SYN, isn, NULL, 0);
    }
}

void stack_on_tcp_relay_event(struct net_daemon *d, int conn_idx, uint32_t events)
{
    if (conn_idx < 0 || conn_idx >= NET_MAX_TCP_CONNS)
        return;
    struct tcp_conn *c = &d->conns[conn_idx];
    if (!c->active)
        return;
    if (events & EPOLLERR) {
        tcp_send_seg(d, c, TCP_RST | TCP_ACK, c->snd_nxt, NULL, 0);
        tcp_destroy(d, c, 0);
        return;
    }
    if (events & EPOLLOUT) {
        tcp_flush_rx_to_relay(d, c);
        if (!c->active) return;
    }
    if (events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP)) {
        tcp_read_from_relay(d, c);
    }
}

void stack_on_udp_relay_readable(struct net_daemon *d, int sock_fd, int is_v6, int is_encap)
{
    uint8_t buf[NET_MAX_PKT_SIZE];
    for (;;) {
        struct sockaddr_storage ss;
        socklen_t slen = sizeof(ss);
        ssize_t n = recvfrom(sock_fd, buf, sizeof(buf), MSG_DONTWAIT,
                             (struct sockaddr *)&ss, &slen);
        if (n <= 0)
            break;

        uint16_t src_port = 0;
        if (ss.ss_family == AF_INET)
            src_port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
        else if (ss.ss_family == AF_INET6)
            src_port = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
        if (src_port == 0)
            continue;

        uint32_t tun_ifindex = 0;
        uint8_t dst_ip[16], local_ip[16];
        uint16_t dst_port = 0;
        const uint8_t *payload = buf;
        size_t plen = (size_t)n;
        memset(dst_ip, 0, 16);
        memset(local_ip, 0, 16);

        if (is_encap) {
            if ((size_t)n < sizeof(struct sv_udp_encap_hdr))
                continue;
            struct sv_udp_encap_hdr eh;
            memcpy(&eh, buf, sizeof(eh));
            if (eh.magic != SV_UDP_ENCAP_MAGIC)
                continue;
            tun_ifindex = eh.tun_ifindex;
            dst_port = eh.dst_port;
            memcpy(dst_ip, eh.dst_ip, 16);
            payload = buf + sizeof(eh);
            plen = (size_t)n - sizeof(eh);

            struct sv_net_iface *ifc = net_find_iface_by_idx(d, tun_ifindex);
            if (!ifc || !ifc->is_tun)
                continue;
            if (is_v6) {
                if (ifc->has_v6) memcpy(local_ip, ifc->ipv6_addr, 16);
                else { local_ip[0] = 0xfd; local_ip[15] = 1; }
            } else {
                uint32_t ip4 = ifc->ipv4_addr ? ifc->ipv4_addr : htonl(0xac130001u);
                memcpy(local_ip, &ip4, 4);
            }

            /* Record/refresh encap port so replies route back through udp*_encap_fd. */
            int slot = -1, free_s = -1;
            uint64_t oldest = UINT64_MAX;
            int oldest_s = 0;
            for (int i = 0; i < SV_NET_FLOW_CAP; i++) {
                if (d->flows[i].active && d->flows[i].proto == 17u &&
                    d->flows[i].local_port == src_port && d->flows[i].is_v6 == (uint8_t)is_v6) {
                    slot = i;
                    break;
                }
                if (!d->flows[i].active && free_s < 0)
                    free_s = i;
                if (d->flows[i].active && d->flows[i].proto == 17u && d->flows[i].last_ms < oldest) {
                    oldest = d->flows[i].last_ms;
                    oldest_s = i;
                }
            }
            if (slot < 0) slot = (free_s >= 0) ? free_s : oldest_s;
            struct pending_flow *fl = &d->flows[slot];
            fl->active = 1;
            fl->proto = 17u;
            fl->is_v6 = (uint8_t)is_v6;
            fl->local_port = src_port;
            fl->dst_port = dst_port;
            fl->tun_ifindex = (uint16_t)tun_ifindex;
            memcpy(fl->dst_ip, dst_ip, 16);
            memcpy(fl->tun_ip, local_ip, 16);
            fl->last_ms = net_now_ms();
            fl->encap = 1;
        } else {
            struct pending_flow *fl = NULL;
            for (int i = 0; i < SV_NET_FLOW_CAP; i++) {
                if (d->flows[i].active && d->flows[i].proto == 17u &&
                    d->flows[i].local_port == src_port && d->flows[i].is_v6 == (uint8_t)is_v6) {
                    fl = &d->flows[i];
                    break;
                }
            }
            if (!fl)
                continue;
            fl->last_ms = net_now_ms();
            tun_ifindex = fl->tun_ifindex;
            dst_port = fl->dst_port;
            memcpy(dst_ip, fl->dst_ip, 16);
            memcpy(local_ip, fl->tun_ip, 16);
        }

        if (8u + plen > 65000u)
            continue;
        uint8_t udp[NET_MAX_PKT_SIZE];
        wr_be16(udp + 0, src_port);
        wr_be16(udp + 2, dst_port);
        wr_be16(udp + 4, (uint16_t)(8u + plen));
        wr_be16(udp + 6, 0);
        memcpy(udp + 8, payload, plen);
        wr_be16(udp + 6, l4_checksum(is_v6, local_ip, dst_ip, 17u, udp, 8u + plen));
        send_l3_packet(d, tun_ifindex, is_v6, local_ip, dst_ip, 17u, udp, 8u + plen);
    }
}

int stack_start_dns_query(struct net_daemon *d, int ctl_fd, uint32_t proc_id,
                          const struct sv_net_dns_query_req *qreq,
                          const uint8_t *dns_wire, size_t dns_len)
{
    if (!d->st->tun_active || dns_len == 0 || dns_len > 4096u)
        return -ENETUNREACH;

    /* Find active UP TUN interface */
    struct sv_net_iface *tun_ifc = NULL;
    for (int i = 0; i < SV_NET_MAX_IFACES; i++) {
        if (d->st->ifaces[i].active && d->st->ifaces[i].is_tun &&
            (d->st->ifaces[i].flags & SV_IFF_UP)) {
            tun_ifc = &d->st->ifaces[i];
            break;
        }
    }
    if (!tun_ifc)
        return -ENETUNREACH;

    int slot = -1;
    for (int i = 0; i < NET_MAX_DNS_REQS; i++) {
        if (!d->dns_reqs[i].active) { slot = i; break; }
    }
    if (slot < 0)
        return -EBUSY;

    uint32_t srv_v4 = qreq->server_v4;
    if (srv_v4 == 0) {
        if (d->st->dns_count > 0 && d->st->dns_v4[0] != 0)
            srv_v4 = d->st->dns_v4[0];
        else
            srv_v4 = htonl(0x08080808u); /* 8.8.8.8 */
    }
    uint16_t dport = qreq->port ? qreq->port : 53u;
    uint32_t timeout = qreq->timeout_ms ? qreq->timeout_ms : 3000u;

    uint16_t sport = d->next_dns_port++;
    if (d->next_dns_port >= 60000u || d->next_dns_port < 50000u)
        d->next_dns_port = 50000u;

    uint8_t src_ip[16], dst_ip[16];
    memset(src_ip, 0, 16); memset(dst_ip, 0, 16);
    uint32_t local_v4 = tun_ifc->ipv4_addr ? tun_ifc->ipv4_addr : htonl(0xac130001u);
    memcpy(src_ip, &local_v4, 4);
    memcpy(dst_ip, &srv_v4, 4);

    uint8_t udp[4200];
    wr_be16(udp + 0, sport);
    wr_be16(udp + 2, dport);
    wr_be16(udp + 4, (uint16_t)(8u + dns_len));
    wr_be16(udp + 6, 0);
    memcpy(udp + 8, dns_wire, dns_len);
    wr_be16(udp + 6, l4_checksum(0, src_ip, dst_ip, 17u, udp, 8u + dns_len));

    if (send_l3_packet(d, tun_ifc->ifindex, 0, src_ip, dst_ip, 17u, udp, 8u + dns_len) < 0)
        return -EIO;

    struct dns_pending *q = &d->dns_reqs[slot];
    q->active = 1;
    q->ctl_fd = ctl_fd;
    q->local_port = sport;
    q->tun_ifindex = (uint16_t)tun_ifc->ifindex;
    q->deadline_ms = net_now_ms() + timeout;
    q->proc_id = proc_id;
    return 0;
}

void stack_on_tun_closed(struct net_daemon *d, uint32_t ifindex)
{
    for (int i = 0; i < NET_MAX_TCP_CONNS; i++) {
        if (d->conns[i].active && d->conns[i].tun_ifindex == ifindex)
            tcp_destroy(d, &d->conns[i], 1);
    }
    for (int i = 0; i < SV_NET_FLOW_CAP; i++) {
        if (d->flows[i].active && d->flows[i].tun_ifindex == ifindex)
            d->flows[i].active = 0;
    }
    for (int i = 0; i < NET_MAX_DNS_REQS; i++) {
        if (d->dns_reqs[i].active && d->dns_reqs[i].tun_ifindex == ifindex) {
            net_send_ctl_reply(d->dns_reqs[i].ctl_fd, NET_OP_DNS_QUERY, -ENETDOWN,
                               d->dns_reqs[i].proc_id, 0, NULL, 0, -1);
            close(d->dns_reqs[i].ctl_fd);
            d->dns_reqs[i].active = 0;
        }
    }
    net_sync_flow_table(d);
}

void stack_tick(struct net_daemon *d)
{
    uint64_t now = net_now_ms();
    if (d->active_conns > 0) {
        for (int i = 0; i < NET_MAX_TCP_CONNS; i++) {
            struct tcp_conn *c = &d->conns[i];
            if (!c->active)
                continue;
            if (c->state == TCP_ST_TIME_WAIT) {
                if (now >= c->tw_deadline_ms)
                    tcp_destroy(d, c, 0);
                continue;
            }
            if (c->rtx_deadline_ms != 0 && now >= c->rtx_deadline_ms) {
                if (c->rtx_retries >= 8) {
                    tcp_send_seg(d, c, TCP_RST | TCP_ACK, c->snd_nxt, NULL, 0);
                    tcp_destroy(d, c, 1);
                    continue;
                }
                c->rtx_retries++;
                tcp_retransmit_una(d, c);
                c->rto_ms *= 2u;
                if (c->rto_ms > 4000u) c->rto_ms = 4000u;
                c->rtx_deadline_ms = now + c->rto_ms;
            }
            /* Reap completely idle half-closed connections after 60s. */
            if ((c->state == TCP_ST_FIN_WAIT_2 || c->state == TCP_ST_CLOSING) &&
                now > c->last_activity_ms + 60000u) {
                tcp_destroy(d, c, 0);
            }
        }
    }
    /* Expire stale UDP encap mappings after 120s. */
    int changed = 0;
    for (int i = 0; i < SV_NET_FLOW_CAP; i++) {
        if (d->flows[i].active && d->flows[i].proto == 17u &&
            now > d->flows[i].last_ms + 120000u) {
            d->flows[i].active = 0;
            changed = 1;
        }
    }
    if (changed)
        net_sync_flow_table(d);

    /* Expire timed-out DNS queries. */
    for (int i = 0; i < NET_MAX_DNS_REQS; i++) {
        struct dns_pending *q = &d->dns_reqs[i];
        if (q->active && now >= q->deadline_ms) {
            net_send_ctl_reply(q->ctl_fd, NET_OP_DNS_QUERY, -ETIMEDOUT,
                               q->proc_id, 0, NULL, 0, -1);
            close(q->ctl_fd);
            q->ctl_fd = -1;
            q->active = 0;
        }
    }
}
