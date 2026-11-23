/* SPDX-License-Identifier: MIT */
/* Internal definitions for svbox-net generic userspace virtual network daemon. */
#ifndef SVBOX_NET_INTERNAL_H
#define SVBOX_NET_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include "vdev_proto.h"
#include "net_proto.h"

#define NET_MAX_TUNS       16
#define NET_MAX_NLS        64
#define NET_MAX_TCP_CONNS  256
#define NET_MAX_UDP_PORTS  256
#define NET_MAX_DNS_REQS   32
#define NET_TCP_BUF_SIZE   262144u /* 256 KiB per-direction ring */
#define NET_TCP_OOO_MAX    16
#define NET_MAX_PKT_SIZE   65536u

/* Epoll tagged object kinds */
enum ep_kind {
    EP_CTL_LISTEN = 1,
    EP_TCP4_LISTEN,
    EP_TCP6_LISTEN,
    EP_UDP4_CONN,
    EP_UDP4_ENCAP,
    EP_UDP6_CONN,
    EP_UDP6_ENCAP,
    EP_TUN_DATA,
    EP_NL_SOCK,
    EP_TCP_RELAY,
    EP_CTL_CLIENT,
};

struct ep_tag {
    int kind;
    int idx;
    int fd;
};

struct tun_dev {
    int      active;
    uint32_t tun_id;
    uint32_t ifindex;
    uint32_t flags;       /* SV_IFF_TUN | SV_IFF_NO_PI ... */
    int      data_fd;     /* host end of SOCK_SEQPACKET pair */
    struct ep_tag tag;
};

struct nl_client {
    int      active;
    uint32_t nl_id;
    uint32_t pid;
    uint32_t groups;
    int      fd;          /* host end of SOCK_SEQPACKET pair */
    struct ep_tag tag;
};

struct pending_flow {
    int      active;
    uint8_t  proto;       /* 6=TCP, 17=UDP */
    uint8_t  is_v6;
    uint16_t local_port;  /* host order */
    uint16_t dst_port;    /* host order */
    uint16_t tun_ifindex;
    uint8_t  dst_ip[16];  /* network order */
    uint8_t  tun_ip[16];  /* network order */
    uint64_t last_ms;
    int      encap;       /* 1 if unconnected UDP via encap port */
};

struct dns_pending {
    int      active;
    int      ctl_fd;      /* client waiting for NET_OP_DNS_QUERY reply */
    uint16_t local_port;  /* ephemeral port in 50000..59999 */
    uint16_t tun_ifindex;
    uint64_t deadline_ms;
    uint32_t proc_id;
};

enum tcp_state {
    TCP_ST_CLOSED = 0,
    TCP_ST_SYN_SENT,
    TCP_ST_ESTABLISHED,
    TCP_ST_FIN_WAIT_1,
    TCP_ST_FIN_WAIT_2,
    TCP_ST_CLOSE_WAIT,
    TCP_ST_LAST_ACK,
    TCP_ST_CLOSING,
    TCP_ST_TIME_WAIT,
};

struct tcp_ooo_seg {
    int      used;
    uint32_t seq;
    uint32_t len;
    uint8_t *data;
};

struct tcp_conn {
    int            active;
    int            idx;
    int            relay_fd;
    int            ep_out_armed;
    struct ep_tag  tag;

    enum tcp_state state;
    uint8_t        is_v6;
    uint16_t       tun_ifindex;
    uint16_t       local_port;   /* host order */
    uint16_t       remote_port;  /* host order */
    uint8_t        local_ip[16]; /* network order */
    uint8_t        remote_ip[16];/* network order */

    /* Send sequence space (guest -> TUN) */
    uint32_t       snd_una;
    uint32_t       snd_nxt;
    uint32_t       snd_write;
    uint32_t       peer_wnd;
    uint16_t       peer_mss;
    uint8_t        peer_wscale;
    uint8_t        our_wscale;
    int            app_eof;      /* relay_fd hit EOF */
    int            fin_sent;     /* FIN transmitted */
    uint32_t       fin_seq;      /* seq of our FIN */
    int            dup_acks;

    uint8_t       *tx_buf;       /* NET_TCP_BUF_SIZE circular buffer */
    uint32_t       tx_head;      /* byte offset of snd_una in tx_buf */

    /* Receive sequence space (TUN -> guest) */
    uint32_t       rcv_nxt;
    int            peer_fin;
    int            peer_fin_shutdown;
    uint8_t       *rx_buf;       /* NET_TCP_BUF_SIZE pending writes to relay_fd */
    uint32_t       rx_head;
    uint32_t       rx_len;
    int            zero_wnd_sent;
    struct tcp_ooo_seg ooo[NET_TCP_OOO_MAX];

    /* Retransmit / TIME_WAIT timers */
    uint64_t       rtx_deadline_ms;
    uint32_t       rto_ms;
    int            rtx_retries;
    uint64_t       tw_deadline_ms;
    uint64_t       last_activity_ms;
};

struct net_daemon {
    int                   ep_fd;
    int                   ctl_listen_fd;
    int                   state_memfd;
    struct sv_net_state  *st;
    int                   log_level;

    int                   tcp4_listen_fd;
    int                   tcp6_listen_fd;
    int                   udp4_conn_fd;
    int                   udp4_encap_fd;
    int                   udp6_conn_fd;
    int                   udp6_encap_fd;

    struct ep_tag         ctl_tag;
    struct ep_tag         tcp4_tag;
    struct ep_tag         tcp6_tag;
    struct ep_tag         udp4_conn_tag;
    struct ep_tag         udp4_encap_tag;
    struct ep_tag         udp6_conn_tag;
    struct ep_tag         udp6_encap_tag;

    uint32_t              next_ifindex;
    uint32_t              next_tun_id;
    uint32_t              next_nl_id;
    uint32_t              udp_rep_seq;
    uint16_t              next_ip_id;
    uint16_t              next_dns_port;

    struct tun_dev        tuns[NET_MAX_TUNS];
    struct nl_client      nls[NET_MAX_NLS];
    struct pending_flow   flows[SV_NET_FLOW_CAP];
    struct tcp_conn       conns[NET_MAX_TCP_CONNS];
    struct dns_pending    dns_reqs[NET_MAX_DNS_REQS];
};

/* Utility / daemon functions shared with tcp_stack.c */
uint64_t net_now_ms(void);
void net_recompute_tun_active(struct net_daemon *d);
struct sv_net_iface *net_find_iface_by_idx(struct net_daemon *d, uint32_t ifindex);
struct tun_dev *net_find_tun_by_ifindex(struct net_daemon *d, uint32_t ifindex);
int net_tun_send_packet(struct net_daemon *d, uint32_t ifindex, const uint8_t *pkt, size_t len);
void net_sync_flow_table(struct net_daemon *d);
int net_send_ctl_reply(int fd, uint32_t op, int32_t status, uint32_t proc_id,
                       uint64_t arg0, const void *payload, uint32_t payload_len, int send_fd);

/* tcp_stack.c entry points */
void stack_init(struct net_daemon *d);
void stack_on_tun_packet(struct net_daemon *d, uint32_t ifindex, const uint8_t *pkt, size_t len);
void stack_on_tcp_accept(struct net_daemon *d, int listen_fd, int is_v6);
void stack_on_tcp_relay_event(struct net_daemon *d, int conn_idx, uint32_t events);
void stack_on_udp_relay_readable(struct net_daemon *d, int sock_fd, int is_v6, int is_encap);
void stack_on_tun_closed(struct net_daemon *d, uint32_t ifindex);
void stack_tick(struct net_daemon *d);
int stack_start_dns_query(struct net_daemon *d, int ctl_fd, uint32_t proc_id,
                          const struct sv_net_dns_query_req *qreq,
                          const uint8_t *dns_wire, size_t dns_len);

#endif /* SVBOX_NET_INTERNAL_H */
