/* SPDX-License-Identifier: MIT */
/* Generic userspace virtual network & TUN protocol (--net-sock PATH), shared
 * between svbox payload, svbox-net daemon, and external network controllers.
 * Uses the same 32-byte struct vdev_hdr wire framing as vdev_proto.h. */
#ifndef SVBOX_NET_PROTO_H
#define SVBOX_NET_PROTO_H

#include <stdint.h>
#include "vdev_proto.h"

#define SV_NET_STATE_MAGIC    0x53564e54u /* "SVNT" */
#define SV_NET_STATE_VERSION  1u

#define SV_NET_MAX_IFACES     16
#define SV_NET_MAX_ROUTES     64
#define SV_NET_MAX_ROUTES6    32
#define SV_NET_MAX_UID_RULES  32
#define SV_NET_PROTECT_CAP    512
#define SV_NET_FLOW_CAP       256
#define SV_NET_UDP_REP_CAP    256
#define SV_NET_MAX_DNS        4

#define SV_UDP_ENCAP_MAGIC    0x53565531u /* "SVU1" */

/* Control opcodes over --net-sock (framed with struct vdev_hdr). */
enum sv_net_op {
    NET_OP_GET_STATE      = 0x100, /* -> returns PROT_READ shared state memfd (arg0=size) */
    NET_OP_OPEN_NETLINK   = 0x101, /* -> returns SOCK_SEQPACKET virtual NETLINK_ROUTE fd */
    NET_OP_FLOW_ADD       = 0x102, /* -> register redirected TCP or connected UDP flow */
    NET_OP_SIOC           = 0x103, /* -> emulate SIOC* socket ioctl */
    NET_OP_PROTECT_INO    = 0x104, /* -> exempt socket inode from TUN routing */
    NET_OP_IFACE_CFG      = 0x105, /* -> admin: configure/add/del interface & IP address */
    NET_OP_ROUTE_CFG      = 0x106, /* -> admin: add/del IPv4/IPv6 route */
    NET_OP_UID_RULES      = 0x107, /* -> admin: set/clear UID routing rules */
    NET_OP_SET_DNS        = 0x108, /* -> admin: set/clear active TUN DNS servers */
    NET_OP_DNS_QUERY      = 0x109, /* -> send raw UDP DNS query through active TUN */
    NET_OP_NL_BIND        = 0x10a, /* -> record netlink multicast groups (arg0=groups) */
};

/* Standard Linux interface flags (subset). */
#define SV_IFF_UP            0x0001u
#define SV_IFF_BROADCAST     0x0002u
#define SV_IFF_LOOPBACK      0x0008u
#define SV_IFF_POINTOPOINT   0x0010u
#define SV_IFF_RUNNING       0x0040u
#define SV_IFF_NOARP         0x0080u
#define SV_IFF_MULTICAST     0x1000u

/* Standard Linux TUN/TAP flags & ioctls (AArch64 / x86_64). */
#define SV_IFF_TUN           0x0001u
#define SV_IFF_TAP           0x0002u
#define SV_IFF_MULTI_QUEUE   0x0100u
#define SV_IFF_NO_PI         0x1000u

#define SV_TUNSETIFF         0x400454cau
#define SV_TUNSETPERSIST     0x400454cbu
#define SV_TUNSETOWNER       0x400454ccu
#define SV_TUNSETGROUP       0x400454ceu
#define SV_TUNGETFEATURES    0x800454cfu
#define SV_TUNGETIFF         0x800454d2u
#define SV_TUNGETVNETHDRSZ   0x800454d7u
#define SV_TUNSETVNETHDRSZ   0x400454d8u
#define SV_TUNSETQUEUE       0x400454d9u

/* Standard Linux SIOC* socket ioctls. */
#define SV_SIOCADDRT         0x890bu
#define SV_SIOCDELRT         0x890cu
#define SV_SIOCGIFNAME       0x8910u
#define SV_SIOCGIFCONF       0x8912u
#define SV_SIOCGIFFLAGS      0x8913u
#define SV_SIOCSIFFLAGS      0x8914u
#define SV_SIOCGIFADDR       0x8915u
#define SV_SIOCSIFADDR       0x8916u
#define SV_SIOCGIFDSTADDR    0x8917u
#define SV_SIOCSIFDSTADDR    0x8918u
#define SV_SIOCGIFBRDADDR    0x8919u
#define SV_SIOCGIFNETMASK    0x891bu
#define SV_SIOCSIFNETMASK    0x891cu
#define SV_SIOCGIFMTU        0x8921u
#define SV_SIOCSIFMTU        0x8922u
#define SV_SIOCGIFHWADDR     0x8927u
#define SV_SIOCGIFINDEX      0x8933u
#define SV_SIOCGIFTXQLEN     0x8942u
#define SV_SIOCSIFTXQLEN     0x8943u

struct sv_net_iface {
    uint32_t active;
    uint32_t ifindex;
    char     name[16];
    uint32_t flags;
    uint32_t mtu;
    uint8_t  mac[6];
    uint8_t  is_tun;
    uint8_t  has_v6;
    uint32_t ipv4_addr;     /* network byte order */
    uint32_t ipv4_mask;     /* network byte order */
    uint32_t ipv4_prefix;   /* 0..32 */
    uint32_t ipv6_prefix;   /* 0..128 */
    uint8_t  ipv6_addr[16]; /* network byte order */
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t tx_bytes;
};

struct sv_net_route4 {
    uint32_t active;
    uint32_t dst;           /* network byte order */
    uint32_t mask;          /* network byte order */
    uint32_t gw;            /* network byte order */
    uint32_t ifindex;
    uint32_t metric;
    uint32_t prefix;        /* 0..32 */
    uint32_t table;         /* 254=main, >0 custom */
};

struct sv_net_route6 {
    uint32_t active;
    uint32_t ifindex;
    uint32_t metric;
    uint32_t prefix;        /* 0..128 */
    uint8_t  dst[16];
    uint8_t  gw[16];
};

struct sv_net_uid_range {
    uint32_t start;
    uint32_t stop;
};

struct sv_net_flow_slot {
    uint32_t active;
    uint16_t local_port;    /* host byte order */
    uint16_t dst_port;      /* host byte order */
    uint8_t  proto;         /* 6=TCP, 17=UDP */
    uint8_t  is_v6;
    uint16_t tun_ifindex;
    uint32_t _pad;
    uint8_t  dst_ip[16];    /* IPv4 in [0..3] or IPv6 in [0..15], network order */
    uint8_t  tun_ip[16];    /* local virtual IP, network order */
};

struct sv_net_udp_reply {
    uint32_t seq;
    uint16_t local_port;    /* host byte order */
    uint16_t src_port;      /* host byte order */
    uint8_t  is_v6;
    uint8_t  _pad[7];
    uint8_t  src_ip[16];    /* network order */
};

/* Single-writer (svbox-net), multi-reader (svbox payloads mapped PROT_READ). */
struct sv_net_state {
    uint32_t magic;
    uint32_t version;
    volatile uint32_t seq;
    uint32_t tun_active;    /* 0 = zero-overhead fast path, 1 = TUN routes active */

    uint16_t tcp_relay_port;  /* host order: 127.0.0.1:<port> */
    uint16_t tcp_relay_port6; /* host order: [::1]:<port> */
    uint16_t udp_conn_port;   /* host order: 127.0.0.1:<port> */
    uint16_t udp_encap_port;  /* host order: 127.0.0.1:<port> */
    uint16_t udp_conn_port6;
    uint16_t udp_encap_port6;
    uint32_t uid_mode;        /* 0=all, 1=allowlist only, 2=disallowlist bypass */
    uint32_t uid_rule_count;

    uint32_t dns_count;
    uint32_t dns_v4[SV_NET_MAX_DNS]; /* network byte order */

    struct sv_net_iface     ifaces[SV_NET_MAX_IFACES];
    struct sv_net_route4    routes[SV_NET_MAX_ROUTES];
    struct sv_net_route6    routes6[SV_NET_MAX_ROUTES6];
    struct sv_net_uid_range uid_ranges[SV_NET_MAX_UID_RULES];

    uint32_t protect_cursor;
    uint32_t _pad_p;
    uint64_t protected_inos[SV_NET_PROTECT_CAP];

    struct sv_net_flow_slot flows[SV_NET_FLOW_CAP];
    struct sv_net_udp_reply udp_replies[SV_NET_UDP_REP_CAP];
};

/* Prepended to unconnected UDP packets sent to udp_encap_port. */
struct sv_udp_encap_hdr {
    uint32_t magic;         /* SV_UDP_ENCAP_MAGIC */
    uint16_t tun_ifindex;
    uint16_t dst_port;      /* host byte order */
    uint8_t  is_v6;
    uint8_t  _pad[3];
    uint32_t _reserved;
    uint8_t  dst_ip[16];    /* IPv4 in [0..3] or IPv6 in [0..15], network order */
};

/* Payload for NET_OP_FLOW_ADD */
struct sv_net_flow_req {
    uint8_t  proto;         /* 6=TCP, 17=UDP */
    uint8_t  is_v6;
    uint16_t local_port;    /* host byte order */
    uint16_t dst_port;      /* host byte order */
    uint16_t tun_ifindex;
    uint8_t  dst_ip[16];    /* network order */
};

/* Payload for NET_OP_SIOC */
struct sv_net_sioc_req {
    uint32_t cmd;
    uint32_t data_len;
    /* followed by data_len bytes (e.g. 40B ifreq or 120B rtentry) */
};

/* Payload for NET_OP_IFACE_CFG */
#define SV_IFCFG_SET_FLAGS   1u
#define SV_IFCFG_SET_MTU     2u
#define SV_IFCFG_ADD_ADDR4   3u
#define SV_IFCFG_DEL_ADDR4   4u
#define SV_IFCFG_CLEAR_ADDRS 5u
#define SV_IFCFG_ADD_ADDR6   6u
#define SV_IFCFG_DEL_ADDR6   7u

struct sv_net_ifcfg_req {
    uint32_t action;
    char     ifname[16];
    uint32_t flags;
    uint32_t mtu;
    uint32_t ipv4_addr;     /* network order */
    uint32_t prefix;
    uint8_t  ipv6_addr[16]; /* network order */
};

/* Payload for NET_OP_ROUTE_CFG */
#define SV_RTCFG_ADD4        1u
#define SV_RTCFG_DEL4        2u
#define SV_RTCFG_ADD6        3u
#define SV_RTCFG_DEL6        4u
#define SV_RTCFG_CLEAR_IFACE 5u

struct sv_net_rtcfg_req {
    uint32_t action;
    char     ifname[16];
    uint32_t dst_v4;        /* network order */
    uint32_t gw_v4;         /* network order */
    uint32_t prefix;
    uint32_t metric;
    uint32_t table;
    uint8_t  dst_v6[16];
    uint8_t  gw_v6[16];
};

/* Payload for NET_OP_UID_RULES */
struct sv_net_uid_rules_req {
    uint32_t mode;          /* 0=all, 1=allowlist, 2=disallowlist */
    uint32_t count;
    struct sv_net_uid_range ranges[SV_NET_MAX_UID_RULES];
};

/* Payload for NET_OP_SET_DNS */
struct sv_net_dns_req {
    uint32_t count;
    uint32_t servers_v4[SV_NET_MAX_DNS]; /* network order */
};

/* Payload for NET_OP_DNS_QUERY: header followed by raw DNS query bytes. */
struct sv_net_dns_query_req {
    uint32_t server_v4;     /* network order; 0 = use configured TUN DNS or 8.8.8.8 */
    uint16_t port;          /* host order; 0 = 53 */
    uint16_t timeout_ms;    /* 0 = default 3000ms */
    /* followed by raw DNS wire packet */
};

#endif /* SVBOX_NET_PROTO_H */
