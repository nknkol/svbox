/* SPDX-License-Identifier: MIT */
/* Generic userspace virtual network & TUN client layer inside svbox payload. */
#ifndef SVBOX_NET_STACK_H
#define SVBOX_NET_STACK_H

#include <stddef.h>
#include <stdint.h>
#include "config.h"
#include "net_proto.h"

static inline int net_stack_enabled(void)
{
    return g_payload_config.net_sock[0] != '\0';
}

/* Returns read-only pointer to mapped shared network state, or NULL. */
const struct sv_net_state *net_stack_state(void);

/* Pre-dispatch hook for socket/close/dup/fcntl/setsockopt/getsockopt/ioctl/
 * bind/getsockname/getpeername/sendto/sendmsg/recvfrom/recvmsg on virtual
 * netlink sockets, SO_MARK/SO_BINDTODEVICE, SIOC* ioctls, and TUN redirects.
 * Returns 1 and stores syscall return value in *out if handled completely. */
int net_stack_pre_syscall(long number, long a[6], long *out);

/* Post-dispatch hook for socket/dup/fcntl (to track/clear FD flags) and for
 * getsockname/getpeername/recvfrom/recvmsg address restoration on redirected
 * sockets and virtual netlink sockets. */
void net_stack_post_syscall(long number, long a[6], long ret, unsigned name_cap);

/* Virtual /proc/net/{dev,route,if_inet6} and /sys/class/net/<iface>/<attr> views.
 * Returns >= 0 (memfd or 0 for stat/access) when handled, or -ENOENT if path
 * is not a virtual network procfs/sysfs entry. */
long net_stack_proc_call(long number, long a[6], const char *guest_path);

#endif /* SVBOX_NET_STACK_H */
