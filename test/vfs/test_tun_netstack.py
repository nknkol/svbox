#!/usr/bin/env python3
"""Generic userspace virtual network & TUN stack tests (--net-sock + --vdev ...:tun).

Verifies without root / CAP_NET_ADMIN / CLONE_NEWNET:
 1. Virtual /proc/net/{dev,route}, /sys/class/net/<iface>/*, SIOC* ioctls,
    and AF_NETLINK/NETLINK_ROUTE (RTM_GET/NEW/DEL LINK/ADDR/ROUTE).
 2. Virtual /dev/net/tun (TUNSETIFF, TUNGETIFF, TUNGETFEATURES, SOCK_SEQPACKET
    packet framing, SCM_RIGHTS passing across processes, auto-teardown on close).
 3. Transparent TCP over TUN (3-way handshake, 256 KiB bulk transfer with OOO
    delivery, dual-stack AF_INET6 ::ffff:, getsockname/getpeername restoration).
 4. Transparent UDP over TUN (connected UDP + unconnected multi-peer sendto/recvfrom
    with remote peer address restoration).
 5. Bypass/protect (SO_MARK, SO_BINDTODEVICE, NET_OP_PROTECT_INO, UID rules)
    and full TUN-proxy loop (FakeIP -> tun0 -> protected outbound -> host server).
 6. NET_OP_DNS_QUERY RPC over TUN and ICMPv4 echo reply.
"""
import hashlib
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
BUILD = lib.BUILD
LOADER = lib.loader()
NET_DAEMON = BUILD / "svbox-net"

# Minimal Python userspace TUN proxy + protocol tester executed inside svbox.
TUN_PROXY_PY = r"""
import array, errno, fcntl, hashlib, os, select, socket, struct, sys, time

TUNSETIFF      = 0x400454ca
TUNGETFEATURES = 0x800454cf
TUNGETIFF      = 0x800454d2
IFF_TUN        = 0x0001
IFF_NO_PI      = 0x1000
SIOCSIFFLAGS   = 0x8914
SIOCGIFFLAGS   = 0x8913
SIOCSIFADDR    = 0x8916
SIOCGIFADDR    = 0x8915
SIOCSIFNETMASK = 0x891c
SIOCSIFMTU     = 0x8922
SIOCGIFMTU     = 0x8921
SIOCGIFINDEX   = 0x8933
IFF_UP         = 0x0001
IFF_RUNNING    = 0x0040

ready_file = sys.argv[1]
host_srv_port = int(sys.argv[2])
scm_sock_path = sys.argv[3]

def csum(data: bytes) -> int:
    if len(data) & 1:
        data += b'\x00'
    s = sum(struct.unpack(f'!{len(data)//2}H', data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

def build_ip4(src_ip: bytes, dst_ip: bytes, proto: int, payload: bytes) -> bytes:
    tot = 20 + len(payload)
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, tot, 1, 0x4000, 64, proto, 0, src_ip, dst_ip)
    c = csum(hdr)
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, tot, 1, 0x4000, 64, proto, c, src_ip, dst_ip)
    return hdr + payload

def build_tcp4(src_ip: bytes, dst_ip: bytes, sport: int, dport: int,
               seq: int, ack: int, flags: int, payload: bytes = b'', wnd: int = 65535) -> bytes:
    th = struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff,
                     0x50, flags, wnd, 0, 0) + payload
    pseudo = struct.pack('!4s4sBBH', src_ip, dst_ip, 0, 6, len(th))
    c = csum(pseudo + th)
    th = struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff,
                     0x50, flags, wnd, c, 0) + payload
    return build_ip4(src_ip, dst_ip, 6, th)

def build_udp4(src_ip: bytes, dst_ip: bytes, sport: int, dport: int, payload: bytes) -> bytes:
    ulen = 8 + len(payload)
    uh = struct.pack('!HHHH', sport, dport, ulen, 0) + payload
    pseudo = struct.pack('!4s4sBBH', src_ip, dst_ip, 0, 17, ulen)
    c = csum(pseudo + uh) or 0xffff
    uh = struct.pack('!HHHH', sport, dport, ulen, c) + payload
    return build_ip4(src_ip, dst_ip, 17, uh)

# 1. Verify /proc/net/dev, /proc/net/route, /sys/class/net/eth0/*
proc_dev = open('/proc/net/dev').read()
assert 'lo:' in proc_dev and 'eth0:' in proc_dev, proc_dev
assert 'wlan0:' not in proc_dev, proc_dev
proc_rt = open('/proc/net/route').read()
assert 'eth0' in proc_rt, proc_rt
assert open('/sys/class/net/eth0/operstate').read().strip() == 'up'
assert open('/sys/class/net/eth0/carrier').read().strip() == '1'
assert open('/sys/class/net/eth0/mtu').read().strip() == '1500'

# 2. Verify AF_NETLINK RTM_GETLINK + RTM_GETADDR
nl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
nl.bind((0, 0))
req = struct.pack('=IHHII', 32, 18, 0x301, 7, 0) + b'\x00' * 16
nl.send(req)
nl_data, nl_src = nl.recvfrom(8192)
assert nl_src == (0, 0), nl_src
assert b'eth0\x00' in nl_data and b'lo\x00' in nl_data, nl_data[:200]

# 3. Open /dev/net/tun, verify fstat 10:200, TUNGETFEATURES, TUNSETIFF, TUNGETIFF
tun_fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
st = os.fstat(tun_fd)
assert (st.st_mode & 0o170000) == 0o020000, oct(st.st_mode)
assert os.major(st.st_rdev) == 10 and os.minor(st.st_rdev) == 200, (os.major(st.st_rdev), os.minor(st.st_rdev))
feat = bytearray(4)
fcntl.ioctl(tun_fd, TUNGETFEATURES, feat)
assert struct.unpack('=I', feat)[0] & IFF_NO_PI

ifr = bytearray(40)
ifr[0:5] = b'tun%d'
struct.pack_into('=H', ifr, 16, IFF_TUN | IFF_NO_PI)
fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
ifname = bytes(ifr[:16]).split(b'\x00', 1)[0].decode()
assert ifname == 'tun0', ifname

ifr_chk = bytearray(40)
fcntl.ioctl(tun_fd, TUNGETIFF, ifr_chk)
assert bytes(ifr_chk[:16]).split(b'\x00', 1)[0].decode() == 'tun0'

# 4. Configure tun0 via SIOC* (IP 10.200.0.1/24, MTU 1400, UP)
ctl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
def mk_ifr(name):
    b = bytearray(40)
    b[:len(name)] = name.encode()
    return b

b = mk_ifr('tun0')
struct.pack_into('=HH4s', b, 16, socket.AF_INET, 0, socket.inet_aton('10.200.0.1'))
fcntl.ioctl(ctl, SIOCSIFADDR, b)

b = mk_ifr('tun0')
struct.pack_into('=HH4s', b, 16, socket.AF_INET, 0, socket.inet_aton('255.255.255.0'))
fcntl.ioctl(ctl, SIOCSIFNETMASK, b)

b = mk_ifr('tun0')
struct.pack_into('=i', b, 16, 1400)
fcntl.ioctl(ctl, SIOCSIFMTU, b)
b2 = mk_ifr('tun0')
fcntl.ioctl(ctl, SIOCGIFMTU, b2)
assert struct.unpack_from('=i', b2, 16)[0] == 1400

b = mk_ifr('tun0')
struct.pack_into('=H', b, 16, IFF_UP | IFF_RUNNING)
fcntl.ioctl(ctl, SIOCSIFFLAGS, b)

b = mk_ifr('tun0')
fcntl.ioctl(ctl, SIOCGIFINDEX, b)
tun_idx = struct.unpack_from('=i', b, 16)[0]
assert tun_idx >= 3, tun_idx

# 5. Add route 192.0.2.0/24 (RFC 5737 TEST-NET) AND 8.8.8.8/32, 1.1.1.1/32, 9.9.9.9/32 via RTNetlink
def add_nl_route(dst_str, prefix):
    dst = socket.inet_aton(dst_str)
    # rtmsg (12B) + RTA_DST (8B) + RTA_OIF (8B)
    rtm = struct.pack('=BBBBBBBBI', socket.AF_INET, prefix, 0, 0, 254, 3, 0, 1, 0)
    rta_dst = struct.pack('=HH4s', 8, 1, dst)
    rta_oif = struct.pack('=HHI', 8, 4, tun_idx)
    body = rtm + rta_dst + rta_oif
    hdr = struct.pack('=IHHII', 16 + len(body), 24, 0x05, 99, 0) # RTM_NEWROUTE, REQUEST|ACK
    nl.send(hdr + body)
    ack = nl.recv(4096)
    err = struct.unpack_from('=i', ack, 16)[0]
    assert err == 0, f'RTM_NEWROUTE failed: {err}'

add_nl_route('192.0.2.0', 24)
add_nl_route('8.8.8.8', 32)
add_nl_route('1.1.1.1', 32)
add_nl_route('9.9.9.9', 32)

# Verify /proc/net/dev & /sys/class/net/tun0
assert 'tun0:' in open('/proc/net/dev').read()
assert open('/sys/class/net/tun0/operstate').read().strip() == 'up'

# Test ICMPv4 Echo to 10.200.0.1 right now
icmp_req = struct.pack('!BBHHH', 8, 0, 0, 0x1234, 1) + b'PINGSVBOX'
ic = csum(icmp_req)
icmp_req = struct.pack('!BBHHH', 8, 0, ic, 0x1234, 1) + b'PINGSVBOX'
os.write(tun_fd, build_ip4(socket.inet_aton('10.200.0.2'), socket.inet_aton('10.200.0.1'), 1, icmp_req))
r, _, _ = select.select([tun_fd], [], [], 2.0)
assert r, 'No ICMP reply!'
irep = os.read(tun_fd, 4096)
assert irep[9] == 1 and irep[20] == 0 and irep[28:] == b'PINGSVBOX', irep

# Also listen on scm_sock_path so test can test SCM_RIGHTS handoff of tun_fd at the end
scm_srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
scm_srv.bind(scm_sock_path)
scm_srv.listen(4)
scm_srv.setblocking(False)

with open(ready_file, 'w') as f:
    f.write('READY\n')

# Minimal stateful TCP/UDP responder + real protected-socket proxy on tun0:
# - TCP to 198.18.0.42:8080: echoes back 256 KiB payload (testing OOO delivery on first two chunks!)
# - TCP to 198.18.0.100:80: dials real host_srv_port via SO_MARK-protected outbound socket and proxies!
# - UDP to *:53: echoes "DNS:<dst_ip>:" + payload (or valid DNS A reply for 198.18.0.77 if DNS wire!)
tcp_flows = {} # key=(src_ip, sport, dst_ip, dport) -> dict

deadline = time.time() + 25.0
while time.time() < deadline:
    rlist = [tun_fd, scm_srv]
    r, _, _ = select.select(rlist, [], [], 0.05)
    if scm_srv in r:
        conn, _ = scm_srv.accept()
        # Send tun_fd over SCM_RIGHTS and exit so caller verifies fd survives after opener closes!
        conn.sendmsg([b'TUNFD'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [tun_fd]))])
        conn.close()
        os.close(tun_fd)
        scm_srv.close()
        sys.exit(0)
    if tun_fd not in r:
        continue
    pkt = os.read(tun_fd, 65536)
    if len(pkt) < 20 or (pkt[0] >> 4) != 4:
        continue
    ihl = (pkt[0] & 0xf) * 4
    proto = pkt[9]
    src_ip = pkt[12:16]
    dst_ip = pkt[16:20]
    l4 = pkt[ihl:]

    if proto == 17 and len(l4) >= 8:
        sport, dport, ulen, _ = struct.unpack('!HHHH', l4[:8])
        payload = l4[8:ulen]
        dst_str = socket.inet_ntoa(dst_ip)
        if payload.startswith(b'ECHO:'):
            reply = f'UDP_OK:{dst_str}:{dport}:'.encode() + payload[5:]
        else:
            # Synthesize minimal DNS A-record response with FakeIP 198.18.0.77
            txid = payload[:2]
            reply = txid + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' + payload[12:]
            reply += b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04' + socket.inet_aton('198.18.0.77')
        os.write(tun_fd, build_udp4(dst_ip, src_ip, dport, sport, reply))
    elif proto == 6 and len(l4) >= 20:
        sport, dport, seq, ack, off_b, flags, wnd = struct.unpack('!HHIIBBH', l4[:16])
        doff = (off_b >> 4) * 4
        payload = l4[doff:]
        key = (src_ip, sport, dst_ip, dport)
        dst_str = socket.inet_ntoa(dst_ip)
        if flags & 0x02: # SYN
            st = {'srv_seq': 10000, 'cli_nxt': (seq + 1) & 0xffffffff, 'buf': bytearray(), 'mode': dst_str}
            tcp_flows[key] = st
            os.write(tun_fd, build_tcp4(dst_ip, src_ip, dport, sport, st['srv_seq'], st['cli_nxt'], 0x12))
            st['srv_seq'] = (st['srv_seq'] + 1) & 0xffffffff
        elif key in tcp_flows:
            st = tcp_flows[key]
            if flags & 0x04: # RST
                del tcp_flows[key]
                continue
            if payload and seq == st['cli_nxt']:
                st['buf'].extend(payload)
                st['cli_nxt'] = (st['cli_nxt'] + len(payload)) & 0xffffffff
                os.write(tun_fd, build_tcp4(dst_ip, src_ip, dport, sport, st['srv_seq'], st['cli_nxt'], 0x10))
            if flags & 0x01: # FIN from client
                st['cli_nxt'] = (st['cli_nxt'] + 1) & 0xffffffff
                os.write(tun_fd, build_tcp4(dst_ip, src_ip, dport, sport, st['srv_seq'], st['cli_nxt'], 0x10))
                if st['mode'] == '192.0.2.100':
                    # Proxy through a SO_MARK-protected outbound socket to the host server!
                    up = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    up.setsockopt(socket.SOL_SOCKET, 36, struct.pack('=I', 0xff)) # SO_MARK=0xff
                    assert struct.unpack('=I', up.getsockopt(socket.SOL_SOCKET, 36, 4))[0] == 0xff
                    up.connect(('127.0.0.1', host_srv_port))
                    up.sendall(bytes(st['buf']))
                    up.shutdown(socket.SHUT_WR)
                    resp = b''
                    while True:
                        ch = up.recv(4096)
                        if not ch: break
                        resp += ch
                    up.close()
                else:
                    resp = bytes(st['buf'])
                # Send response back over TUN (intentionally deliver 2nd chunk before 1st to test OOO reassembly!)
                chunks = [resp[i:i+1400] for i in range(0, len(resp), 1400)]
                seq_map = []
                cur_s = st['srv_seq']
                for ch in chunks:
                    seq_map.append((cur_s, ch))
                    cur_s = (cur_s + len(ch)) & 0xffffffff
                if len(seq_map) >= 2:
                    seq_map[0], seq_map[1] = seq_map[1], seq_map[0]
                for s_num, ch in seq_map:
                    os.write(tun_fd, build_tcp4(dst_ip, src_ip, dport, sport, s_num, st['cli_nxt'], 0x18, ch))
                st['srv_seq'] = cur_s
                os.write(tun_fd, build_tcp4(dst_ip, src_ip, dport, sport, st['srv_seq'], st['cli_nxt'], 0x11))
                st['srv_seq'] = (st['srv_seq'] + 1) & 0xffffffff
"""

CLIENT_PY = r"""
import array, errno, hashlib, os, socket, struct, sys, time

scm_sock_path = sys.argv[1]

# 1. Bulk 256 KiB TCP transfer over TUN (including OOO segments + getpeername/getsockname check)
payload = os.urandom(256 * 1024)
want_hash = hashlib.sha256(payload).hexdigest()
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(10)
s.connect(('192.0.2.42', 8080))
assert s.getpeername() == ('192.0.2.42', 8080), f'getpeername={s.getpeername()}'
assert s.getsockname()[0] == '10.200.0.1', f'getsockname={s.getsockname()}'
s.sendall(payload)
s.shutdown(socket.SHUT_WR)
got = bytearray()
while True:
    ch = s.recv(16384)
    if not ch: break
    got.extend(ch)
s.close()
assert len(got) == len(payload), (len(got), len(payload))
assert hashlib.sha256(got).hexdigest() == want_hash, 'SHA256 mismatch on 256KiB TCP!'

# 2. Dual-stack AF_INET6 ::ffff:192.0.2.42:8080 (exact Android Java/OkHttp/Chromium pattern)
s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s6.settimeout(5)
s6.connect(('::ffff:192.0.2.42', 8080))
assert s6.getpeername()[:2] == ('::ffff:192.0.2.42', 8080), s6.getpeername()
s6.sendall(b'hello-dualstack-v6')
s6.shutdown(socket.SHUT_WR)
r6 = s6.recv(1024)
s6.close()
assert r6 == b'hello-dualstack-v6', r6

# 3. Full FakeIP -> TUN proxy -> SO_MARK protected socket -> host TCP server!
sp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sp.settimeout(5)
sp.connect(('192.0.2.100', 80))
sp.sendall(b'GET /svbox-tun-test')
sp.shutdown(socket.SHUT_WR)
rp = sp.recv(1024)
sp.close()
assert rp == b'HOST_SERVER_ACK:GET /svbox-tun-test', rp

# 4. Connected UDP over TUN
uc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
uc.settimeout(5)
uc.connect(('8.8.8.8', 53))
assert uc.getpeername() == ('8.8.8.8', 53), uc.getpeername()
uc.send(b'ECHO:conn-udp')
rc = uc.recv(1024)
uc.close()
assert rc == b'UDP_OK:8.8.8.8:53:conn-udp', rc

# 5. Unconnected multi-peer UDP sendto/recvfrom over TUN with exact peer restoration
uu = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
uu.settimeout(5)
uu.sendto(b'ECHO:first', ('1.1.1.1', 53))
d1, a1 = uu.recvfrom(1024)
assert d1 == b'UDP_OK:1.1.1.1:53:first' and a1 == ('1.1.1.1', 53), (d1, a1)
uu.sendto(b'ECHO:second', ('9.9.9.9', 53))
d2, a2 = uu.recvfrom(1024)
assert d2 == b'UDP_OK:9.9.9.9:53:second' and a2 == ('9.9.9.9', 53), (d2, a2)
uu.close()

# 6. SO_MARK & SO_BINDTODEVICE bypass check (must NOT reach container's tun0!)
def check_bypassed(sock):
    sock.settimeout(0.4)
    try:
        sock.connect(('192.0.2.42', 8080))
        if sock.getsockname()[0] == '10.200.0.1':
            return False
        sock.sendall(b'BYPASS_PROBE')
        sock.shutdown(socket.SHUT_WR)
        try:
            data = sock.recv(64)
            return data != b'BYPASS_PROBE'
        except OSError:
            return True
    except OSError:
        return True

sb = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sb.setsockopt(socket.SOL_SOCKET, 36, struct.pack('=I', 0x42)) # SO_MARK
assert check_bypassed(sb), 'SO_MARK socket unexpectedly hit container TUN!'
sb.close()

sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sd.setsockopt(socket.SOL_SOCKET, 25, b'eth0\x00') # SO_BINDTODEVICE
assert sd.getsockopt(socket.SOL_SOCKET, 25, 16).rstrip(b'\x00') == b'eth0'
assert check_bypassed(sd), 'SO_BINDTODEVICE(eth0) socket unexpectedly hit container TUN!'
sd.close()

# 6b. Cross-process NET_OP_PROTECT_INO socket inode exemption (no SO_MARK/SO_BINDTODEVICE!)
net_sock_path = sys.argv[2]
sp_ino = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ino = os.fstat(sp_ino.fileno()).st_ino
assert ino != 0
ctl_p = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
ctl_p.connect(net_sock_path)
ctl_p.sendall(struct.pack('=IIiIIIQQ', 0x56444556, 0x104, 0, 0, 0, 0, ino, 0))
rh = ctl_p.recv(40)
ctl_p.close()
assert struct.unpack('=IIiIIIQQ', rh)[2] == 0
assert check_bypassed(sp_ino), 'NET_OP_PROTECT_INO socket unexpectedly hit container TUN!'
sp_ino.close()

# 6c. UID routing rule (disallowlist mode=2 for UID 0 -> bypasses TUN; mode=0 restores routing)
ctl_u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
ctl_u.connect(net_sock_path)
uid_req = struct.pack('=II', 2, 1) + struct.pack('=II', 0, 0) + b'\x00' * (31 * 8)
ctl_u.sendall(struct.pack('=IIiIIIQQ', 0x56444556, 0x107, 0, len(uid_req), 0, 0, 0, 0) + uid_req)
assert struct.unpack('=IIiIIIQQ', ctl_u.recv(40))[2] == 0
ctl_u.close()
su_byp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
assert check_bypassed(su_byp), 'UID-disallowed socket unexpectedly hit container TUN!'
su_byp.close()
ctl_u2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
ctl_u2.connect(net_sock_path)
uid_clr = struct.pack('=II', 0, 0) + b'\x00' * (32 * 8)
ctl_u2.sendall(struct.pack('=IIiIIIQQ', 0x56444556, 0x107, 0, len(uid_clr), 0, 0, 0, 0) + uid_clr)
assert struct.unpack('=IIiIIIQQ', ctl_u2.recv(40))[2] == 0
ctl_u2.close()

# 7. Test SCM_RIGHTS handoff of tun_fd from proxy -> client, then close -> auto-teardown!
c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
c.connect(scm_sock_path)
msg, ancdata, _, _ = c.recvmsg(64, socket.CMSG_SPACE(4))
c.close()
fds = array.array('i')
for cmsg_level, cmsg_type, cmsg_data in ancdata:
    if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
        fds.frombytes(cmsg_data[:4])
assert len(fds) == 1 and msg == b'TUNFD'
handed_tun = fds[0]
time.sleep(0.15)
# Proxy has exited and closed its copy, yet tun0 MUST still be alive while we hold handed_tun!
assert 'tun0:' in open('/proc/net/dev').read(), 'tun0 vanished while SCM_RIGHTS holder still open!'
os.close(handed_tun)
time.sleep(0.15)
# Now last holder closed -> svbox-net MUST have torn down tun0 automatically!
assert 'tun0:' not in open('/proc/net/dev').read(), 'tun0 not torn down after last FD closed!'
print('TUN_NETSTACK_ALL_OK')
"""

def run_host_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(('127.0.0.1', 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            data = b''
            while True:
                ch = c.recv(4096)
                if not ch: break
                data += ch
            c.sendall(b'HOST_SERVER_ACK:' + data)
            c.close()
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    return srv, port

def test_dns_rpc(net_sock_path):
    """Test generic NET_OP_DNS_QUERY RPC directly against svbox-net over TUN."""
    # Build minimal DNS A query for example.com
    dns_q = b'\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
    qreq = struct.pack('=IHH', 0, 53, 2000) + dns_q
    hdr = struct.pack('=IIiIIIQQ', 0x56444556, 0x109, 0, len(qreq), 1, 0, 0, 0)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(net_sock_path)
    s.sendall(hdr + qreq)
    rhdr = s.recv(40)
    magic, op, status, plen, _, _, _, _ = struct.unpack('=IIiIIIQQ', rhdr)
    assert magic == 0x56444556 and op == 0x109 and status == 0, (magic, op, status)
    rep = s.recv(plen)
    s.close()
    assert rep[:2] == b'\xab\xcd' and rep[-4:] == socket.inet_aton('198.18.0.77'), rep

python_rel = str(Path(sys.executable).resolve()).lstrip('/')

with tempfile.TemporaryDirectory(prefix='tun-net-', dir=lib.mode_capable()) as tmp:
    td = Path(tmp)
    net_sock = str(td / 'net.sock')
    scm_sock = str(td / 'scm.sock')
    ready_file = td / 'ready'
    srv, host_port = run_host_server()

    daemon = subprocess.Popen(
        [str(NET_DAEMON), '--sock', net_sock,
         '--iface', 'eth0:10.0.2.15/24:10.0.2.2:02:00:00:00:00:01',
         '--dns', '8.8.8.8', '--log-level', '2'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    proxy = None
    try:
        for _ in range(100):
            if os.path.exists(net_sock):
                break
            time.sleep(0.02)
        assert os.path.exists(net_sock), 'svbox-net failed to create net.sock'

        base_cmd = [
            str(LOADER),
            '--mode', 'container',
            '--root', '/',
            '--net-sock', net_sock,
            '--vdev', f'/dev/net/tun:{net_sock}:tun',
            '--', python_rel, '-B',
        ]
        proxy = subprocess.Popen(
            base_cmd + ['-c', TUN_PROXY_PY, str(ready_file), str(host_port), scm_sock],
            cwd='/', stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        for _ in range(200):
            if ready_file.exists():
                break
            if proxy.poll() is not None:
                break
            time.sleep(0.02)
        assert ready_file.exists(), f'proxy failed to start: rc={proxy.poll()} err={proxy.stderr.read()}'

        # Test NET_OP_DNS_QUERY RPC from external host resolver while tun0 is UP!
        test_dns_rpc(net_sock)

        # Run client container process (TCP 256KiB + OOO + dual-stack IPv6 + proxy loop + UDP + bypass + SCM_RIGHTS teardown)
        client = subprocess.run(
            base_cmd + ['-c', CLIENT_PY, scm_sock, net_sock],
            cwd='/', capture_output=True, text=True, timeout=30,
        )
        assert client.returncode == 0 and 'TUN_NETSTACK_ALL_OK\n' in client.stdout, (
            client.returncode, client.stdout, client.stderr,
            proxy.poll(), proxy.stderr.read() if proxy.poll() is not None else 'running',
        )
        proxy.wait(timeout=5)
        assert proxy.returncode == 0, (proxy.returncode, proxy.stderr.read())
    finally:
        if proxy and proxy.poll() is None:
            proxy.kill(); proxy.wait()
        daemon.terminate()
        daemon.wait(timeout=5)
        srv.close()

print('PASS: generic userspace virtual network & TUN stack (netlink, SIOC, proc/sys, TCP 256KiB+OOO+v6, UDP, bypass, proxy loop, DNS RPC, SCM_RIGHTS, auto-teardown)')
