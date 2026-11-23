#!/usr/bin/env python3
"""High-concurrency stress test for svbox-net + net_stack.c:
1. 320 simultaneous TCP connections through virtual TUN (exceeds old 256 limit,
   exercises O(1) 4-tuple TCP hash table, 2048 connection table, 512 backlog).
2. 128 simultaneous SO_MARK sockets in one guest process (exceeds old static
   64-slot g_mark_fds limit, exercises dynamic mmap-grown mark table).
"""
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

LOADER = lib.loader()
NET_DAEMON = lib.BUILD / "svbox-net"

TUN_ECHO_SERVER_PY = r"""
import fcntl, os, select, socket, struct, sys, time

TUNSETIFF    = 0x400454ca
IFF_TUN      = 0x0001
IFF_NO_PI    = 0x1000
SIOCSIFFLAGS = 0x8914
SIOCSIFADDR  = 0x8916
SIOCSIFNETMASK = 0x891c
SIOCADDRT    = 0x890b
IFF_UP       = 0x0001
IFF_RUNNING  = 0x0040

ready_file = sys.argv[1]
target_conns = int(sys.argv[2])

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

tun_fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
ifr = struct.pack('16sH22s', b'tun0', IFF_TUN | IFF_NO_PI, b'')
fcntl.ioctl(tun_fd, TUNSETIFF, ifr)

ctl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
def set_if(cmd, data):
    fcntl.ioctl(ctl.fileno(), cmd, struct.pack('16s24s', b'tun0', data.ljust(24, b'\x00')))

set_if(SIOCSIFADDR, struct.pack('=HH4s8s', socket.AF_INET, 0, socket.inet_aton('10.200.0.1'), b''))
set_if(SIOCSIFNETMASK, struct.pack('=HH4s8s', socket.AF_INET, 0, socket.inet_aton('255.255.255.0'), b''))
set_if(SIOCSIFFLAGS, struct.pack('=H', IFF_UP | IFF_RUNNING))

# Add route 198.18.0.0/16 -> tun0 via netlink RTM_NEWROUTE
nl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
nl.bind((0, 0))
# RTM_NEWROUTE=24, NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL=0x605
# rtmsg: family=2, dst_len=16, src_len=0, tos=0, table=254, proto=3, scope=0, type=1, flags=0
rtm = struct.pack('=BBBBBBBBI', 2, 16, 0, 0, 254, 3, 0, 1, 0)
# RTA_DST (1): 198.18.0.0
rta_dst = struct.pack('=HH4s', 8, 1, socket.inet_aton('198.18.0.0'))
# Get tun0 ifindex
ifr_idx = bytearray(struct.pack('16s24s', b'tun0', b''))
fcntl.ioctl(ctl.fileno(), 0x8933, ifr_idx)
tun_idx = struct.unpack('=i', ifr_idx[16:20])[0]
rta_oif = struct.pack('=HHi', 8, 4, tun_idx)
body = rtm + rta_dst + rta_oif
hdr = struct.pack('=IHHII', 16 + len(body), 24, 0x605, 1, 0)
nl.send(hdr + body)
nl.recv(4096)

open(ready_file, 'w').write('ready\n')

# Stateless/lightweight TCP echo responder for all concurrent flows
flows = {}  # (src_ip, sport, dst_ip, dport) -> [srv_seq, cli_nxt]
deadline = time.monotonic() + 25.0
echoed = 0
while time.monotonic() < deadline:
    r, _, _ = select.select([tun_fd], [], [], 0.05)
    if not r:
        if echoed >= target_conns:
            break
        continue
    while True:
        try:
            pkt = os.read(tun_fd, 65535)
        except BlockingIOError:
            break
        if len(pkt) < 40 or (pkt[0] >> 4) != 4 or pkt[9] != 6:
            continue
        ihl = (pkt[0] & 0x0f) * 4
        src_ip = pkt[12:16]
        dst_ip = pkt[16:20]
        seg = pkt[ihl:]
        if len(seg) < 20:
            continue
        sport, dport, seq, ack = struct.unpack('!HHII', seg[:12])
        doff = (seg[12] >> 4) * 4
        flags = seg[13]
        payload = seg[doff:]
        key = (src_ip, sport, dst_ip, dport)
        if flags & 0x02:  # SYN
            srv_isn = 0x20000000 + sport
            flows[key] = [srv_isn + 1, (seq + 1) & 0xffffffff]
            resp = build_tcp4(dst_ip, src_ip, dport, sport, srv_isn, seq + 1, 0x12)
            os.write(tun_fd, resp)
        elif flags & 0x04:  # RST
            flows.pop(key, None)
        elif key in flows:
            st = flows[key]
            if payload:
                st[1] = (seq + len(payload)) & 0xffffffff
                # Echo payload back immediately
                resp = build_tcp4(dst_ip, src_ip, dport, sport, st[0], st[1], 0x18, payload)
                st[0] = (st[0] + len(payload)) & 0xffffffff
                os.write(tun_fd, resp)
                echoed += 1
            if flags & 0x01:  # FIN
                st[1] = (st[1] + 1) & 0xffffffff
                resp = build_tcp4(dst_ip, src_ip, dport, sport, st[0], st[1], 0x11)
                st[0] = (st[0] + 1) & 0xffffffff
                os.write(tun_fd, resp)
                flows.pop(key, None)
"""

CLIENT_STRESS_PY = r"""
import errno, select, socket, struct, sys, time

N_CONNS = int(sys.argv[1])
N_MARKS = int(sys.argv[2])
SO_MARK = 36

# Part 1: 128 simultaneous SO_MARK sockets (exceeds old static 64 limit)
mark_socks = []
for i in range(N_MARKS):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mark_val = 0x1000 + i
    s.setsockopt(socket.SOL_SOCKET, SO_MARK, struct.pack('=I', mark_val))
    mark_socks.append((s, mark_val))

for i, (s, expected) in enumerate(mark_socks):
    got = struct.unpack('=I', s.getsockopt(socket.SOL_SOCKET, SO_MARK, 4))[0]
    assert got == expected, f"SO_MARK mismatch at {i}: got {got:#x}, expected {expected:#x}"
for s, _ in mark_socks:
    s.close()

# Part 2: 320 simultaneous TCP connections through virtual TUN
socks = []
for i in range(N_CONNS):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setblocking(False)
    dst_ip = f"198.18.{1 + (i // 200)}.{1 + (i % 200)}"
    rc = s.connect_ex((dst_ip, 9000 + (i % 100)))
    assert rc in (0, errno.EINPROGRESS), f"connect_ex[{i}] failed: {rc}"
    socks.append((i, s, f"PING-{i:04d}".encode()))

# Wait for all sockets to connect & send payloads, keeping all 320 open simultaneously!
pending_write = {s: (i, msg) for i, s, msg in socks}
pending_read = {}
received = {}

deadline = time.monotonic() + 20.0
while (pending_write or pending_read) and time.monotonic() < deadline:
    rlist = list(pending_read.keys())
    wlist = list(pending_write.keys())
    rs, ws, _ = select.select(rlist, wlist, [], 0.2)
    for s in ws:
        i, msg = pending_write.pop(s)
        err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        assert err == 0, f"conn[{i}] SO_ERROR={err}"
        s.sendall(msg)
        pending_read[s] = (i, msg, bytearray())
    for s in rs:
        i, msg, buf = pending_read[s]
        chunk = s.recv(64)
        if chunk:
            buf.extend(chunk)
        if len(buf) >= len(msg):
            assert bytes(buf) == msg, f"conn[{i}] echo mismatch: {buf!r} != {msg!r}"
            received[i] = True
            pending_read.pop(s)

assert len(received) == N_CONNS, f"Only {len(received)}/{N_CONNS} completed (pw={len(pending_write)} pr={len(pending_read)})"

# Close all 320 cleanly after all were simultaneously live
for _, s, _ in socks:
    s.close()

print(f"OK_HIGH_CONC conns={N_CONNS} marks={N_MARKS}")
"""


def main():
    n_conns = 320
    n_marks = 128
    with tempfile.TemporaryDirectory(prefix="svbox_net_hc_") as td:
        sock = os.path.join(td, "net.sock")
        ready = os.path.join(td, "ready")
        srv_py = os.path.join(td, "srv.py")
        cli_py = os.path.join(td, "cli.py")
        Path(srv_py).write_text(TUN_ECHO_SERVER_PY)
        Path(cli_py).write_text(CLIENT_STRESS_PY)

        daemon = subprocess.Popen(
            [str(NET_DAEMON), "--sock", sock, "--log-level", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        srv = None
        try:
            for _ in range(50):
                if os.path.exists(sock):
                    break
                time.sleep(0.05)
            assert os.path.exists(sock), "svbox-net failed to create socket"

            python_rel = str(Path(sys.executable).resolve()).lstrip("/")
            base_cmd = [
                str(LOADER),
                "--mode", "container",
                "--root", "/",
                "--net-sock", sock,
                "--vdev", f"/dev/net/tun:{sock}:tun",
                "--", python_rel, "-B",
            ]
            srv = subprocess.Popen(
                base_cmd + [srv_py, ready, str(n_conns)],
                cwd="/", stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            for _ in range(100):
                if os.path.exists(ready) or srv.poll() is not None:
                    break
                time.sleep(0.05)
            assert os.path.exists(ready), (
                f"TUN echo server failed: rc={srv.poll()} err={srv.stderr.read() if srv.poll() is not None else 'running'}"
            )

            t0 = time.monotonic()
            cli = subprocess.run(
                base_cmd + [cli_py, str(n_conns), str(n_marks)],
                cwd="/", stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30,
            )
            dt = time.monotonic() - t0
            if cli.returncode != 0 or f"OK_HIGH_CONC conns={n_conns} marks={n_marks}" not in cli.stdout:
                raise AssertionError(
                    f"client failed rc={cli.returncode}\nstdout={cli.stdout}\nstderr={cli.stderr}"
                )
            srv.wait(timeout=10)
            print(f"PASS: high-concurrency netstack ({n_conns} simultaneous TCP over TUN + {n_marks} SO_MARK sockets in {dt:.2f}s)")
        finally:
            if srv and srv.poll() is None:
                srv.terminate()
                try:
                    srv.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    srv.kill()
            daemon.terminate()
            try:
                daemon.wait(timeout=3)
            except subprocess.TimeoutExpired:
                daemon.kill()


if __name__ == "__main__":
    main()
