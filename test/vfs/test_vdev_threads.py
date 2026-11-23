#!/usr/bin/env python3
"""Generic --vdev multi-thread RPC channel test: >64 concurrent threads keep
stable per-thread daemon sessions, and exited threads are reclaimed."""
import os
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402

VDEV_PROTO_MAGIC = 0x56444556
VDEV_OP_OPEN = 1
VDEV_OP_ATTACH_THREAD = 2
VDEV_OP_IOCTL = 4

# struct vdev_hdr: 6*I + 2*Q = 40 bytes? Wait: check exact layout:
# uint32 magic, op; int32 status; uint32 payload_len, proc_id, fd_count; uint64 arg0, arg1 -> 40 bytes.
HDR_FMT = "<IIiIIIQQ"
HDR_SZ = struct.calcsize(HDR_FMT)


def recv_exact(conn, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


def send_reply(conn, op, proc_id, status, payload=b""):
    hdr = struct.pack(HDR_FMT, VDEV_PROTO_MAGIC, op, status, len(payload), proc_id, 0, 0, 0)
    conn.sendall(hdr + payload)


class MockVdevDaemon:
    def __init__(self, sock_path):
        self.sock_path = sock_path
        self.stop_evt = threading.Event()
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(sock_path)
        self.srv.listen(256)
        self.srv.setblocking(False)
        self.active_thread_conns = 0
        self.peak_thread_conns = 0
        self.total_attaches = 0
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        conns = {}  # fd -> dict(sock, kind, state)
        next_proc_id = 1
        while not self.stop_evt.is_set():
            rlist = [self.srv] + [c["sock"] for c in conns.values()]
            try:
                ready, _, _ = select.select(rlist, [], [], 0.05)
            except OSError:
                break
            for s in ready:
                if s is self.srv:
                    try:
                        c, _ = self.srv.accept()
                    except OSError:
                        continue
                    c.setblocking(True)
                    conns[c.fileno()] = {"sock": c, "kind": "new", "state": 0}
                else:
                    fd = s.fileno()
                    info = conns.get(fd)
                    if not info:
                        continue
                    raw = recv_exact(s, HDR_SZ)
                    if not raw:
                        if info["kind"] == "thread":
                            with self.lock:
                                self.active_thread_conns -= 1
                        s.close()
                        conns.pop(fd, None)
                        continue
                    magic, op, status, plen, proc_id, fd_cnt, a0, a1 = struct.unpack(HDR_FMT, raw)
                    payload = recv_exact(s, plen) if plen else b""
                    if magic != VDEV_PROTO_MAGIC or payload is None:
                        s.close()
                        conns.pop(fd, None)
                        continue
                    if op == VDEV_OP_OPEN:
                        pid = next_proc_id
                        next_proc_id += 1
                        info["kind"] = "notify"
                        rep = struct.pack("<IIII", pid, 10, 250, 0)
                        send_reply(s, op, pid, 0, rep)
                    elif op == VDEV_OP_ATTACH_THREAD:
                        info["kind"] = "thread"
                        with self.lock:
                            self.total_attaches += 1
                            self.active_thread_conns += 1
                            if self.active_thread_conns > self.peak_thread_conns:
                                self.peak_thread_conns = self.active_thread_conns
                        send_reply(s, op, proc_id, 0)
                    elif op == VDEV_OP_IOCTL:
                        # struct vdev_ioctl_req { uint64 cmd, arg; uint32 in_len, out_len; }
                        cmd, arg, in_len, out_len = struct.unpack_from("<QQII", payload, 0)
                        cmd &= 0xffffffff
                        data = payload[24:24 + in_len]
                        if cmd == 0x40045601 and len(data) == 4:
                            # SET_TAG: bind caller-chosen u32 token to this thread connection.
                            info["state"] = struct.unpack("<I", data)[0]
                            send_reply(s, op, proc_id, 0)
                        elif cmd == 0x80045602:
                            # GET_TAG: return the token bound to this thread connection.
                            send_reply(s, op, proc_id, 0, struct.pack("<I", info["state"]))
                        else:
                            send_reply(s, op, proc_id, -25)  # -ENOTTY
                    else:
                        send_reply(s, op, proc_id, -25)
        for info in list(conns.values()):
            try:
                info["sock"].close()
            except OSError:
                pass
        try:
            self.srv.close()
        except OSError:
            pass

    def stop(self):
        self.stop_evt.set()
        self.thread.join(timeout=2)


GUEST_C = r"""
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#define IOCTL_SET_TAG 0x40045601u
#define IOCTL_GET_TAG 0x80045602u

static int g_fd = -1;
static pthread_barrier_t g_bar;
static volatile int g_errors = 0;

static void *concurrent_worker(void *arg) {
    uint32_t idx = (uint32_t)(uintptr_t)arg;
    uint32_t token = 0x10000000u + idx;
    if (ioctl(g_fd, IOCTL_SET_TAG, &token) != 0) {
        fprintf(stderr, "concurrent SET_TAG failed idx=%u errno=%d\n", idx, errno);
        __sync_fetch_and_add(&g_errors, 1);
    }
    pthread_barrier_wait(&g_bar);
    uint32_t got = 0;
    if (ioctl(g_fd, IOCTL_GET_TAG, &got) != 0 || got != token) {
        fprintf(stderr, "concurrent GET_TAG mismatch idx=%u got=0x%x want=0x%x errno=%d\n",
                idx, got, token, errno);
        __sync_fetch_and_add(&g_errors, 1);
    }
    return NULL;
}

static void *ephemeral_worker(void *arg) {
    uint32_t idx = (uint32_t)(uintptr_t)arg;
    uint32_t token = 0x20000000u + idx;
    uint32_t got = 0;
    if (ioctl(g_fd, IOCTL_SET_TAG, &token) != 0 ||
        ioctl(g_fd, IOCTL_GET_TAG, &got) != 0 || got != token) {
        fprintf(stderr, "ephemeral mismatch idx=%u got=0x%x want=0x%x\n", idx, got, token);
        __sync_fetch_and_add(&g_errors, 1);
    }
    return NULL;
}

int main(void) {
    g_fd = open("/dev/vtest", O_RDWR);
    if (g_fd < 0) {
        perror("open /dev/vtest");
        return 1;
    }

    /* Phase 1: 128 concurrent threads (> legacy 64-slot limit). */
    const int N_CONC = 128;
    pthread_t th[128];
    pthread_barrier_init(&g_bar, NULL, N_CONC);
    for (int i = 0; i < N_CONC; i++) {
        if (pthread_create(&th[i], NULL, concurrent_worker, (void *)(uintptr_t)i) != 0) {
            perror("pthread_create");
            return 2;
        }
    }
    for (int i = 0; i < N_CONC; i++)
        pthread_join(th[i], NULL);
    pthread_barrier_destroy(&g_bar);

    /* Phase 2: 320 sequential short-lived threads to verify dead-thread reclamation. */
    for (int i = 0; i < 320; i++) {
        pthread_t t;
        if (pthread_create(&t, NULL, ephemeral_worker, (void *)(uintptr_t)i) != 0) {
            perror("pthread_create ephemeral");
            return 3;
        }
        pthread_join(t, NULL);
    }

    close(g_fd);
    if (g_errors != 0) {
        fprintf(stderr, "FAILED with %d errors\n", g_errors);
        return 4;
    }
    printf("VDEV_THREADS_OK\n");
    return 0;
}
"""


def main():
    sock_dir = tempfile.mkdtemp(prefix="svbox-vdev-th-", dir=lib.mode_capable())
    sock_path = os.path.join(sock_dir, "vtest.sock")
    daemon = MockVdevDaemon(sock_path)
    try:
        with tempfile.TemporaryDirectory(prefix="vdev-th-", dir=lib.BUILD) as td:
            src = Path(td) / "guest.c"
            exe = Path(td) / "guest"
            src.write_text(GUEST_C)
            subprocess.run(["clang", "-O2", "-pthread", str(src), "-o", str(exe)], check=True)
            cmd = [
                str(lib.loader()),
                "--vdev", f"/dev/vtest:{sock_path}:chr",
                "--", str(exe),
            ]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            assert p.returncode == 0 and "VDEV_THREADS_OK" in p.stdout, (p.returncode, p.stdout, p.stderr)
            # Peak live thread connections should stay bounded (initial cap 256, reclaimed before hitting 448).
            assert daemon.peak_thread_conns <= 260, (
                f"dead threads not reclaimed: peak={daemon.peak_thread_conns}, total={daemon.total_attaches}"
            )
            assert daemon.total_attaches >= 400, f"unexpected total attaches: {daemon.total_attaches}"
            print(f"PASS: --vdev multi-thread sessions & dead-thread reclamation "
                  f"(total_attaches={daemon.total_attaches}, peak_live={daemon.peak_thread_conns})")
    finally:
        daemon.stop()
        try:
            os.unlink(sock_path)
            os.rmdir(sock_dir)
        except OSError:
            pass


if __name__ == "__main__":
    main()
