#!/usr/bin/env python3
"""Generic --vdev chr ioctl ABI tests: FIONBIO/FIONREAD passthrough, legacy
termios/winsize, and Linux usbfs (USBDEVFS_CONTROL/BULK/CLAIM/GETDRIVER)."""
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
HDR_FMT = "<IIiIIIQQ"
HDR_SZ = struct.calcsize(HDR_FMT)


def recv_exact(conn, n):
    buf = bytearray()
    while len(buf) < n:
        ch = conn.recv(n - len(buf))
        if not ch:
            return None
        buf.extend(ch)
    return bytes(buf)


def send_reply(conn, op, proc_id, status, payload=b""):
    hdr = struct.pack(HDR_FMT, VDEV_PROTO_MAGIC, op, status, len(payload), proc_id, 0, 0, 0)
    conn.sendall(hdr + payload)


class MockUsbSerialDaemon:
    def __init__(self, sock_path):
        self.stop_evt = threading.Event()
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(sock_path)
        self.srv.listen(32)
        self.srv.setblocking(False)
        self.termios = bytearray(36)
        self.termios[0:4] = struct.pack("<I", 0x0500)
        self.winsize = struct.pack("<HHHH", 24, 80, 0, 0)
        self.claimed_iface = -1
        self.last_bulk_out = b""
        self.last_ctrl_out = b""
        self.stream_conns = []
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        conns = {}
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
                    conns[c.fileno()] = {"sock": c, "kind": "new"}
                else:
                    fd = s.fileno()
                    info = conns.get(fd)
                    if not info:
                        continue
                    if info["kind"] == "stream":
                        d = s.recv(4096)
                        if not d:
                            s.close()
                            conns.pop(fd, None)
                        continue
                    raw = recv_exact(s, HDR_SZ)
                    if not raw:
                        s.close()
                        conns.pop(fd, None)
                        continue
                    magic, op, _, plen, proc_id, _, _, _ = struct.unpack(HDR_FMT, raw)
                    payload = recv_exact(s, plen) if plen else b""
                    if magic != VDEV_PROTO_MAGIC or payload is None:
                        s.close()
                        conns.pop(fd, None)
                        continue
                    if op == VDEV_OP_OPEN:
                        info["kind"] = "stream"
                        rep = struct.pack("<IIII", 1, 189, 1, 0)
                        send_reply(s, op, 1, 0, rep)
                        # Push 6 bytes into stream so FIONREAD sees them.
                        s.sendall(b"HELLO!")
                    elif op == VDEV_OP_ATTACH_THREAD:
                        info["kind"] = "thread"
                        send_reply(s, op, proc_id, 0)
                    elif op == VDEV_OP_IOCTL:
                        cmd, arg, in_len, out_len = struct.unpack_from("<QQII", payload, 0)
                        data = payload[24:24 + in_len]
                        if cmd == 0x5401:  # TCGETS
                            send_reply(s, op, proc_id, 0, bytes(self.termios))
                        elif cmd == 0x5402:  # TCSETS
                            self.termios[:] = data[:36]
                            send_reply(s, op, proc_id, 0)
                        elif cmd == 0x5413:  # TIOCGWINSZ
                            send_reply(s, op, proc_id, 0, self.winsize)
                        elif cmd == 0x8004550f:  # USBDEVFS_CLAIMINTERFACE
                            self.claimed_iface = struct.unpack("<I", data[:4])[0]
                            send_reply(s, op, proc_id, 0)
                        elif cmd == 0x41045508:  # USBDEVFS_GETDRIVER
                            iface = struct.unpack("<I", data[:4])[0]
                            drv = f"svbox-usb-{iface}".encode().ljust(256, b"\x00")
                            send_reply(s, op, proc_id, 0, struct.pack("<I", iface) + drv)
                        elif cmd == 0xc0185500:  # USBDEVFS_CONTROL
                            bReqType, bReq, wVal, wIdx, wLen, to, pad, ptr = struct.unpack_from("<BBHHHIIQ", data, 0)
                            if bReqType & 0x80:  # IN
                                reply = b"\x12\x01\x00\x02\x00\x00\x00\x40"[:wLen]
                                send_reply(s, op, proc_id, len(reply), reply)
                            else:  # OUT
                                self.last_ctrl_out = data[24:24 + wLen]
                                send_reply(s, op, proc_id, len(self.last_ctrl_out))
                        elif cmd == 0xc0185502:  # USBDEVFS_BULK
                            ep, blen, to, pad, ptr = struct.unpack_from("<IIIIQ", data, 0)
                            if ep & 0x80:  # IN: echo reversed last_bulk_out
                                reply = self.last_bulk_out[::-1][:blen]
                                send_reply(s, op, proc_id, len(reply), reply)
                            else:  # OUT
                                self.last_bulk_out = data[24:24 + blen]
                                send_reply(s, op, proc_id, len(self.last_bulk_out))
                        else:
                            send_reply(s, op, proc_id, -25)
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
#include <errno.h>
#include <fcntl.h>
#include <linux/usbdevice_fs.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct k_termios {
    uint32_t c_iflag, c_oflag, c_cflag, c_lflag;
    uint8_t c_line;
    uint8_t c_cc[19];
};

int main(void) {
    int fd = open("/dev/vusb0", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    /* 1. FIONBIO + FIONREAD native socket passthrough */
    int one = 1;
    if (ioctl(fd, FIONBIO, &one) != 0) { perror("FIONBIO"); return 2; }
    int avail = 0;
    for (int i = 0; i < 50 && avail == 0; i++) {
        if (ioctl(fd, FIONREAD, &avail) != 0) { perror("FIONREAD"); return 3; }
        if (avail == 0) usleep(10000);
    }
    if (avail != 6) { fprintf(stderr, "FIONREAD=%d want 6\n", avail); return 4; }
    char rbuf[16] = {0};
    if (read(fd, rbuf, 6) != 6 || memcmp(rbuf, "HELLO!", 6) != 0) {
        fprintf(stderr, "read mismatch: %s\n", rbuf);
        return 5;
    }
    /* Non-blocking read when empty must return EAGAIN */
    if (read(fd, rbuf, 4) != -1 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
        fprintf(stderr, "expected EAGAIN after FIONBIO, errno=%d\n", errno);
        return 6;
    }

    /* 2. Legacy termios & winsize */
    struct k_termios tio = {0};
    if (ioctl(fd, 0x5401 /* TCGETS */, &tio) != 0 || tio.c_iflag != 0x0500) {
        fprintf(stderr, "TCGETS failed iflag=0x%x\n", tio.c_iflag);
        return 7;
    }
    tio.c_iflag = 0x1234;
    if (ioctl(fd, 0x5402 /* TCSETS */, &tio) != 0) { perror("TCSETS"); return 8; }
    memset(&tio, 0, sizeof(tio));
    if (ioctl(fd, 0x5401 /* TCGETS */, &tio) != 0 || tio.c_iflag != 0x1234) {
        fprintf(stderr, "TCGETS verify failed iflag=0x%x\n", tio.c_iflag);
        return 9;
    }
    struct winsize ws = {0};
    if (ioctl(fd, TIOCGWINSZ, &ws) != 0 || ws.ws_row != 24 || ws.ws_col != 80) {
        fprintf(stderr, "TIOCGWINSZ failed %ux%u\n", ws.ws_row, ws.ws_col);
        return 10;
    }

    /* 3. Linux usbfs ioctls */
    unsigned int iface = 2;
    if (ioctl(fd, USBDEVFS_CLAIMINTERFACE, &iface) != 0) { perror("CLAIM"); return 11; }

    struct usbdevfs_getdriver gd = {0};
    gd.interface = 2;
    if (ioctl(fd, USBDEVFS_GETDRIVER, &gd) != 0 || strcmp(gd.driver, "svbox-usb-2") != 0) {
        fprintf(stderr, "GETDRIVER failed: %s\n", gd.driver);
        return 12;
    }

    uint8_t desc[8] = {0};
    struct usbdevfs_ctrltransfer ct = {0};
    ct.bRequestType = 0x80; /* IN */
    ct.bRequest = 0x06;
    ct.wLength = 8;
    ct.data = desc;
    int cr = ioctl(fd, USBDEVFS_CONTROL, &ct);
    if (cr != 8 || desc[0] != 0x12 || desc[1] != 0x01 || desc[7] != 0x40) {
        fprintf(stderr, "CONTROL IN failed cr=%d\n", cr);
        return 13;
    }

    char out_msg[] = "SVBOX_USB_BULK_1234";
    struct usbdevfs_bulktransfer bt = {0};
    bt.ep = 0x02; /* OUT */
    bt.len = (uint32_t)strlen(out_msg);
    bt.data = out_msg;
    if (ioctl(fd, USBDEVFS_BULK, &bt) != (int)strlen(out_msg)) {
        perror("BULK OUT");
        return 14;
    }

    char in_msg[32] = {0};
    bt.ep = 0x82; /* IN */
    bt.len = (uint32_t)strlen(out_msg);
    bt.data = in_msg;
    int br = ioctl(fd, USBDEVFS_BULK, &bt);
    if (br != (int)strlen(out_msg) || strcmp(in_msg, "4321_KLUB_BSU_XOBVS") != 0) {
        fprintf(stderr, "BULK IN failed br=%d got='%s'\n", br, in_msg);
        return 15;
    }

    close(fd);
    printf("VDEV_CHR_IOCTLS_OK\n");
    return 0;
}
"""


def main():
    sock_dir = tempfile.mkdtemp(prefix="svbox-vdev-chr-", dir=lib.mode_capable())
    sock_path = os.path.join(sock_dir, "vusb.sock")
    daemon = MockUsbSerialDaemon(sock_path)
    try:
        with tempfile.TemporaryDirectory(prefix="vdev-chr-", dir=lib.BUILD) as td:
            src = Path(td) / "guest.c"
            exe = Path(td) / "guest"
            src.write_text(GUEST_C)
            subprocess.run(["clang", "-O2", str(src), "-o", str(exe)], check=True)
            cmd = [
                str(lib.loader()),
                "--vdev", f"/dev/vusb0:{sock_path}:chr",
                "--", str(exe),
            ]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            assert p.returncode == 0 and "VDEV_CHR_IOCTLS_OK" in p.stdout, (p.returncode, p.stdout, p.stderr)
            assert daemon.claimed_iface == 2
            print("PASS: --vdev chr ioctls (FIONBIO, FIONREAD, termios/winsize, USBDEVFS control/bulk/claim/getdriver)")
    finally:
        daemon.stop()
        try:
            os.unlink(sock_path)
            os.rmdir(sock_dir)
        except OSError:
            pass


if __name__ == "__main__":
    main()
