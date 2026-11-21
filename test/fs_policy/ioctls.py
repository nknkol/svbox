#!/usr/bin/env python3
"""File ioctl authorization, command/type rejection and native parity."""
import hashlib
import json
import os
import struct
import subprocess
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
repo = Path(__file__).resolve().parents[2]
build = lib.BUILD
loader = lib.loader('-guarded')
with tempfile.TemporaryDirectory(prefix='ioctl-policy-', dir=build) as tmp:
    root = Path(tmp)
    for name in ('ro', 'rw', 'deny'):
        (root / name).mkdir()
        (root / name / 'file').write_bytes(b'unchanged')
    before = {name: (root / name / 'file').stat().st_ctime_ns for name in ('ro', 'deny')}
    def compile_probe(guarded):
        subprocess.run(['clang', '-O1', '-nostdlib', '-static', '-ffreestanding',
                        '-fno-builtin', '-fno-stack-protector', *(['-DGUARDED'] if guarded else []),
                        str(repo / 'test/fs_policy/ioctls.c'), '-o', str(root / 'probe.next')], check=True)
        (root / 'probe.next').replace(root / 'probe')
    compile_probe(False)
    native = subprocess.run([str(root / 'probe'), 'native', str(root / 'rw/file')],
                            capture_output=True, timeout=10)
    assert native.returncode == 0 and len(native.stdout)==64, (
        'native ioctl probe', native.returncode, native.stdout, native.stderr)
    print('Native permitted ioctl results:', struct.unpack('8q', native.stdout))
    base = [str(loader), '--mode', 'container', '--root', str(root)]
    pol_binds = ['--root-mode', 'deny', '-v', f'{root}/ro:/ro:ro',
                 '-v', f'{root}/rw:/rw:rw', '-v', f'{root}/deny:/deny:deny']
    raw_binds = ['-v', f'{root}/ro:/ro', '-v', f'{root}/rw:/rw', '-v', f'{root}/deny:/deny']
    for level in (None, 'observe', 'paths', 'files'):
        guarded = level == 'files'
        compile_probe(guarded)
        command = [*base, *([*pol_binds, '--guard', level] if level else raw_binds),
                   *(['--allow-stdio'] if guarded else []), '--', './probe', 'guest']
        p = subprocess.run(command, cwd=root, capture_output=True, timeout=20)
        assert p.returncode == 0 and p.stdout==native.stdout, (
            level, p.returncode, p.stdout, p.stderr)
        for name in ('ro', 'rw', 'deny'):
            assert (root / name / 'file').read_bytes()==b'unchanged'
        for name, timestamp in before.items():
            assert (root / name / 'file').stat().st_ctime_ns==timestamp
        print('PASS: ioctl native parity and policy:', level or 'none')
    master, slave = os.openpty()
    try:
        p = subprocess.run([*base, *pol_binds, '--guard', 'files',
                            '--allow-stdio', '--', './probe', 'tty'], cwd=root,
                           stdout=slave, stderr=subprocess.PIPE, timeout=20)
        assert p.returncode==0, (p.returncode, p.stderr)
        print('PASS: real PTY queries and mutation/injection rejection')
    finally:
        os.close(master);os.close(slave)
