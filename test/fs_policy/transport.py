#!/usr/bin/env python3
"""Real loader/payload/exec observation transport; no permission enforcement."""
import hashlib
import json
import re
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
with tempfile.TemporaryDirectory(prefix='policy-transport-', dir=build) as tmp:
    root = Path(tmp)
    for name in ('ro', 'rw'):
        (root / name).mkdir()
    base = [str(loader), '--mode', 'container', '--root', str(root)]
    def run(options):
        return subprocess.run([*base, *options, '--', './probe'], cwd=root,
                              capture_output=True, text=True, timeout=20)
    for enabled in (True, False):
        subprocess.run(['clang', '-O1', '-nostdlib', '-static', '-ffreestanding',
                        '-fno-builtin', '-fno-stack-protector',
                        *([] if enabled else ['-DNO_POLICY']),
                        '-I' + str(repo / 'src/payload/include'),
                        str(repo / 'test/fs_policy/transport.c'), '-o', str(root / 'probe.next')], check=True)
        (root / 'probe.next').replace(root / 'probe')
        opts = (['--root-mode', 'deny', '-v', f'{root}/ro:/ro:ro', '-v', f'{root}/rw:/rw:rw',
                 '--guard', 'observe'] if enabled
                else ['-v', f'{root}/ro:/ro', '-v', f'{root}/rw:/rw', '--guard', 'track'])
        p = run(opts)
        assert p.returncode == 0 and 'PASS: policy observation' in p.stdout, (p.returncode, p.stdout, p.stderr)
        print('PASS: real exec transport, observation enabled =', enabled)
    for options in (['--root-mode', 'bad'],
                    ['-v', f'{root}/ro:/ro:bad'],
                    ['--guard', 'bogus'],
                    ['--root-mode', 'ro', '--guard', 'none'],
                    ['--root-mode', 'ro', '--guard', 'track'],
                    ['--guard', 'observe', '--guard', 'observe'],
                    ['--guard', 'observe', '--guard', 'paths'],
                    ['--guard', 'observe', '--sandbox'],
                    ['--sandbox', '--sandbox'],
                    ['--__handoff-fd', '9999']):
        p = run(options)
        assert p.returncode != 0, (options, p.stdout, p.stderr)
    # --help and --version smoke checks
    p = subprocess.run([str(loader), '--help'], capture_output=True, text=True, timeout=10)
    assert p.returncode == 0 and 'Usage: svbox' in p.stdout and '--__handoff-fd' not in p.stdout, p.stdout
    p = subprocess.run([str(loader), '--version'], capture_output=True, text=True, timeout=10)
    assert p.returncode == 0 and p.stdout.startswith('svbox '), p.stdout
    print('PASS: reject malformed/conflicting CLI options, bad handoff FD, and verify --help/--version')
    # Verify the actual experimental payload layout has its own ABI version,
    # and old custom payload headers are rejected before guest startup.
    ABI = int(re.search(r'#define PAYLOAD_ABI_VERSION (\d+)', (repo / 'src/payload/include/elf_abi.h').read_text()).group(1))
    blob = (repo / 'src/payload/payload.bin').read_bytes()
    entry, phoff = struct.unpack_from('<QQ', blob, 24)
    phsize, phnum = struct.unpack_from('<HH', blob, 54)
    offset = None
    for i in range(phnum):
        kind, _, off, addr, _, size, _, _ = struct.unpack_from('<IIQQQQQQ', blob, phoff+i*phsize)
        if kind == 1 and addr <= entry and entry+16 <= addr+size:
            offset = off+entry-addr
            break
    assert offset is not None and struct.unpack_from('<I', blob, offset+12)[0] == ABI
    for version in range(ABI - 1, 1, -1):
        old = bytearray(blob)
        struct.pack_into('<I', old, offset+12, version)
        payload = root / f'old-{version}.bin'
        payload.write_bytes(old)
        p = subprocess.run([str(loader), '--payload', str(payload), '--mode', 'compat',
                            '--', str(root / 'probe')], capture_output=True, text=True, timeout=20)
        assert p.returncode != 0 and 'payload ABI mismatch' in p.stdout+p.stderr, (p.stdout, p.stderr)
    print(f'PASS: payload ABI {ABI} rejects older payload layouts')
