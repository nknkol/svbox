#!/usr/bin/env python3
"""Reject high-bit MADV_REMOVE after admission loss; verify actual file bytes."""
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lib  # noqa: E402
repo=Path(__file__).resolve().parents[2]
build=lib.BUILD
loader = lib.loader('-guarded')
page=os.sysconf('SC_PAGE_SIZE')
with tempfile.TemporaryDirectory(prefix='madvise-abi-',dir=build) as tmp:
    root=Path(tmp)
    (root/'rw').mkdir()
    probe=root/'probe'
    target=root/'rw/file'
    subprocess.run(['clang','-O1','-nostdlib','-static','-ffreestanding','-fno-builtin',
                    '-fno-stack-protector',f'-DPAGE_SIZE={page}',
                    str(repo/'test/fs_policy/madvise_abi.c'),'-o',str(probe)],check=True)
    for level in ('native',None,'observe','paths','files'):
        for variant in ('low','high','sign'):
            target.write_bytes(b'Z'*page)
            before=target.stat()
            guarded=level=='files'
            if level=='native':
                command=[str(probe),str(target),'native',variant]
            else:
                policy=(['--root-mode','deny','-v',f'{root}/rw:/rw:rw','--guard',level]
                        if level else ['-v',f'{root}/rw:/rw'])
                command=[str(loader),'--mode','container','--root',str(root),*policy,
                         '--','./probe','/rw/file','guarded' if guarded else 'native',variant]
            p=subprocess.run(command,cwd=root,capture_output=True,timeout=20)
            actual=target.read_bytes()
            assert p.returncode==0,(level,variant,p.returncode,'file_zeroed',actual==bytes(page),p.stderr)
            assert actual==(b'Z'*page if guarded else bytes(page)),(level,variant)
            if guarded:
                after=target.stat()
                assert (before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(
                    after.st_size,after.st_mtime_ns,after.st_ctime_ns)
            print('PASS: madvise ABI, live shared mapping and host bytes:',level or 'none',variant)
