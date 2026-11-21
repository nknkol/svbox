#!/usr/bin/env python3
"""Reject untracked asynchronous IO, including valid inherited writable FDs."""
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
repo=Path(__file__).resolve().parents[2]
build=lib.BUILD
loader = lib.loader('-guarded')
with tempfile.TemporaryDirectory(prefix='async-policy-',dir=build) as tmp:
    root=Path(tmp)
    (root/'ro').mkdir()
    target=root/'ro/file'
    target.write_bytes(b'seed')
    probe=root/'probe'
    subprocess.run(['clang','-O1','-nostdlib','-static','-ffreestanding','-fno-builtin',
                    '-fno-stack-protector',str(repo/'test/fs_policy/async_io.c'),'-o',str(probe)],check=True)
    fd=os.open(target,os.O_RDWR)
    try:
        def invoke(level):
            if level=='native':
                command=[str(probe),str(fd),'native']
            else:
                policy=(['--root-mode','deny','-v',f'{root}/ro:/ro:ro','--guard',level]
                        if level else ['-v',f'{root}/ro:/ro'])
                command=[str(loader),'--mode','container','--root',str(root),*policy,
                         '--','./probe',str(fd),'guarded' if level=='files' else 'native']
            return subprocess.run(command,cwd=root,pass_fds=(fd,),capture_output=True,timeout=10)
        # Native capability is tested only inside an isolated child. A denial or
        # SIGSYS is an environmental limit, not successful AIO implementation.
        native=invoke('native')
        if native.returncode==0 and len(native.stdout)==40:
            baseline=struct.unpack('5q',native.stdout)
            print('Native AIO setup/submit/events/destroy/result:',baseline)
            if baseline==(0,1,1,0,4):
                assert target.read_bytes()==b'AIO!'
                for level in (None,'observe','paths'):
                    os.pwrite(fd,b'seed',0)
                    p=invoke(level)
                    assert p.returncode==0 and p.stdout==native.stdout,(level,p.returncode,p.stdout,p.stderr)
                    assert target.read_bytes()==b'AIO!'
                    print('PASS: native async write compatibility:',level or 'none')
            else:
                print('SKIP: native AIO write parity unavailable:',baseline)
        else:
            print('SKIP: native AIO probe unavailable:',native.returncode,native.stderr)
        os.pwrite(fd,b'seed',0)
        before=target.stat()
        p=invoke('files')
        assert p.returncode==0,(p.returncode,p.stdout,p.stderr,'host bytes',target.read_bytes())
        after=target.stat()
        assert target.read_bytes()==b'seed'
        assert (before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(
            after.st_size,after.st_mtime_ns,after.st_ctime_ns)
        print('PASS: all nine async entries reject valid/invalid requests without file changes')
    finally:
        os.close(fd)
