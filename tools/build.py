#!/usr/bin/env python3
"""Build svbox (with its embedded payload) and svbox-exec into build/.

Outputs build/svbox, build/svbox-exec, and build/svbox.json recording their
hashes: tests refuse a binary that is not the last one built. A failed build
leaves no manifest."""
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from elf_abi import LOADER_FIXED_BASE

parser = argparse.ArgumentParser(description=__doc__)
args = parser.parse_args()
repo = Path(__file__).resolve().parents[1]
build = repo / 'build'
build.mkdir(exist_ok=True)
name = 'svbox'
(build / f'{name}.json').unlink(missing_ok=True)
# Dependency files hold absolute paths; drop them after repository moves.
shutil.rmtree(repo / 'src/payload/path-build', ignore_errors=True)
with (build / f'{name}.log').open('w') as log:
    # Static and non-PIE at a fixed address: no host dynamic linker in guest
    # processes, and the seccomp backstop allows the loader's own syscalls
    # by address across every exec.
    subprocess.run(['make', '-B', '-C', str(repo / 'src'), 'CC=clang', 'LD=ld.lld',
                    'OBJCOPY=llvm-objcopy',
                    f'LDFLAGS=-nostdlib -static -no-pie -Wl,--image-base={LOADER_FIXED_BASE:#x} '
                    '-e z_start -Wl,--no-undefined,--build-id=none'],
                   stdout=log, stderr=subprocess.STDOUT, check=True)
binary = build / name
pending = build / f'{name}.next'
shutil.copy2(repo / 'src' / name, pending)
pending.replace(binary)
manifest = {'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
# First guest program of agent launches and containers (tools/oci). Static-pie
# keeps it near the loader's stubs; it carries no relocations.
helper = build / 'svbox-exec'
subprocess.run(['clang', '-O1', '-static-pie', '-fPIE', '-nostdlib', '-ffreestanding',
                '-fno-builtin', '-fno-stack-protector', '-I', str(repo / 'src/payload/include'),
                str(repo / 'tools/agent/exec_helper.c'), '-o', str(helper)], check=True)
manifest['exec_helper_sha256'] = hashlib.sha256(helper.read_bytes()).hexdigest()
# Generic userspace virtual network & TUN daemon (tools/net).
net_daemon = build / 'svbox-net'
subprocess.run(['clang', '-O2', '-Wall', '-Wextra',
                '-I', str(repo / 'src/payload/include'),
                str(repo / 'tools/net/svbox_net.c'),
                str(repo / 'tools/net/tcp_stack.c'),
                '-o', str(net_daemon)], check=True)
manifest['net_daemon_sha256'] = hashlib.sha256(net_daemon.read_bytes()).hexdigest()
(build / f'{name}.json').write_text(json.dumps(manifest, indent=2))
print('Built', binary, 'and', net_daemon)
