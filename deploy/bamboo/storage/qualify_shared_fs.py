#!/usr/bin/env python3
"""Qualify a fresh synthetic GlusterFS namespace without opening a live store."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import uuid

REMOTE = r'''
import errno, fcntl, hashlib, json, os, pathlib, select, sys
mode, marker = sys.argv[1:]
import uuid
assert str(uuid.UUID(marker)) == marker
base = pathlib.Path('/data/atlassian/application-data/bamboo/shared')
root = base / ('omp-bamboo-jms-qualification-' + marker)
os.setgroups([])
os.setgid(1400)
os.setuid(1400)
os.umask(0o077)
payload = ('synthetic-shared-fs:' + marker).encode()
if mode == 'hold':
    root.mkdir(mode=0o700)
    (root / 'OWNED_QUALIFICATION').write_text(marker, encoding='ascii')
assert root.is_dir() and not root.is_symlink()
assert (root / 'OWNED_QUALIFICATION').read_text(encoding='ascii') == marker

def sync_write(name, data):
    part = root / (name + '.part')
    with part.open('xb') as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    os.replace(part, root / name)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

with (root / 'cross-node.lock').open('a+b') as lock:
    inode = os.fstat(lock.fileno()).st_ino
    if mode == 'hold':
        fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        sync_write('visibility.payload', payload)
        print(json.dumps({'phase': mode, 'inode': inode, 'held': True}), flush=True)
        ready, _, _ = select.select([sys.stdin], [], [], 90)
        if not ready or sys.stdin.readline().strip() != 'RELEASE':
            raise RuntimeError('HOLDER_RELEASE_NOT_RECEIVED')
        fcntl.lockf(lock, fcntl.LOCK_UN)
        print(json.dumps({'phase': 'released', 'released': True}), flush=True)
    elif mode == 'contend':
        assert (root / 'visibility.payload').read_bytes() == payload
        try:
            fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno not in (errno.EAGAIN, errno.EACCES):
                raise
        else:
            fcntl.lockf(lock, fcntl.LOCK_UN)
            raise RuntimeError('CROSS_NODE_LOCK_NOT_EXCLUSIVE')
        print(json.dumps({'phase': mode, 'inode': inode,
                          'exclusive_conflict_observed': True,
                          'fsync_rename_payload_visible': True}), flush=True)
    elif mode in ('handoff', 'reacquire'):
        assert (root / 'visibility.payload').read_bytes() == payload
        fcntl.lockf(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if mode == 'handoff':
            sync_write('handoff.payload', payload)
        else:
            assert (root / 'handoff.payload').read_bytes() == payload
        fcntl.lockf(lock, fcntl.LOCK_UN)
        print(json.dumps({'phase': mode, 'inode': inode, 'acquired_after_release': True,
                          'handoff_visible': True}), flush=True)
    else:
        raise RuntimeError('UNKNOWN_PHASE')
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--namespace', required=True, type=uuid.UUID)
    parser.add_argument('--ssh-config', default='C:/Users/25321/.ssh/bamboo-log-maintenance.conf')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    marker = str(args.namespace)
    if args.output.exists():
        parser.error('refusing to overwrite qualification evidence')
    env = {k: v for k, v in os.environ.items() if k.upper() in
           {'PATH', 'SYSTEMROOT', 'WINDIR', 'PROGRAMDATA', 'USERPROFILE'}}

    def command(node, phase):
        remote = 'python3 -u -c ' + shlex.quote(REMOTE) + ' ' + phase + ' ' + marker
        return ['ssh', '-F', args.ssh_config, '-o', 'BatchMode=yes',
                '-o', 'ConnectTimeout=10', '-o', 'StrictHostKeyChecking=yes',
                'omp-bamboo-log' + str(node), remote]

    def run(node, phase):
        result = subprocess.run(command(node, phase), capture_output=True, text=True,
                                env=env, timeout=30)
        if result.returncode:
            raise RuntimeError('REMOTE_PHASE_FAILED:' + str(node) + ':' + phase + ':' + result.stderr)
        return json.loads(result.stdout)

    report = {'namespace': marker,
              'root': '/data/atlassian/application-data/bamboo/shared/omp-bamboo-jms-qualification-' + marker,
              'live_store_opened': False, 'observations': {}, 'passed': False}
    holder = None
    released = False
    try:
        holder = subprocess.Popen(command(60, 'hold'), stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, env=env)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            first = pool.submit(holder.stdout.readline)
            try:
                ready = first.result(timeout=30)
            except concurrent.futures.TimeoutError:
                holder.kill()
                report['remote_holder_release_unknown'] = True
                raise RuntimeError('HOLDER_READINESS_TIMEOUT')
        observation = json.loads(ready)
        if not observation.get('held'):
            raise RuntimeError('HOLDER_NOT_READY')
        report['observations']['60_hold'] = observation
        for node in (61, 63):
            report['observations'][str(node) + '_contend'] = run(node, 'contend')
        tail, errors = holder.communicate(input='RELEASE\n', timeout=30)
        released = True
        if holder.returncode:
            raise RuntimeError('HOLDER_RELEASE_FAILED:' + errors)
        if not json.loads(tail).get('released'):
            raise RuntimeError('HOLDER_RELEASE_UNVERIFIED')
        report['observations']['61_handoff'] = run(61, 'handoff')
        report['observations']['63_reacquire'] = run(63, 'reacquire')
        inodes = {o['inode'] for o in report['observations'].values()}
        if len(inodes) != 1:
            raise RuntimeError('SHARED_LOCK_INODE_MISMATCH')
        report['passed'] = True
    except Exception as exc:
        report['error'] = str(exc)
    finally:
        if holder is not None and holder.poll() is None and not released:
            try:
                holder.communicate(input='RELEASE\n', timeout=15)
            except subprocess.TimeoutExpired:
                holder.kill()
                holder.communicate(timeout=15)
                report['remote_holder_release_unknown'] = True
        with args.output.open('x', encoding='utf-8', newline='\n') as out:
            json.dump(report, out, indent=2)
            out.write('\n')
    print(json.dumps({'passed': report['passed'], 'namespace': marker,
                      'observations': len(report['observations']), 'evidence': str(args.output),
                      'error': report.get('error')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
