#!/usr/bin/env python3
"""One-attempt cold KahaDB copy/commit; never starts a service or restores data.

Run only on backend60 inside a separately coordinated outage. Peer attestations
are collected by the maintenance controller immediately before each action;
they are not distributed fencing and require the exclusive operator window.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import uuid

HOME = Path('/data/atlassian/application-data/bamboo')
SOURCE = HOME / 'local-jms-store'
SHARED = HOME / 'shared'
LIVE = SHARED / 'jms-store'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def manifest(root):
    """Reject aliases/special files; retain metadata and hashes, never payloads."""
    require(root.is_dir() and not root.is_symlink(), 'store root is not a real directory')
    result = []
    for path in [root] + sorted(root.rglob('*')):
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'nonregular store descendant')
        require(not stat.S_ISREG(info.st_mode) or info.st_nlink == 1, 'hardlinked store file')
        item = {'path': str(path.relative_to(root)), 'mode': stat.S_IMODE(info.st_mode),
                'uid': info.st_uid, 'gid': info.st_gid, 'mtime_ns': info.st_mtime_ns,
                'kind': 'directory' if stat.S_ISDIR(info.st_mode) else 'file',
                'xattrs': {key: hashlib.sha256(os.getxattr(path, key)).hexdigest()
                           for key in os.listxattr(path) if not key.startswith('trusted.glusterfs') and key != 'trusted.gfid'}}
        if stat.S_ISREG(info.st_mode):
            item.update(size=info.st_size, sha256=digest(path))
            after = path.stat()
            require((info.st_ino, info.st_size, info.st_mtime_ns) ==
                    (after.st_ino, after.st_size, after.st_mtime_ns), 'store changed during hashing')
        result.append(item)
    return result


def save(path, value):
    temporary = path.with_name(path.name + '.pending')
    with temporary.open('x', encoding='utf-8') as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    sync_directory(path.parent)


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def cold_gate(proof, attempt):
    require(proof.get('attempt') == attempt, 'wrong stopped-attestation attempt')
    nodes = proof.get('nodes', {})
    require(set(nodes) == {'60', '61', '63'}, 'missing stopped peer')
    for node in nodes.values():
        require(0 <= time.time() - node['captured_at'] <= 60, 'stale stopped peer')
        require(node['unit'] == 'bamboo.service' and node['active'] == 'inactive'
                and node['main_pid'] == 0 and node['cgroup_pids'] == []
                and node['listeners'] == [] and node['start_fence_verified'] is True,
                'peer is not fenced cold')
    local = dict(line.split('=', 1) for line in subprocess.check_output(
        ['systemctl', 'show', 'bamboo.service', '-p', 'ActiveState', '-p', 'MainPID',
         '-p', 'ConditionResult', '-p', 'DropInPaths'], text=True).splitlines())
    require(local['ActiveState'] == 'inactive' and local['MainPID'] == '0'
            and local['ConditionResult'] == 'no', 'local service not fenced stopped')
    hold = Path('/run') / ('omp-bamboo-jms-hold-' + attempt)
    condition = Path('/run/systemd/system/bamboo.service.d') / ('00-omp-jms-fence-' + attempt + '.conf')
    require(hold.is_dir() and not hold.is_symlink() and hold.stat().st_uid == 0
            and stat.S_IMODE(hold.stat().st_mode) == 0o700, 'local start hold absent')
    require(not condition.is_symlink() and condition.stat().st_uid == 0
            and condition.read_text() == '[Unit]\nConditionPathExists=!' + str(hold) + '\n'
            and str(condition) in local['DropInPaths'].split(), 'local start condition absent')
    require(LIVE.is_symlink() and os.readlink(LIVE) == str(SOURCE), 'live link changed')


def load_mac_qualification(attempt, proof):
    private = Path('/root') / ('omp-bamboo-jms-migration-' + attempt)
    receipt = private / 'native-mac-proof.json'
    require(not private.is_symlink() and private.stat().st_uid == 0
            and stat.S_IMODE(private.stat().st_mode) == 0o700, 'unsafe qualification directory')
    require(not receipt.is_symlink() and receipt.stat().st_uid == 0
            and stat.S_IMODE(receipt.stat().st_mode) == 0o600, 'unsafe qualification receipt')
    qualified = json.loads(receipt.read_text())
    require(qualified['schema'] == 1 and qualified['status'] ==
            'PASSED_EXACT_NATIVE_DOMAIN_WITH_EXISTING_ENFORCEMENT_MODES', 'unqualified MAC profile')
    require(str(uuid.UUID(qualified['namespace'])) != attempt, 'qualification and migration must differ')
    label_sha = '641d6c2d0bb036d503858595da9988eb8563782bb1574407cf430432534446b6'
    domain = 'system_u:system_r:unconfined_service_t:s0'
    require(set(qualified['runs']) == {'60', '61', '63'}, 'missing MAC-qualified peer')
    for name, run in qualified['runs'].items():
        observed = run['observed_java']
        require(run['exit'] == 0 and observed['context'] == domain, 'native MAC-domain mismatch')
        require(observed['identity']['Uid'].split() == ['1400'] * 4
                and observed['identity']['Gid'].split() == ['1400'] * 4
                and observed['identity']['Groups'].split() == ['1400'], 'native identity mismatch')
        require(proof['nodes'][name]['enforcement'] == run['enforcement'], 'enforcement mode drift')
        labels = qualified['mounted_labels'][name]
        require(labels['labels'] == ['system_u:object_r:fusefs_t:s0']
                and labels['label_sha256'] == [label_sha], 'unqualified mounted label')
    require(qualified['runs']['60']['enforcement'] == 'Enforcing', 'missing enforced access proof')
    require(subprocess.check_output(['getenforce'], text=True).strip() == 'Enforcing', 'local enforcement drift')
    require(hashlib.sha256(os.getxattr(SHARED, 'security.selinux')).hexdigest() == label_sha,
            'mounted SELinux label drift')
    return {'namespace': qualified['namespace'], 'receipt_sha256': digest(receipt), 'label_sha256': label_sha}


def shared_manifest_expected(original, profile):
    # Keep originallabels in the protected source/backup manifest. Only this
    # independently qualified mount-specific label differs in the shared copy.
    expected = json.loads(json.dumps(original))
    for entry in expected:
        require('security.selinux' in entry['xattrs'], 'source SELinux label absent')
        entry['xattrs']['security.selinux'] = profile['label_sha256']
    return expected



def copy_store(destination):
    require(not destination.exists() and not destination.is_symlink(), 'copy destination already exists')
    subprocess.run(['cp', '-a', '--reflink=auto', '--', str(SOURCE), str(destination)], check=True)
    for path in destination.rglob('*'):
        if path.is_file():
            with path.open('rb') as stream:
                os.fsync(stream.fileno())
    for path in sorted((p for p in destination.rglob('*') if p.is_dir()), reverse=True):
        sync_directory(path)
    sync_directory(destination)
    sync_directory(destination.parent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('stage', 'commit'))
    parser.add_argument('attempt', type=lambda value: str(uuid.UUID(value)))
    args = parser.parse_args()
    require(os.geteuid() == 0, 'root required')
    require(os.uname().nodename.split('.')[0] == 'git-app-1', 'only audited backend60 permitted')
    os.umask(0o077)
    proof = json.load(sys.stdin)
    cold_gate(proof, args.attempt)
    profile = load_mac_qualification(args.attempt, proof)
    backup = Path('/var/backups') / ('bamboo-jms-migration-' + args.attempt)
    stage = SHARED / ('.omp-jms-store-stage-' + args.attempt)
    old_link = SHARED / ('.omp-jms-store-original-link-' + args.attempt)
    with open('/run/lock/omp-bamboo-jms-migration.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.action == 'stage':
            backup.mkdir(mode=0o700)
            state = {'attempt': args.attempt, 'phase': 'RESERVED', 'created_at': time.time()}
            state['mac_profile'] = profile
            save(backup / 'attempt.json', state)
            require(not stage.exists() and not stage.is_symlink(), 'shared stage already exists')
            require(not old_link.exists() and not old_link.is_symlink(), 'saved link already exists')
            original = manifest(SOURCE)
            require(any(item['kind'] == 'file' for item in original), 'empty source forbidden')
            save(backup / 'manifest.json', original)
            expected_shared = shared_manifest_expected(original, profile)
            save(backup / 'shared-manifest.json', expected_shared)
            subprocess.run(['cp', '-a', '--no-dereference', '--', str(LIVE), str(backup / 'original-link')], check=True)
            copy_store(backup / 'store')
            require(manifest(backup / 'store') == original, 'backup manifest mismatch')
            copy_store(stage)
            require(manifest(stage) == expected_shared, 'shared stage manifest mismatch')
            require(manifest(SOURCE) == original, 'source changed after copying')
            state['phase'] = 'STAGED'
            save(backup / 'attempt.json', state)
        else:
            require(backup.is_dir() and not backup.is_symlink(), 'missing protected backup')
            require(backup.stat().st_uid == 0 and stat.S_IMODE(backup.stat().st_mode) == 0o700, 'unsafe backup permissions')
            state = json.loads((backup / 'attempt.json').read_text())
            require(state['attempt'] == args.attempt and state['phase'] == 'STAGED', 'commit phase not replayable')
            require(state['mac_profile'] == profile, 'qualification profile changed after staging')
            original = json.loads((backup / 'manifest.json').read_text())
            expected_shared = shared_manifest_expected(original, profile)
            require(json.loads((backup / 'shared-manifest.json').read_text()) == expected_shared,
                    'shared expectation drift')
            require(manifest(SOURCE) == original and manifest(stage) == expected_shared
                    and manifest(backup / 'store') == original, 'cold data drift')
            cold_gate(proof, args.attempt)
            require(not old_link.exists() and not old_link.is_symlink(), 'saved link already exists')
            state['phase'] = 'COMMITTING_NO_SERVICE_START_AUTHORITY'
            save(backup / 'attempt.json', state)
            os.rename(LIVE, old_link)
            sync_directory(SHARED)
            os.rename(stage, LIVE)
            sync_directory(SHARED)
            require(manifest(LIVE) == expected_shared, 'installed manifest mismatch')
            state['phase'] = 'INSTALLED_NO_SERVICE_STARTED'
            save(backup / 'attempt.json', state)
        print(json.dumps({'ok': True, 'attempt': args.attempt, 'phase': state['phase'],
                          'file_count': sum(item['kind'] == 'file' for item in original),
                          'bytes': sum(item.get('size', 0) for item in original),
                          'manifest_sha256': digest(backup / 'manifest.json')}))


if __name__ == '__main__':
    main()
