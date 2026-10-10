"""Trusted finite observations run before importing any reviewed target helper."""
import errno
import json
import os
from pathlib import Path
import resource
import socket
import sys


def require(condition, name):
    if not condition:
        raise RuntimeError('security preflight failed: ' + name)


def denied_write(path):
    try:
        with open(path, 'xb') as handle:
            handle.write(b'public control')
    except OSError as error:
        require(error.errno in (errno.EROFS, errno.EACCES), 'readonly-error')
    else:
        raise RuntimeError('security preflight failed: protected-write')


def main():
    allowed = {'PATH', 'HOME', 'TMPDIR', 'XDG_CACHE_HOME', 'PYTHONUTF8',
               'PYTHONIOENCODING', 'PYTHONDONTWRITEBYTECODE', 'LANG', 'LC_ALL',
               'REVAYAT_SECURITY_TIER'}
    require(set(os.environ) == allowed, 'exact-environment')
    require(os.environ['HOME'] == '/scratch/home', 'scratch-home')
    require(os.environ['TMPDIR'] == '/scratch/tmp', 'scratch-temp')
    require(os.getuid() != 0, 'nonroot')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text(encoding='utf-8').splitlines() if ':' in line)
    require(int(status['CapEff'].strip(), 16) == 0 and int(status['CapBnd'].strip(), 16) == 0, 'capabilities')
    require(status['NoNewPrivs'].strip() == '1', 'no-new-privileges')
    for target in ('/target/.security-write', '/usr/.security-write', '/.security-write',
                   '/dev/.security-write', '/dev/shm/.security-write', '/dev/mqueue/.security-write'):
        denied_write(target)
    require(Path('/target/tests/security/coverage.json').read_text(encoding='utf-8').startswith('{'),
            'public-target-readable')
    mounts = [line.split() for line in Path('/proc/self/mounts').read_text(encoding='utf-8').splitlines()]
    for target in ('/', '/target', '/dev/shm', '/dev/mqueue'):
        require(any(row[1] == target and 'ro' in row[3].split(',') for row in mounts), 'readonly-mount-' + target)
    # Isolated proc/dev endpoints are kernel runtime interfaces, not artifact storage.
    # Regular storage writes there remain refused for the unprivileged worker.
    root = Path('/scratch')
    root.joinpath('positive').write_bytes(b'allowed scratch')
    require(root.joinpath('positive').read_bytes() == b'allowed scratch', 'scratch-write')
    root.joinpath('positive').unlink()
    require(not Path('/host-only-canary').exists(), 'host-path-not-mounted')
    require(set(p.name for p in Path('/sys/class/net').iterdir()) == {'lo'}, 'network-interfaces')
    for family, address in ((socket.AF_INET, ('192.0.2.1', 9)), (socket.AF_INET6, ('2001:db8::1', 9, 0, 0))):
        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(0.1)
            try:
                client.connect(address)
            except OSError as error:
                require(error.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH), 'network-denial')
            else:
                raise RuntimeError('security preflight failed: network-connect')
    cgroup = Path('/sys/fs/cgroup')
    require(cgroup.joinpath('memory.max').read_text(encoding='utf-8').strip() == '1073741824', 'memory')
    require(cgroup.joinpath('pids.max').read_text(encoding='utf-8').strip() == '64', 'pids')
    quota, period = cgroup.joinpath('cpu.max').read_text(encoding='utf-8').split()
    require(quota != 'max' and int(quota) == 2 * int(period), 'cpu')
    require(resource.getrlimit(resource.RLIMIT_FSIZE) == (67108864, 67108864), 'file-size')
    require(resource.getrlimit(resource.RLIMIT_NOFILE) == (128, 128), 'file-descriptors')
    sizes = os.statvfs('/scratch')
    require(sizes.f_blocks * sizes.f_frsize == 134217728, 'aggregate-disk')
    # A sparse logical extension verifies the per-file limit without filling RAM/disk.
    import signal
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    oversized = root / 'size-control'
    try:
        with oversized.open('xb') as handle:
            try:
                handle.truncate(67108865)
            except OSError as error:
                require(error.errno == errno.EFBIG, 'file-size-enforced')
            else:
                raise RuntimeError('security preflight failed: file-size-not-enforced')
    finally:
        oversized.unlink(missing_ok=True)
    quota_files, refused = [], False
    try:
        for index in range(9):
            path = root / ('aggregate-control-' + str(index))
            quota_files.append(path)
            with path.open('xb') as handle:
                try:
                    os.posix_fallocate(handle.fileno(), 0, 16 * 1024 * 1024)
                except OSError as error:
                    require(error.errno == errno.ENOSPC, 'aggregate-denial-error')
                    refused = True
                    break
        require(refused, 'aggregate-disk-enforced')
    finally:
        for path in quota_files:
            path.unlink(missing_ok=True)
    print(json.dumps({'phase': 'preflight', 'status': 'passed', 'controls': sorted(allowed),
                      'scratch_bytes': 134217728, 'file_bytes': 67108864}))


if __name__ == '__main__':
    main()
    if sys.argv[1:] == ['--worker']:
        sys.stdout.flush()
        os.execv(sys.executable, [sys.executable, '-B', '/target/tests/security/linux_worker.py'])
    elif sys.argv[1:]:
        raise RuntimeError('unsupported trusted probe arguments')
