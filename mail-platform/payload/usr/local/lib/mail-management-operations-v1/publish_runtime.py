"""Future collector entry: root publishes aggregates, web caller only reads them."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import uuid

DIRECTORY = Path('/var/lib/mail-management-operations-v1')
SOURCE_SHA = '353ea8a1c444da78fb25580621feaf027ba3d57289a1dae23d1419d11098f219'
GROUP = 113  # Existing verified mailadmin group; no identity/grant creation.


def need(ok):
    if not ok:
        raise ValueError('collector_guard')


def identity(s):
    return None if s is None else (s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)


def runtime():
    source = Path(__file__).with_name('read_runtime.py')
    raw = source.read_bytes()
    need(hashlib.sha256(raw).hexdigest() == SOURCE_SHA)
    scope = dict(__name__='bound_runtime_library', __file__=str(source), SOURCE_SHA=SOURCE_SHA)
    exec(compile(raw, 'bound-runtime-collector', 'exec'), scope)
    return scope


def write_snapshot(directory_fd, result):
    need(result['source_sha256'] == SOURCE_SHA and result['operation'] == 'management-operations-read-v1')
    raw = (json.dumps(result, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')
    need(0 < len(raw) <= 65536)
    try:
        old = os.stat('snapshot.json', dir_fd=directory_fd, follow_symlinks=False)
        need(stat.S_ISREG(old.st_mode) and old.st_uid == 0 and old.st_gid == GROUP
             and stat.S_IMODE(old.st_mode) == 0o640 and old.st_nlink == 1)
    except FileNotFoundError:
        old = None
    name = '.snapshot-' + uuid.uuid4().hex + '.tmp'
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
    try:
        os.fchown(fd, 0, GROUP)
        with os.fdopen(fd, 'wb', closefd=False) as output:
            output.write(raw); output.flush(); os.fsync(fd)
        os.fchmod(fd, 0o640)
    finally:
        os.close(fd)
    try:
        current = os.stat('snapshot.json', dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        current = None
    need(identity(current) == identity(old))
    os.rename(name, 'snapshot.json', src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
    os.fsync(directory_fd)


def run():
    need(os.geteuid() == 0 and sys.argv[1:] == ['--collect'])
    # No directory creation here. A separately approved activation must provision it.
    parent = os.open('/var/lib', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    directory = lock = None
    try:
        parent_info = os.fstat(parent)
        need(parent_info.st_uid == 0 and not parent_info.st_mode & 0o022)
        directory = os.open(DIRECTORY.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        info = os.fstat(directory)
        need(info.st_uid == 0 and info.st_gid == GROUP and stat.S_IMODE(info.st_mode) == 0o750)
        lock = os.open('collector.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
        info = os.fstat(lock)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = runtime()['collect']()
        write_snapshot(directory, result)
        return 0 if result['status'] == 'ok' else 1
    finally:
        for fd in (lock, directory, parent):
            if fd is not None: os.close(fd)


if __name__ == '__main__':
    try:
        code = run()
        print('OPERATIONS_COLLECTOR=' + json.dumps(dict(status='ok' if code == 0 else 'partial', snapshot_written=True)))
        raise SystemExit(code)
    except Exception as error:
        kind = type(error).__name__
        print('OPERATIONS_COLLECTOR=' + json.dumps(dict(status='fail', snapshot_written=False,
              error_class=kind if kind in ('ValueError','OSError','FileNotFoundError','PermissionError','BlockingIOError') else 'other',
              errno=error.errno if isinstance(error,OSError) else None)))
        raise SystemExit(2)
