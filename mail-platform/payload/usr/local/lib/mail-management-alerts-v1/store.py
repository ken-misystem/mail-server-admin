"""POSIX service-user-owned JSON state with one nonblocking advisory lock.

No directory provisioning, secrets, network, database or test CLI. The caller
selects the fixed deployed directory only after reviewed activation.
"""
import hashlib
import json
import os
import stat
import uuid
import re

LIMIT = 8*1024*1024


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def identity(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def directory(path):
    need(type(path) is str and path.startswith('/') and '\x00' not in path and all(p not in ('', '.', '..') for p in path.split('/')[1:]), 'store_absolute_path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.split('/')[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            s = os.fstat(fd)
            need(s.st_uid in (0, os.geteuid()) and not s.st_mode & 0o022, 'store_parent_permissions')
        s = os.fstat(fd)
        need(s.st_uid == os.geteuid() and s.st_gid == os.getegid() and stat.S_IMODE(s.st_mode) == 0o700, 'store_directory_permissions')
        result, fd = fd, None
        return result
    finally:
        if fd is not None:
            os.close(fd)


class Store:
    def __init__(self, path, validator):
        self.path, self.validator = path, validator
        self.fd = self.lock = None
        self.previous = None
        self.loaded = False

    def __enter__(self):
        import fcntl
        need(os.geteuid() != 0, 'store_nonroot_required')
        try:
            self.fd = directory(self.path)
            self.lock = os.open('worker.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=self.fd)
            self._guard(os.fstat(self.lock))
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        for fd in (self.lock, self.fd):
            if fd is not None:
                os.close(fd)
        self.lock = self.fd = None

    @staticmethod
    def _guard(s):
        need(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and s.st_gid == os.getegid() and
             s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600 and s.st_size <= LIMIT, 'store_file_permissions')

    def _read(self):
        try:
            fd = os.open('state.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self.fd)
        except FileNotFoundError:
            return None, None
        try:
            before = os.fstat(fd)
            self._guard(before)
            raw = os.pread(fd, before.st_size+1, 0)
            after = os.stat('state.json', dir_fd=self.fd, follow_symlinks=False)
            need(identity(before) == identity(os.fstat(fd)) == identity(after) and len(raw) == before.st_size, 'store_read_drift')
            return raw, identity(after)
        finally:
            os.close(fd)

    def load(self):
        self._assert_lock()
        raw, self.previous = self._read()
        self.loaded = True
        if raw is None:
            return None
        def pairs(items):
            out = {}
            for key, value in items:
                need(key not in out, 'state_duplicate_key')
                out[key] = value
            return out
        state = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: need(False, 'state_nonfinite'))
        return self.validator(state)

    def save(self, state):
        need(self.loaded and self.fd is not None and self.lock is not None, 'state_lock_required')
        self._assert_lock()
        self.validator(state)
        raw = (json.dumps(state, ensure_ascii=True, separators=(',', ':'), allow_nan=False)+'\n').encode('ascii')
        need(0 < len(raw) <= LIMIT, 'state_size_bound')
        # Refuse concurrent/unknown changes; do not overwrite an unexpected inode.
        _, current = self._read()
        need(current == self.previous, 'state_changed_outside_lock')
        name = '.state-'+uuid.uuid4().hex+'.tmp'
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        try:
            self._guard(os.fstat(fd))
            view = memoryview(raw)
            while view:
                size = os.write(fd, view)
                need(size > 0, 'state_short_write')
                view = view[size:]
            os.fsync(fd)
        finally:
            os.close(fd)
        _, current = self._read()
        need(current == self.previous, 'state_changed_before_replace')
        os.rename(name, 'state.json', src_dir_fd=self.fd, dst_dir_fd=self.fd)
        os.fsync(self.fd)
        check, updated = self._read()
        need(check == raw, 'state_readback')
        self.previous = updated
        return hashlib.sha256(raw).hexdigest()

    def _assert_lock(self):
        need(self.fd is not None and self.lock is not None, 'state_lock_required')
        current = os.stat('worker.lock', dir_fd=self.fd, follow_symlinks=False)
        held = os.fstat(self.lock)
        self._guard(current)
        need(identity(current) == identity(held), 'state_lock_replaced')


class Archive:
    """Completed events only; immutable files, no automatic deletion or overwrite."""
    def __init__(self, path):
        self.path = path

    def commit(self, event):
        need(type(event) is dict and type(event.get('id')) is str and re.fullmatch('[a-f0-9]{64}', event['id']), 'archive_event_id')
        need(set(event['deliveries']) == {'email', 'discord'} and all(d['state'] == 'accepted' for d in event['deliveries'].values()), 'archive_incomplete_event')
        raw = (json.dumps(event, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)+'\n').encode()
        need(0 < len(raw) <= 262144, 'archive_event_bound')
        fd = directory(self.path)
        try:
            name = event['id']+'.json'
            def read_existing():
                try:
                    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                except FileNotFoundError:
                    return None
                try:
                    start = os.fstat(child)
                    Store._guard(start)
                    need(start.st_size <= 262144, 'archive_file_bound')
                    value = os.pread(child, start.st_size+1, 0)
                    need(len(value) == start.st_size and identity(start) == identity(os.fstat(child)) ==
                         identity(os.stat(name, dir_fd=fd, follow_symlinks=False)), 'archive_read_drift')
                    return value
                finally:
                    os.close(child)
            existing = read_existing()
            if existing is not None:
                need(existing == raw, 'archive_identity_conflict')
                return hashlib.sha256(raw).hexdigest()
            count = total = 0
            with os.scandir(fd) as entries:
                for entry in entries:
                    count += 1
                    need(count < 4096 and re.fullmatch(r'(?:[a-f0-9]{64}\.json|\.archive-[a-f0-9]{32}\.tmp)', entry.name), 'archive_directory_bound')
                    info = entry.stat(follow_symlinks=False)
                    Store._guard(info)
                    need(info.st_size <= 262144, 'archive_member_bound')
                    total += info.st_size
                    need(total+len(raw) <= 64*1024*1024, 'archive_capacity_bound')
            temp = '.archive-'+uuid.uuid4().hex+'.tmp'
            child = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                Store._guard(os.fstat(child))
                view = memoryview(raw)
                while view:
                    written = os.write(child, view)
                    need(written > 0, 'archive_short_write')
                    view = view[written:]
                os.fsync(child)
            finally:
                os.close(child)
            need(read_existing() is None, 'archive_changed_before_replace')
            os.rename(temp, name, src_dir_fd=fd, dst_dir_fd=fd)
            os.fsync(fd)
            need(read_existing() == raw, 'archive_readback')
            return hashlib.sha256(raw).hexdigest()
        finally:
            os.close(fd)
