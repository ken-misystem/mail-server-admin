"""Durable fresh-host operations with private command output and CAS restoration."""
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import time
import uuid


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def durable_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(json.dumps(value, sort_keys=True, indent=2).encode() + b'\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def regular(path, limit=268435456):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
            raise ValueError('resource_attributes')
        chunks = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(fd, min(1048576, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b''.join(chunks)
        final = os.fstat(fd)
        named = path.lstat()
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
                                  value.st_ctime_ns, value.st_uid, value.st_gid, value.st_mode)
        if len(raw) != info.st_size or identity(info) != identity(final) or identity(info) != identity(named):
            raise ValueError('resource_changed_during_read')
        return raw, {'sha256': digest(raw), 'uid': info.st_uid, 'gid': info.st_gid,
                     'mode': stat.S_IMODE(info.st_mode)}
    finally:
        os.close(fd)


class CommandFailure(RuntimeError):
    def __init__(self, record):
        super().__init__('command_failed')
        self.record = record


class Commands:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.sequence = 0
        self.records = []

    def run(self, label, argv, data=None, timeout=300):
        if not label.replace('_', '').isalnum() or not all(type(value) is str for value in argv):
            raise ValueError('command_shape')
        self.sequence += 1
        prefix = str(self.sequence).zfill(4) + '-' + label
        started = time.time()
        out = self.directory / (prefix + '.stdout')
        err = self.directory / (prefix + '.stderr')
        result = None
        timed_out = False
        spawn_error = None
        with out.open('xb') as stdout, err.open('xb') as stderr:
            try:
                process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                                           start_new_session=True,
                                           env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
                                                'DEBIAN_FRONTEND': 'noninteractive', 'UCF_FORCE_CONFFOLD': '1'})
            except OSError as error:
                spawn_error = {'class': type(error).__name__, 'errno': error.errno}
            else:
                try:
                    process.communicate(data, timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                    process.communicate()
                result = process.returncode
            stdout.flush()
            stderr.flush()
            os.fsync(stdout.fileno())
            os.fsync(stderr.fileno())
        record = {'label': label, 'argv': argv, 'started': started, 'finished': time.time(),
                  'exit': result, 'timed_out': timed_out, 'spawn_error': spawn_error,
                  'stdout': out.name, 'stderr': err.name}
        self.records.append(record)
        durable_json(self.directory / (prefix + '.json'), record)
        if spawn_error or result != 0 or timed_out:
            raise CommandFailure(record)
        if out.stat().st_size > 16777216 or err.stat().st_size > 16777216:
            raise ValueError('command_output_bound')
        return out.read_bytes()


class Files:
    def __init__(self, root, state):
        self.root = Path(root).resolve()
        self.state = Path(state)
        self.entries = []
        self.receipt = self.state / 'file-journal.json'

    def save_entry(self, entry):
        durable_json(self.state / ('file-entry-' + str(entry['sequence']).zfill(6) + '.json'), entry)

    def target(self, name):
        relative = Path(name.lstrip('/'))
        if not name.startswith('/') or '..' in relative.parts or '\\' in name:
            raise ValueError('target_path')
        path = self.root / relative
        for parent in reversed(path.parents):
            if parent == self.root or self.root in parent.parents:
                if parent.is_symlink():
                    raise ValueError('target_parent_link')
                if parent.exists() and parent.stat().st_uid not in (0, os.geteuid()):
                    raise ValueError('target_parent_owner')
        return path

    def write(self, name, raw, mode=0o644, uid=0, gid=0, preserve=False):
        path = self.target(name)
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        before = None
        backup = None
        if os.path.lexists(path):
            original, before = regular(path)
            backup = 'original-' + str(len(self.entries)).zfill(5)
            fd = os.open(self.state / backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(original)
                stream.flush()
                os.fsync(stream.fileno())
        entry = {'path': name, 'before': before, 'backup': backup, 'preserve': preserve,
                 'sequence': len(self.entries),
                 'after': {'sha256': digest(raw), 'mode': mode, 'uid': uid, 'gid': gid},
                 'phase': 'write_started'}
        self.entries.append(entry)
        self.save_entry(entry)
        temporary = path.with_name(path.name + '.mail-platform-' + uuid.uuid4().hex)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), uid, gid)
            stream.flush()
            os.fsync(stream.fileno())
        # Refuse a competing writer between backup and publication.
        if before is None:
            if os.path.lexists(path):
                raise ValueError('new_resource_appeared')
            os.link(temporary, path, follow_symlinks=False)
            temporary.unlink()
        else:
            if regular(path)[1] != before:
                raise ValueError('resource_CAS_conflict')
            os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        if regular(path)[1] != entry['after']:
            raise ValueError('resource_readback')
        entry['phase'] = 'written'
        self.save_entry(entry)

    def restore(self, paths=None):
        held = []
        # Restoring writes must not append to the journal being traversed.
        for entry in reversed(list(self.entries)):
            if paths is not None and entry['path'] not in paths:
                continue
            if entry['preserve'] or entry['phase'] == 'restored':
                continue
            if entry['phase'] != 'written':
                held.append(entry['path'])
                continue
            path = self.target(entry['path'])
            try:
                if regular(path)[1] != entry['after']:
                    held.append(entry['path'])
                    continue
                if entry['before'] is None:
                    # Keep newly created bytes under an inactive name.
                    retained = path.with_name(path.name + '.mail-platform-retained-' + uuid.uuid4().hex)
                    os.rename(path, retained)
                else:
                    raw = (self.state / entry['backup']).read_bytes()
                    if digest(raw) != entry['before']['sha256']:
                        raise ValueError('original_backup_drift')
                    temporary = path.with_name(path.name + '.restore-' + uuid.uuid4().hex)
                    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(raw)
                        os.fchmod(stream.fileno(), entry['before']['mode'])
                        os.fchown(stream.fileno(), entry['before']['uid'], entry['before']['gid'])
                        stream.flush()
                        os.fsync(stream.fileno())
                    if regular(path)[1] != entry['after']:
                        raise ValueError('restore_CAS_conflict')
                    os.replace(temporary, path)
                directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
                entry['phase'] = 'restored'
                self.save_entry(entry)
            except (OSError, ValueError):
                held.append(entry['path'])
        durable_json(self.receipt, self.entries)
        return {'status': 'held' if held else 'restored', 'held_paths': held,
                'data_and_credentials_preserved': True}


class Transaction:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)
        self.value = {'phase': 'created', 'steps': [], 'started': time.time()}
        self.save()

    def save(self):
        durable_json(self.directory / 'transaction.json', self.value)

    def step(self, name, operation):
        self.value['phase'] = name + '_started'
        self.save()
        result = operation()
        self.value['steps'].append({'name': name, 'completed': time.time()})
        self.value['phase'] = name + '_complete'
        self.save()
        return result

    def finish(self, phase, **metadata):
        self.value.update(phase=phase, finished=time.time(), **metadata)
        self.save()
        if json.loads((self.directory / 'transaction.json').read_bytes()) != self.value:
            raise ValueError('transaction_readback')
