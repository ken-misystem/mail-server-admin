"""Manage only the existing alert transport switches, keeping recipients and history intact."""
import json
import os
from pathlib import Path
import stat
import tempfile

from release import canonical, require, sha

DIRECTORY = Path('/etc/mail-management-alerts-v1')
CHANNELS = {'email', 'discord'}


def identity(meta):
    return (meta.st_dev, meta.st_ino, meta.st_mode, meta.st_uid, meta.st_gid,
            meta.st_nlink, meta.st_size, meta.st_mtime_ns, meta.st_ctime_ns)


def read(path, mode):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(fd)
        require(stat.S_ISREG(meta.st_mode) and stat.S_IMODE(meta.st_mode) == mode
                and meta.st_uid == 0 and meta.st_nlink == 1 and 0 < meta.st_size <= 16384,
                'alert_file_attributes')
        raw = stream.read(16385)
        require(len(raw) == meta.st_size and identity(meta) == identity(os.fstat(fd))
                == identity(path.lstat()), 'alert_file_changed')
        return json.loads(raw), sha(raw), meta


def channels(value):
    return type(value) is dict and set(value) == CHANNELS and all(type(v) is bool for v in value.values())


def load(directory):
    parent = directory.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and not parent.st_mode & 0o022,
            'alert_directory')
    runtime, digest, meta = read(directory/'runtime.json', 0o640)
    require(type(runtime) is dict and set(runtime) == {'version','enabled','channels','smtp','public_group'}
            and type(runtime['version']) is int and runtime['version'] == 1
            and type(runtime['enabled']) is bool and channels(runtime['channels'])
            and (runtime['enabled'] or not any(runtime['channels'].values()))
            and type(runtime['public_group']) is int and runtime['public_group'] == meta.st_gid
            and meta.st_gid > 0, 'alert_runtime')
    enabled = runtime['enabled'] and any(runtime['channels'].values())
    configured = runtime['channels']
    if not enabled:
        try:
            saved, _, info = read(directory/'delivery-resume.json', 0o600)
        except FileNotFoundError:
            pass
        else:
            require(info.st_gid == 0 and type(saved) is dict
                    and set(saved) == {'device','inode','sha256','channels'}
                    and channels(saved['channels']), 'alert_resume_record')
            if (saved['device'],saved['inode'],saved['sha256']) == (meta.st_dev,meta.st_ino,digest):
                configured = saved['channels']
    revision = sha(canonical([digest, *identity(meta)]))
    return runtime, meta, {'enabled':enabled,'channels':configured,'configurable':any(configured.values()),
                           'revision':revision}


def store(path, value, mode, old=None, prepare=None):
    raw = canonical(value)
    fd, name = tempfile.mkstemp(prefix='.alert-settings-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            if old is not None:
                os.fchown(fd, -1, old.st_gid)
                for attr in os.listxattr(path, follow_symlinks=False):
                    os.setxattr(fd, attr, os.getxattr(path, attr, follow_symlinks=False))
            os.fchmod(fd, mode)
            os.fsync(fd)
            staged = os.fstat(fd)
        if prepare is not None:
            prepare(staged, sha(raw))
        if old is not None:
            require(identity(path.lstat()) == identity(old), 'alert_runtime_changed')
        os.replace(name, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        Path(name).unlink(missing_ok=True)


def status(directory=DIRECTORY):
    return load(directory)[2]


def change(enabled, revision, directory=DIRECTORY):
    runtime, meta, status = load(directory)
    require(type(enabled) is bool and status['revision'] == revision and status['configurable'],
            'alert_delivery_revision_or_channels')
    require(status['enabled'] != enabled, 'alert_delivery_no_change')

    def remember(staged, digest):
        # Bind the stored channels to the staged stopped file. A manual replacement
        # or an interrupted write cannot authorize a later unexpected resume.
        store(directory/'delivery-resume.json', {'device':staged.st_dev,'inode':staged.st_ino,
              'sha256':digest,'channels':status['channels']}, 0o600)

    updated = dict(runtime, enabled=enabled,
                   channels=status['channels'] if enabled else dict.fromkeys(CHANNELS,False))
    store(directory/'runtime.json', updated, 0o640, meta, None if enabled else remember)
    require(load(directory)[2]['enabled'] == enabled, 'alert_delivery_readback')
