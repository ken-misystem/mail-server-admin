"""Trusted certificate inputs and locks shared by setup, renewal and CA changes."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import stat

from host_transaction import regular, durable_json

STATE = Path('/var/lib/mail-platform-certificates')
CONFIG = Path('/etc/mail-platform/certificates.json')
LOCK = '/run/lock/mail-platform-certificates.lock'


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def trusted(path, *, private=False, limit=1048576):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts, 'certificate_input_path')
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'certificate_input_parent')
    raw, attributes = regular(path, limit)
    require(attributes['uid'] == 0 and not attributes['mode'] & (0o077 if private else 0o022),
            'certificate_input_permissions')
    return raw, attributes


def configuration():
    value = json.loads(trusted(CONFIG, private=True)[0])
    require(set(value)=={'format','profile','host','probe_address','trust_store'} and value.get('format') == 1 and re.fullmatch(r'(?:[a-z0-9][a-z0-9-]*\.)+[a-z][a-z0-9-]*', value['host']),
            'certificate_configuration')
    require(value['profile'] in ('production', 'private-validation'), 'certificate_profile')
    if value['profile'] == 'private-validation':
        require(Path('/etc/mail-platform-validation-machine').read_text().strip() == 'mail-platform-lab-v1',
                'certificate_validation_fixture')
    else:
        require(value['trust_store'] == '/etc/ssl/certs/ca-certificates.crt', 'certificate_production_trust')
    return value


def evidence_path(path):
    path=Path(path)
    require(path.is_absolute() and '..' not in path.parts and not os.path.lexists(path),'certificate_new_evidence_required')
    for parent in path.parents:
        info=parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode & 0o022,'certificate_evidence_parent_trust')
    return path


def require_settled():
    for kind in ('tls','ca','migration'):
        path=STATE/(kind+'-pending.json')
        if path.exists():
            require(json.loads(trusted(path,private=True)[0])['phase'] in ('complete','restored'),kind.upper()+'_pending_requires_root_recovery')


@contextmanager
def certificate_lock(*, update=True):
    import fcntl
    paths = [LOCK]
    if update and Path('/var/lib/mail-platform-update').exists():
        paths.insert(0, '/var/lib/mail-platform-update/update.lock')
    descriptors = []
    try:
        for path in paths:
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            descriptors.append(fd)
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                    and not info.st_mode & 0o077, 'certificate_lock_permissions')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def private_directory(path):
    path = Path(path)
    require(not path.is_symlink(), 'certificate_state_directory_link')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.stat()
    require(info.st_uid == 0 and not info.st_mode & 0o077, 'certificate_state_directory_permissions')
    return path


def new_file(path, raw, mode=0o600, uid=0, gid=0):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchown(stream.fileno(), uid, gid)
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def failure(directory, error, phase, recovery):
    import traceback
    durable_json(Path(directory)/'failure.json', {
        'class': type(error).__name__, 'reason': str(error) if type(error) is ValueError else 'operation_failed',
        'phase': phase, 'command': getattr(error, 'record', None), 'recovery': recovery,
        'diagnostic':getattr(error,'diagnostic',None),
        'errno':getattr(error,'errno',None),
        'frames':[{'file':Path(item.filename).name,'line':item.lineno,'function':item.name}
                  for item in traceback.extract_tb(error.__traceback__)],
        'private_state_retained': True})
