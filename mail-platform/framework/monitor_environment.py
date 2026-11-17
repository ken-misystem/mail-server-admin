"""Site-owned monitoring references. No hostname rewriting, writes, or shell calls."""
import json as _mon_json
import os as _mon_os
import re as _mon_re
import stat as _mon_stat

MONITOR_CONFIG = '/etc/mail-management-operations-v1/environment.json'


def monitor_need(value, reason):
    if not value:
        raise ValueError('monitor_environment_' + reason)


def monitor_validate(value):
    monitor_need(type(value) is dict and set(value) == {
        'format', 'queue_config_directory', 'certificate_lineage'}, 'fields')
    monitor_need(type(value['format']) is int and value['format'] == 1, 'format')
    path = value['queue_config_directory']
    monitor_need(type(path) is str and len(path) <= 512 and
                 _mon_re.fullmatch(r'/etc/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+', path)
                 and all(part not in ('.', '..') for part in path.split('/')), 'queue_path')
    name = value['certificate_lineage']
    monitor_need(type(name) is str and len(name) <= 128 and
                 _mon_re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', name), 'lineage')
    return dict(value)


def monitor_decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            monitor_need(key not in result, 'duplicate_key')
            result[key] = value
        return result
    monitor_need(len(raw) <= 4096, 'size')
    return monitor_validate(_mon_json.loads(raw, object_pairs_hook=pairs))


def monitor_encode(value):
    return (_mon_json.dumps(monitor_validate(value), sort_keys=True, indent=2) + '\n').encode()


def monitor_directory(path, root='/'):
    """Open each directory without following links; never trust writable parents."""
    fd = _mon_os.open(root, _mon_os.O_RDONLY | _mon_os.O_DIRECTORY | _mon_os.O_NOFOLLOW)
    try:
        for part in path.strip('/').split('/'):
            monitor_need(part not in ('', '.', '..'), 'directory_component')
            child = _mon_os.open(part, _mon_os.O_RDONLY | _mon_os.O_DIRECTORY | _mon_os.O_NOFOLLOW, dir_fd=fd)
            _mon_os.close(fd); fd = child
            info = _mon_os.fstat(fd)
            monitor_need(info.st_uid == 0 and not info.st_mode & 0o022, 'directory_trust')
        return fd
    except BaseException:
        _mon_os.close(fd)
        raise


def monitor_regular(directory, name, limit, *, contents=False):
    fd = _mon_os.open(name, _mon_os.O_RDONLY | _mon_os.O_NOFOLLOW | _mon_os.O_NONBLOCK, dir_fd=directory)
    try:
        info = _mon_os.fstat(fd)
        monitor_need(_mon_stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                     info.st_uid == 0 and not info.st_mode & 0o022 and 0 < info.st_size <= limit, 'file_trust')
        raw = _mon_os.read(fd, limit + 1) if contents else None
        after = _mon_os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_uid, s.st_gid, s.st_mode)
        monitor_need(identity(info) == identity(after) == identity(_mon_os.stat(name, dir_fd=directory, follow_symlinks=False)), 'file_race')
        if contents: monitor_need(len(raw) == info.st_size, 'file_size')
        return raw if contents else identity(info)
    finally:
        _mon_os.close(fd)


def monitor_load(root='/'):
    directory = monitor_directory('/etc/mail-management-operations-v1', root)
    try:
        return monitor_decode(monitor_regular(directory, 'environment.json', 4096, contents=True))
    finally:
        _mon_os.close(directory)


def monitor_queue_guard(value, root='/'):
    directory = monitor_directory(monitor_validate(value)['queue_config_directory'], root)
    try:
        return monitor_regular(directory, 'main.cf', 1048576)
    finally:
        _mon_os.close(directory)


def monitor_certificate_guard(value, root='/'):
    name = monitor_validate(value)['certificate_lineage']
    live = monitor_directory('/etc/letsencrypt/live/' + name, root)
    archive = None
    try:
        link = _mon_os.stat('fullchain.pem', dir_fd=live, follow_symlinks=False)
        monitor_need(link.st_uid == 0 and _mon_stat.S_ISLNK(link.st_mode), 'certificate_link')
        target = _mon_os.readlink('fullchain.pem', dir_fd=live)
        match = _mon_re.fullmatch(r'\.\./\.\./archive/' + _mon_re.escape(name) + r'/(fullchain[1-9][0-9]{0,6}\.pem)', target)
        monitor_need(match is not None, 'certificate_target')
        archive = monitor_directory('/etc/letsencrypt/archive/' + name, root)
        identity = monitor_regular(archive, match[1], 65536)
        again = _mon_os.stat('fullchain.pem', dir_fd=live, follow_symlinks=False)
        monitor_need((link.st_ino, link.st_mtime_ns, link.st_ctime_ns) ==
                     (again.st_ino, again.st_mtime_ns, again.st_ctime_ns) and
                     _mon_os.readlink('fullchain.pem', dir_fd=live) == target, 'certificate_race')
        return (link.st_dev, link.st_ino, link.st_mtime_ns, target, *identity)
    finally:
        _mon_os.close(live)
        if archive is not None: _mon_os.close(archive)


def monitor_commands(value):
    value = monitor_validate(value)
    return {
        'queue': ('/usr/sbin/postqueue', '-c', value['queue_config_directory'], '-j'),
        'certificate': ('/usr/bin/openssl', 'x509', '-in', '/etc/letsencrypt/live/' +
                        value['certificate_lineage'] + '/fullchain.pem', '-noout', '-enddate'),
    }


def monitor_targets(value, root='/'):
    monitor_queue_guard(value, root)
    monitor_certificate_guard(value, root)
    return monitor_validate(value)
