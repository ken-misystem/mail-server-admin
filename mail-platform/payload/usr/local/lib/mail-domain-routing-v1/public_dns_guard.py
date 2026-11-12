"""Collector-only DNS mount contract. No DNS, DB or service operation in this module."""
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import traceback

SOURCE = '/etc/mail-domain-routing-v1/public-resolv.conf'
VIEW = '/etc/resolv.conf'
RUNTIME_TARGETS = ('/run/systemd/resolve/stub-resolv.conf', '/run/systemd/resolve/resolv.conf')
OVERRIDES = ('LOCALDOMAIN', 'RES_OPTIONS', 'RESOLV_HOST_CONF', 'HOSTALIASES',
             'LD_PRELOAD', 'LD_LIBRARY_PATH', 'GCONV_PATH')


class ProtectionError(ValueError):
    pass


def require(ok, reason):
    if not ok:
        raise ProtectionError(reason)


def resolver_bytes(servers):
    require(type(servers) is list and 1 <= len(servers) <= 3, 'public_dns_server_count')
    normalized = []
    for value in servers:
        require(type(value) is str and '%' not in value, 'public_dns_address_type')
        address = ipaddress.ip_address(value)
        require(address.is_global and not address.is_multicast and getattr(address, 'ipv4_mapped', None) is None,
                'public_dns_address_required')
        require(value == str(address) and value not in normalized, 'public_dns_canonical_unique')
        normalized.append(value)
    # Explicit root-only search. No implicit hostname-derived search domain or local fallback.
    return (''.join('nameserver ' + value + '\n' for value in normalized)
            + 'search .\noptions timeout:1 attempts:1 ndots:1\n').encode('ascii')


def parse_config(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 1024, 'public_dns_config_bound')
    text = raw.decode('ascii', 'strict')
    servers = [line[len('nameserver '):] for line in text.splitlines() if line.startswith('nameserver ')]
    require(raw == resolver_bytes(servers), 'public_dns_config_not_canonical')
    return servers


def key(s):
    return tuple(getattr(s, name) for name in ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode',
                                               'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def guarded_read(path, runtime_uid=None):
    """Root-owned leaf. Only fixed resolved runtime parents may have their observed service UID."""
    path = Path(path)
    fds = [os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    bindings = []
    try:
        for index, part in enumerate(path.parts[1:-1]):
            parent = fds[-1]
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            fds.append(fd)
            s = os.fstat(fd)
            fixed_runtime_parent = path.parts[1:index + 2] == ('run', 'systemd', 'resolve')
            owners = (0, runtime_uid) if fixed_runtime_parent and runtime_uid is not None else (0,)
            require(s.st_uid in owners and not s.st_mode & 0o022, 'public_dns_parent_guard')
            bindings.append((parent, part, fd))
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fds[-1])
        fds.append(fd)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o022
                and before.st_nlink == 1 and 0 < before.st_size <= 1024, 'public_dns_leaf_guard')
        raw = os.pread(fd, before.st_size + 1, 0)
        require(len(raw) == before.st_size and key(before) == key(os.fstat(fd))
                == key(os.stat(path.name, dir_fd=fds[-2], follow_symlinks=False)), 'public_dns_file_drift')
        for parent, part, child in bindings:
            require(key(os.fstat(child)) == key(os.stat(part, dir_fd=parent, follow_symlinks=False)), 'public_dns_parent_binding')
        return raw, before
    finally:
        for fd in reversed(fds):
            os.close(fd)


def mount_readonly(text, target):
    rows = [row.split() for row in text.splitlines() if len(row.split()) >= 7 and row.split()[4] == target]
    require(len(rows) == 1 and 'ro' in rows[0][5].split(','), 'public_dns_readonly_mount_required')


def verify(source=SOURCE):
    # Production caller supplies no arguments. Private verification passes only its approved fixture path.
    require(not any(name in os.environ for name in OVERRIDES), 'public_dns_environment_override')
    raw, original = guarded_read(source)
    servers = parse_config(raw)
    entry = Path(VIEW)
    before = entry.lstat()
    target = VIEW
    runtime_uid = None
    if stat.S_ISLNK(before.st_mode):
        require(before.st_uid == 0, 'public_dns_view_link_owner')
        value = os.readlink(entry)
        require(len(value.encode()) <= 512, 'public_dns_view_link_bound')
        target = os.path.normpath(os.path.join('/etc', value))
        require(target in RUNTIME_TARGETS, 'public_dns_view_link_target')
        import pwd  # Native Linux only; not imported by Windows local contracts.
        runtime_uid = pwd.getpwnam('systemd-resolve').pw_uid
    mounted, final = guarded_read(target, runtime_uid)
    require(raw == mounted and (original.st_dev, original.st_ino) == (final.st_dev, final.st_ino),
            'public_dns_view_not_source_inode')
    require(key(before) == key(entry.lstat()), 'public_dns_view_entry_drift')
    info = Path('/proc/self/mountinfo').read_bytes()
    require(len(info) <= 1048576, 'public_dns_mountinfo_bound')
    mount_readonly(info.decode('ascii', 'strict'), target)
    return {'public_nameservers': len(servers), 'mount_readonly': True, 'source_inode_matches': True,
            'mount_namespace_inode': os.stat('/proc/self/ns/mnt').st_ino}


def safe_error(exc):
    return {'component': 'collector_public_dns_guard', 'class': type(exc).__name__,
            'reason': str(exc) if type(exc) is ProtectionError else 'public_dns_guard_failed',
            'errno': getattr(exc, 'errno', None),
            'frames': [{'source': Path(f.filename).name, 'function': f.name, 'line': f.lineno}
                       for f in traceback.extract_tb(exc.__traceback__)[-5:]], 'raw_error_output': False}
