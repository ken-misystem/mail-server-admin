"""Create a private, isolated installation tree without configuring the host."""
import hashlib
import json
import os
import secrets
import stat
from pathlib import Path

from configuration_templates import describe, references, render, templates
from identity_bindings import bind as bind_identities
from site_bindings import bind as bind_site


def baseline_identities(payload):
    value = json.loads((Path(payload) / 'blueprint/identities.json').read_bytes())
    users = {row['uid']: name for name, row in value['users'].items()}
    groups = {number: name for name, number in value['groups'].items()}
    groups.update({row['gid']: row['group'] for row in value['users'].values()})
    users[0] = 'root'
    groups[0] = 'root'
    return {'users': users, 'groups': groups}


def read_payload(payload):
    root = Path(payload)
    files = {}
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('payload_link')
        if path.is_file():
            if path.relative_to(root).as_posix() == 'installer.py':
                continue
            files[path.relative_to(root).as_posix()] = path.read_bytes()
    return files


def compile_tree(payload, site, facts, private_secrets):
    if set(facts) != {'identities', 'artifacts'}:
        raise ValueError('facts_fields')
    files = read_payload(payload)
    bound = bind_site(files, site)
    bound, changed = bind_identities(bound, facts['identities'], baseline_identities(payload))
    configs = render(site, {**facts, 'secrets': private_secrets})
    paths = {path.lstrip('/') for path in configs}
    if paths.intersection(bound):
        raise ValueError('configuration_payload_collision')
    public = {
        'status': 'prepared_candidate', 'host_configured': False,
        'code_files': len(bound), 'configuration_files': len(configs),
        'identity_guard_sources': changed,
        'configuration': describe(site),
        'activation_markers_created': False,
        'migration_history_created': False,
        'update_default': 'manual', 'notifications_default': 'disabled',
    }
    return bound, configs, public


def read_facts(path):
    """Only public target identities and artifact paths/digests belong here."""
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
        raise ValueError('facts_file')
    value = json.loads(path.read_bytes())
    if type(value) is not dict or set(value) != {'identities', 'artifacts'}:
        raise ValueError('facts_fields')
    return value


def private_write(root_fd, name, raw):
    parts = Path(name).parts
    if not parts or Path(name).is_absolute() or '..' in parts:
        raise ValueError('staging_path')
    descriptor = os.dup(root_fd)
    try:
        for piece in parts[:-1]:
            try:
                os.mkdir(piece, 0o700, dir_fd=descriptor)
                os.fsync(descriptor)
            except FileExistsError:
                pass
            child = os.open(piece, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError('staging_directory_attributes')
        fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=descriptor)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def prepare(payload, site, facts, output):
    """Generate new secrets once, retaining an interrupted tree for operator review."""
    if os.name != 'posix':
        raise ValueError('private_staging_requires_POSIX_permissions')
    destination = Path(output).absolute()
    parent_fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    root_fd = None
    try:
        for part in destination.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child
            info = os.fstat(parent_fd)
            sticky = bool(info.st_mode & stat.S_ISVTX)
            if info.st_uid not in (0, os.geteuid()) or (info.st_mode & 0o022 and not sticky):
                raise ValueError('staging_parent_attributes')
        os.mkdir(destination.name, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
        root_fd = os.open(destination.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                          dir_fd=parent_fd)
        names = sorted({ref.name for template in templates(site)
                        for ref in references(template.value) if ref.section == 'secrets'})
        values = {name: secrets.token_hex(32) for name in names}
        private_write(root_fd, 'private/credentials.json', json.dumps(values).encode())
        code, configs, report = compile_tree(payload, site, facts, values)
        for name, raw in code.items():
            private_write(root_fd, 'rootfs/' + name, raw)
        for path, entry in configs.items():
            private_write(root_fd, 'rootfs/' + path.lstrip('/'), entry['bytes'])
        public = json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2).encode() + b'\n'
        private_write(root_fd, 'preparation.json', public)
        fd = os.open('preparation.json', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=root_fd)
        try:
            received = os.read(fd, len(public) + 1)
        finally:
            os.close(fd)
        if received != public:
            raise ValueError('preparation_readback')
        return {'status': report['status'], 'host_configured': False,
                'code_files': len(code), 'configuration_files': len(configs),
                'receipt_sha256': hashlib.sha256(public).hexdigest()}
    finally:
        if root_fd is not None:
            os.close(root_fd)
        os.close(parent_fd)
