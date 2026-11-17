"""Keep adopted native fixes across signed application updates.

This is a read-only compatibility gate, never a package installer. Native package
changes need a separately tested migration hook. Both manual and automatic
updates use the same gate; an old release cannot silently drop adopted fixes.
"""
import json
import os
from pathlib import Path
import re
import subprocess

from host_transaction import regular
from release import sha

DESCRIPTOR = 'payload/blueprint/migrations/native-requirements-v1.json'
RECEIPT = 'native-components.json'
LIBRARY = '/usr/lib/rspamd/librspamd-server.so'
PRESERVE_DESCRIPTOR = 'payload/blueprint/migrations/native-preservation-v1.json'
MIGRATION_DESCRIPTOR = 'payload/blueprint/migrations/rspamd-package-v1/manifest.json'
PRESERVE_CONTRACT = {'format': 1, 'mode': 'preserve-installed',
                     'package_operations': False, 'existing_receipt': 'verify-runtime'}


def validate(value):
    if (type(value) is not dict or set(value) != {'format', 'components'}
            or type(value['format']) is not int or value['format'] != 1
            or type(value['components']) is not dict
            or set(value['components']) != {'rspamd'}):
        raise ValueError('native_requirements_shape')
    row = value['components']['rspamd']
    if (type(row) is not dict or set(row) != {'version', 'architecture', 'files', 'fix'}
            or row['architecture'] != 'amd64'
            or type(row['version']) is not str
            or not re.fullmatch(r'[0-9][A-Za-z0-9.+:~_-]{0,79}', row['version'])
            or row['fix'] != 'symcache-single-fd-persistence-v1'
            or type(row['files']) is not dict or set(row['files']) != {LIBRARY}
            or type(row['files'][LIBRARY]) is not str
            or not re.fullmatch('[a-f0-9]{64}', row['files'][LIBRARY])):
        raise ValueError('native_requirements_component')
    return value


def observe(allow_inactive=False):
    result = subprocess.run(['/usr/bin/dpkg-query', '-W',
        '-f=${db:Status-Status}\t${Version}\t${Architecture}', 'rspamd'],
        capture_output=True, timeout=15)
    if result.returncode or result.stderr:
        raise ValueError('native_package_query_failed')
    fields = result.stdout.decode('ascii').split('\t')
    if len(fields) != 3 or fields[0] != 'installed':
        raise ValueError('native_package_not_installed')
    before = Path(LIBRARY).stat()
    raw, info = regular(LIBRARY)
    if info['uid'] != 0 or info['gid'] != 0 or info['mode'] & 0o022:
        raise ValueError('native_library_trust')
    process = subprocess.run(['/usr/bin/systemctl', 'show', 'rspamd.service',
        '-p', 'ActiveState,MainPID,Job'], capture_output=True, timeout=15)
    if process.returncode or process.stderr:
        raise ValueError('native_service_query_failed')
    values = dict(line.split('=',1) for line in process.stdout.decode('ascii').splitlines())
    if allow_inactive and values.get('ActiveState') == 'inactive' and values.get('MainPID') == '0' and values.get('Job') == '':
        after = Path(LIBRARY).stat()
        identity = lambda st: (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
        if identity(before) != identity(after):
            raise ValueError('native_runtime_changed_during_read')
        return {'version': fields[1], 'architecture': fields[2],
                'files': {LIBRARY: sha(raw)}, 'fix': 'symcache-single-fd-persistence-v1'}
    if values.get('ActiveState') != 'active' or values.get('Job') != '' or not values.get('MainPID','').isdecimal():
        raise ValueError('native_service_not_ready')
    pid = int(values['MainPID'])
    if pid <= 1:
        raise ValueError('native_service_pid')
    proc = Path('/proc')/str(pid)
    initial = (proc/'stat').read_bytes()
    maps = (proc/'maps').read_text(encoding='ascii')
    final = (proc/'stat').read_bytes()
    ticks = lambda raw: int(raw.rsplit(b')',1)[1].split()[19])
    after = Path(LIBRARY).stat()
    identity = lambda st: (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
    if ticks(initial) != ticks(final) or identity(before) != identity(after):
        raise ValueError('native_runtime_changed_during_read')
    mapped = []
    for line in maps.splitlines():
        row = line.split(None,5)
        if len(row) != 6 or row[5] not in (LIBRARY,LIBRARY+' (deleted)'):
            continue
        device = tuple(int(n,16) for n in row[3].split(':'))
        if row[5] != LIBRARY or device != (os.major(after.st_dev),os.minor(after.st_dev)) or int(row[4]) != after.st_ino:
            raise ValueError('native_loaded_library_drift')
        mapped.append(row)
    if not any('x' in row[1] for row in mapped):
        raise ValueError('native_library_not_loaded')
    return {'version': fields[1], 'architecture': fields[2],
            'files': {LIBRARY: sha(raw)}, 'fix': 'symcache-single-fd-persistence-v1'}


def check(files, state, observer=observe):
    """files is the already signature-verified release member dictionary."""
    receipt = Path(state)/RECEIPT
    installed = None
    if receipt.exists() or receipt.is_symlink():
        raw, attributes = regular(receipt, limit=16384)
        if attributes['uid'] != 0 or attributes['gid'] != 0 or attributes['mode'] != 0o600:
            raise ValueError('native_receipt_trust')
        installed = validate(json.loads(raw))
    offered = files.get(DESCRIPTOR)
    migration = files.get(MIGRATION_DESCRIPTOR)
    if migration is not None:
        value = json.loads(migration[0])
        if (value.get('format') != 1 or value.get('package') != 'rspamd' or value.get('architecture') != 'amd64'
                or value.get('baseline',{}).get('version') != '3.12.1-1'
                or value.get('candidate',{}).get('version') != '3.12.1-1+0misystem1'):
            raise ValueError('native_signed_migration_shape')
        if installed is not None:
            actual = observe(allow_inactive=True) if observer is observe else observer()
            if (installed['components']['rspamd']['version'] != value['candidate']['version']
                    or installed['components']['rspamd']['files'][LIBRARY] != value['candidate']['runtime_files'][LIBRARY]
                    or actual != installed['components']['rspamd']):
                raise ValueError('native_migration_receipt_runtime_drift')
        return {'required':True,'preflight_operations':0,'package_operations':'signed-migration-hook',
                'existing_receipt_verified':installed is not None,'descriptor_sha256':sha(migration[0])}
    preservation = files.get(PRESERVE_DESCRIPTOR)
    if preservation is not None:
        if json.loads(preservation[0]) != PRESERVE_CONTRACT:
            raise ValueError('native_preservation_descriptor')
        if installed is not None and observer() != installed['components']['rspamd']:
            raise ValueError('native_runtime_requires_migration_or_repair')
        return {'required': installed is not None, 'operations': 0,
                'native_fix_applied_by_this_update': False,
                'existing_receipt_verified': installed is not None,
                'descriptor_sha256': sha(preservation[0])}
    if offered is None:
        if installed is not None:
            raise ValueError('release_drops_adopted_native_fix')
        return {'required': False, 'operations': 0}
    raw = offered[0]
    if len(raw) > 16384:
        raise ValueError('native_descriptor_size')
    required = validate(json.loads(raw))
    if installed is None:
        raise ValueError('native_adoption_receipt_required')
    # Changing a native version is NOT an application-update side effect.
    if installed is not None and required != installed:
        raise ValueError('native_change_requires_dedicated_migration')
    actual = observer()
    if actual != required['components']['rspamd']:
        raise ValueError('native_runtime_requires_migration_or_repair')
    return {'required': True, 'operations': 0, 'reused_installed_rspamd': actual['version'],
            'descriptor_sha256': sha(raw)}
