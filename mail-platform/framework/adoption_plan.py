"""Read-only adoption contract for a separately managed, already populated host.

No host operations are implemented here. Empty-host installation and fabricating
an old package version are explicitly excluded from the adoption procedure.
"""
import json
import re
from pathlib import PurePosixPath
from release import canonical, sha

PROTECTED = ('/var/vmail', '/var/spool/postfix', '/var/lib/mysql', '/etc/letsencrypt',
             '/var/lib/rspamd', '/var/lib/mail-client-certificates-v1',
             '/var/lib/mail-send-limits-v1', '/var/lib/mail-pop-general-v1',
             '/var/lib/mail-residual-pop-v1', '/var/lib/mail-backup-mx-v1',
             '/var/lib/mail-pop', '/etc/mail-pop', '/root',
             '/usr/local/sbin/xmail-pop-migrate.py')
READINESS = ('code_mapping', 'current_settings_mapping', 'DB_schema_and_grants',
             'Sieve_and_forwarding', 'Maildir_UID_identity', 'credential_reuse',
             'native_components', 'timer_and_dependencies', 'secondary_preservation',
             'isolated_initial_adoption', 'isolated_rollback', 'signed_release')


def safe_path(name):
    if (type(name) is not str or not name.startswith('/') or '\\' in name
            or '\0' in name or '..' in name.split('/')
            or PurePosixPath(name).as_posix() != name):
        raise ValueError('adoption_path')
    return name


def validate(value):
    if (set(value)-{'code_aliases'} != {'format', 'kind', 'source', 'target', 'changes', 'preserve', 'checks'}
            or value['format'] != 1 or value['kind'] != 'existing-host-adoption'
            or value['source'] != 'unregistered-existing-host'
            or type(value['target']) is not dict
            or set(value['target']) != {'version', 'release_sha256'}):
        raise ValueError('adoption_contract')
    from code_aliases import validate as validate_aliases, assert_physical
    aliases=validate_aliases(value.get('code_aliases',{}))
    assert_physical([c['path'] for c in value['changes']],aliases)
    if set(value['checks']) != set(READINESS):
        raise ValueError('adoption_readiness_inventory')
    if any(type(result) is not bool for result in value['checks'].values()):
        raise ValueError('adoption_readiness_boolean')
    if all(value['checks'].values()):
        if (type(value['target']['version']) is not str
                or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',value['target']['version'])
                or type(value['target']['release_sha256']) is not str
                or not re.fullmatch('[a-f0-9]{64}',value['target']['release_sha256'])):
            raise ValueError('adoption_target_not_pinned')
    for name in value['preserve']:
        safe_path(name)
    if not set(PROTECTED) <= set(value['preserve']):
        raise ValueError('adoption_missing_preservation')
    seen = set()
    for change in value['changes']:
        if set(change) != {'path', 'before', 'after', 'operation'}:
            raise ValueError('adoption_change_fields')
        name = safe_path(change['path'])
        if name in seen:
            raise ValueError('adoption_duplicate_change')
        seen.add(name)
        if change['operation'] not in ('create', 'replace'):
            raise ValueError('adoption_destructive_operation')
        if any(name == p or name.startswith(p+'/') or p.startswith(name+'/') for p in value['preserve']):
            raise ValueError('adoption_preserved_resource_write')
        if change['operation'] == 'replace' and change['before'] is None:
            raise ValueError('adoption_missing_CAS')
        if change['operation'] == 'create' and change['before'] is not None:
            raise ValueError('adoption_create_collision')
        for metadata in (change['before'], change['after']):
            if metadata is None:
                if metadata is change['after']:
                    raise ValueError('adoption_missing_target')
                continue
            if set(metadata) != {'sha256', 'uid', 'gid', 'mode'}:
                raise ValueError('adoption_attributes')
            if not re.fullmatch('[a-f0-9]{64}', metadata['sha256']):
                raise ValueError('adoption_hash')
            if any(type(metadata[k]) is not int or metadata[k] < 0 for k in ('uid','gid','mode')):
                raise ValueError('adoption_identity')
            if metadata['mode'] > 0o777:
                raise ValueError('adoption_permissions')
    return {'status': 'READY_FOR_REVIEW' if all(value['checks'].values()) else 'HOLD',
            'pending': [k for k,v in value['checks'].items() if not v],
            'changes': len(value['changes']), 'contract_sha256': sha(canonical(value)),
            'production_operations': 0}


def compare_current(plan, observed):
    """The future executor must repeat this immediately before any mutation."""
    result = validate(plan)
    if result['status'] != 'READY_FOR_REVIEW':
        raise ValueError('adoption_not_ready')
    for change in plan['changes']:
        if change['path'] not in observed or observed[change['path']] != change['before']:
            raise ValueError('adoption_current_state_changed')
    return result
