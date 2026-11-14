"""Signed component inventory and installed, root-owned update boundaries."""
import json
from pathlib import PurePosixPath
import re

from release import canonical, sha, version


def path(value):
    if not isinstance(value, str) or not re.fullmatch(r'/[A-Za-z0-9_./@+-]+', value):
        raise ValueError('availability_path')
    if '..' in value.split('/') or PurePosixPath(value).as_posix() != value:
        raise ValueError('availability_path')
    return value


def configuration(value):
    if set(value) != {'format', 'generation_root', 'components'} or value['format'] != 1:
        raise ValueError('availability_configuration')
    path(value['generation_root'])
    if not value['components']:
        raise ValueError('availability_components_empty')
    for name, component in value['components'].items():
        roots = []
        if not re.fullmatch('[a-z][a-z0-9-]{0,30}', name):
            raise ValueError('availability_component_name')
        fields = {'kind', 'roots', 'route', 'control', 'runtime', 'unit', 'template', 'health', 'drain_seconds'}
        if set(component) != fields or component['kind'] not in ('web', 'reader', 'writer'):
            raise ValueError('availability_component_fields')
        for field in ('route', 'control', 'runtime'):
            path(component[field])
        if component['kind'] == 'web':
            path(component['template'])
        elif component['template'] is not None:
            raise ValueError('availability_unexpected_template')
        if not re.fullmatch(r'mail-platform-[a-z0-9-]+@\.service', component['unit']):
            raise ValueError('availability_unit_template')
        if type(component['drain_seconds']) not in (int, float) or not 0 < component['drain_seconds'] <= 300:
            raise ValueError('availability_drain_budget')
        if not component['roots']:
            raise ValueError('availability_component_roots')
        for root in component['roots']:
            path(root)
            if any(root == other or root.startswith(other + '/') or other.startswith(root + '/') for other in roots):
                raise ValueError('availability_root_overlap')
            roots.append(root)
        health = component['health']
        fields={'kind','request','reply'}
        if set(health) not in (fields,fields|{'peer_uid','peer_gid'},fields|{'parameters'}) or health['kind'] not in ('http', 'fcgi', 'policy'):
            raise ValueError('availability_health')
        if 'peer_uid' in health and (health['kind']!='policy' or
                any(type(health[key]) is not int or health[key]<=0 for key in ('peer_uid','peer_gid'))):
            raise ValueError('availability_health_peer_identity')
        if 'parameters' in health:
            allowed = {'SCRIPT_NAME','REQUEST_URI','SERVER_NAME','SERVER_PORT','HTTPS','REMOTE_ADDR','SERVER_SOFTWARE'}
            parameters = health['parameters']
            if (health['kind'] != 'fcgi' or type(parameters) is not dict or set(parameters)-allowed
                    or any(type(value) is not str or not 0 < len(value) <= 1024 or any(char in value for char in '\r\n\0')
                           for value in parameters.values())):
                raise ValueError('availability_health_parameters')
        if any(not isinstance(health[key], str) or len(health[key]) > 16384 for key in ('request', 'reply')):
            raise ValueError('availability_health_payload')
    return value


def select(contract, installed, changes):
    if set(contract) != {'format', 'from_version', 'to_version', 'components', 'configuration_sha256'} or contract['format'] != 2:
        raise ValueError('availability_contract')
    if version(contract['to_version']) <= version(contract['from_version']):
        raise ValueError('availability_contract_version')
    if not re.fullmatch('[a-f0-9]{64}', contract['configuration_sha256']):
        raise ValueError('availability_contract_digest')
    configuration(installed)
    if contract['configuration_sha256'] != sha(canonical(installed)):
        raise ValueError('availability_configuration_drift')
    names = contract['components']
    if type(names) is not list or not names or len(names) != len(set(names)):
        raise ValueError('availability_contract_components')
    if set(names) - installed['components'].keys():
        raise ValueError('availability_unregistered_component')
    for name in names:
        component = installed['components'][name]
        siblings = [other for other, value in installed['components'].items() if value['unit'] == component['unit']]
        if set(siblings) - set(names):
            raise ValueError('availability_shared_unit_requires_all_components')
        if any((installed['components'][other]['kind'] != component['kind'] for other in siblings)):
            raise ValueError('availability_shared_unit_mixed_kinds')
    owners = {}
    for changed in changes:
        path(changed)
        matching = [name for name, component in installed['components'].items() if any((changed.startswith(root + '/') for root in component['roots']))]
        if not matching or set(matching) - set(names):
            raise ValueError('availability_uncovered_code:' + changed)
        owners[changed] = matching
    if set().union(*(set(value) for value in owners.values())) != set(names):
        raise ValueError('availability_extra_component')
    return owners


def impact(components):
    return [{'component': name, 'method': 'writer_handoff' if component['kind'] == 'writer' else 'new_generation',
             'mail_reception': '継続', 'session': '既存要求の完了後に旧世代を停止',
             'temporary_failure': '引継ぎの待機上限超過時は451' if component['kind'] == 'writer' else None}
            for name, component in components.items()]


def release_impact(files):
    raw = files.get('payload/blueprint/update-contract.json')
    if raw is None:
        return None
    value = json.loads(raw[0])
    if value.get('format') == 2:
        names = value.get('components')
        if not isinstance(names, list) or not all(isinstance(name, str) and re.fullmatch('[a-z][a-z0-9-]{0,30}', name) for name in names):
            raise ValueError('availability_preview_components')
        return {'method': '機能ごとの世代切替え', 'components': names,
                'delivery': '初回組込みと接続先の登録を確認して適用'}
    return {'method': '停止・再開を伴う更新', 'components': [],
            'delivery': '更新契約の対象サービスと復旧条件を確認して適用'}
