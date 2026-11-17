"""Render first-adoption changes from observed files, without an old receipt.

Configuration is retained byte-for-byte except explicit component additions and
references to code whose old and new bytes are both part of this transaction.
This is a planner: no DB, account, key, package, enablement or mailbox writes.
"""
import json
from pathlib import Path

from adoption_plan import PROTECTED, READINESS
from code_update import CERTIFICATE, PREFIXES
from configuration_templates import templates
from host_transaction import regular
from identity_bindings import bind as bind_identities
from install_preparation import read_payload, baseline_identities
from profile_bindings import bind as bind_profile
from release import canonical, sha
from roundcube_core import render as render_core
from roundcube_migration import configuration, MARKER, CONFIG
from site_bindings import bind as bind_site, rebase
from sieve_lock import MODULE, SOURCE, validate as validate_module
from sieve_migration import ANCHOR, REPLACEMENT
from policy_binding import DROPIN, CONTENT


def attributes(raw, before=None, *, mode=0o644, gid=0):
    return {'sha256':sha(raw), 'uid':before['uid'] if before else 0,
            'gid':before['gid'] if before else gid, 'mode':before['mode'] if before else mode}


def replace_references(value, hashes):
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            new_key = hashes.get(key, key)
            if new_key in result:
                raise ValueError('adoption_configuration_key_collision')
            result[new_key] = replace_references(item, hashes)
        return result
    if isinstance(value, list):
        return [replace_references(item, hashes) for item in value]
    return hashes.get(value, value) if isinstance(value, str) else value


def compile_components(payload, site, identities, live, exists, *, native,
                       module, module_metadata, version, release_sha256, checks, updater_registration=None, sieve_layout=None, code_aliases=None, monitor_root="/"):
    from code_aliases import bind as bind_aliases, validate as validate_aliases
    aliases=validate_aliases(code_aliases or {})
    from monitor_binding import adoption as monitoring_adoption
    from monitor_environment import MONITOR_CONFIG
    monitoring = monitoring_adoption(live, exists, monitor_root)
    if set(checks) != set(READINESS):
        raise ValueError('adoption_component_readiness')
    if isinstance(payload,dict):
        files={k:v for k,v in payload.items() if k!='installer.py'}
        values=json.loads(files['blueprint/identities.json'])
        baseline={'users':{row['uid']:name for name,row in values['users'].items()},
                  'groups':{number:name for name,number in values['groups'].items()}}
        baseline['groups'].update({row['gid']:row['group'] for row in values['users'].values()})
        baseline['users'][0]='root';baseline['groups'][0]='root'
    else:files=read_payload(payload);baseline=baseline_identities(payload)
    bound = bind_site(files, site)
    bound, _ = bind_identities(bound, identities, baseline)
    bound = bind_profile(bound, supplemental_dns=b"UNITS += ('mail-reputation-dns-v1.service',)" in
                         live('/usr/local/lib/mail-management-operations-v1/read_runtime.py')[0])
    manifest_name = CERTIFICATE+'runtime-manifest.json'
    current_manifest = json.loads(live('/'+manifest_name)[0])
    next_manifest = json.loads(bound[manifest_name])
    for field in ('guard_pin','python_pin','openssl_pin','php_pin'):
        next_manifest[field] = current_manifest[field]
    guard = CERTIFICATE+'guard.so'
    guard_raw, _ = live('/'+guard)
    if sha(guard_raw) != current_manifest['guard_pin']:
        raise ValueError('adoption_certificate_guard_pin')
    baseline = dict(bound)
    bound[guard] = guard_raw
    next_manifest['pins'] = {name:sha(bound[CERTIFICATE+name]) for name in next_manifest['pins']}
    bound[manifest_name] = canonical(next_manifest)
    # Native guard is present in the installed tree, not necessarily in the tar.
    baseline.setdefault(guard, guard_raw)
    bound = rebase(bound, baseline)
    bound = bind_aliases(bound, aliases)
    desired = {}
    owned = {}
    units = {}
    observations = {}

    def before(name):
        if name not in observations:
            observations[name] = live(name)[1] if exists(name) else None
        return observations[name]

    def put(name, raw, *, code=False, mode=0o644, gid=0):
        previous = before(name)
        if previous is not None and (previous['uid'] != 0 or previous['mode'] & 0o022):
            raise ValueError('adoption_existing_file_trust:'+name)
        metadata = attributes(raw, previous, mode=mode, gid=gid)
        if code:
            owned[name] = metadata
        if previous != metadata:
            desired[name] = (raw, previous, metadata)
        return metadata

    if monitoring is not None:
        put(MONITOR_CONFIG, monitoring)

    for name, raw in bound.items():
        if name.startswith('blueprint/'):
            if name.startswith('blueprint/systemd/'):
                unit = name.removeprefix('blueprint/systemd/')
                if '/' in unit or not unit.endswith(('.service','.socket','.timer','.target','.slice')):
                    raise ValueError('adoption_unit_name')
                units[unit] = put('/etc/systemd/system/'+unit, raw)
            continue
        if not name.startswith(PREFIXES):
            raise ValueError('adoption_payload_scope:'+name)
        # Operational import script stays outside package ownership.
        if '/'+name in PROTECTED:
            continue
        put('/'+name, raw, code=True)

    if updater_registration is not None:
        from adoption_enrollment import resources
        for name,(raw,mode) in resources(updater_registration['public_key'],updater_registration['allowed_uid']).items():
            if exists(name):raise ValueError('adoption_existing_updater_configuration')
            put(name,raw,mode=mode)

    # Standard Roundcube sources are restored by exact known patch reversal.
    for name, raw in render_core(bound, live).items():
        put('/'+name, raw, code=True)
    original, info = live(CONFIG)
    if MARKER in original:
        # Existing plugin mode is accepted only with the exact generated block.
        marker_at = original.index(MARKER)
        prefix = original[:marker_at].rstrip(b'\n')
        if configuration(prefix, site['mail_host']) != original:
            raise ValueError('adoption_existing_Roundcube_plugin_configuration')
    else:
        put(CONFIG, configuration(original, site['mail_host']))

    validate_module(module, module_metadata, bound[SOURCE])
    if exists(MODULE) and live(MODULE)[0] != module:
        raise ValueError('adoption_Sieve_native_collision')
    put(MODULE, module, code=True)
    raw, _ = live('/etc/dovecot/dovecot.conf')
    if sieve_layout is not None:
        from adoption_sieve import render as render_sieve, PATH, content as sieve_content
        if exists(PATH):raise ValueError('adoption_Sieve_include_exists')
        put('/etc/dovecot/dovecot.conf',render_sieve(raw,sieve_layout))
        put(PATH,sieve_content(sieve_layout))
    elif b'mail_sieve_session_lock' not in raw:
        if raw.count(ANCHOR) != 1:
            raise ValueError('adoption_Sieve_configuration_anchor')
        put('/etc/dovecot/dovecot.conf', raw.replace(ANCHOR, REPLACEMENT))
    elif raw.count(REPLACEMENT) != 1:
        raise ValueError('adoption_Sieve_configuration_unknown')
    if exists(DROPIN) and live(DROPIN)[0] != CONTENT:
        raise ValueError('adoption_policy_binding_collision')
    put(DROPIN, CONTENT)
    meta_path = '/etc/mail-platform/sieve-lock.json'
    if exists(meta_path) and json.loads(live(meta_path)[0]) != module_metadata:
        raise ValueError('adoption_Sieve_metadata_collision')
    put(meta_path, canonical(module_metadata), mode=0o600)

    hashes = {}
    for name, (_, old, new) in desired.items():
        if name in owned and old:
            if old['sha256'] in hashes and hashes[old['sha256']] != new['sha256']:
                raise ValueError('adoption_ambiguous_configuration_pin')
            hashes[old['sha256']] = new['sha256']
    for template in templates(site):
        if template.encoding != 'json' or not exists(template.path):
            continue
        raw, _ = live(template.path)
        original = json.loads(raw)
        following = replace_references(original, hashes)
        if following != original:
            put(template.path, canonical(following))
    for actor in ('owner','gate','issuer','verifier','lifecycle'):
        name = '/etc/mail-client-certificates-v1/'+actor+'.json'
        raw, _ = live(name); value = json.loads(raw)
        if value['manifest_sha256'] != sha(live('/'+manifest_name)[0]):
            raise ValueError('adoption_certificate_actor_drift')
        value['manifest_sha256'] = sha(bound[manifest_name])
        if value != json.loads(raw):
            put(name, canonical(value))
    for name, raw in {
        '/etc/systemd/system/mail-client-cert-owner.service.d/70-ca-IPC.conf':
            b'[Service]\nSupplementaryGroups=mailcert-gate\n',
        '/etc/systemd/system/mail-client-cert-health.service.d/70-certificate-lock.conf':
            b'[Service]\nReadWritePaths=/run/lock\n'}.items():
        if exists(name) and live(name)[0] != raw:
            raise ValueError('adoption_certificate_dropin_collision')
        put(name, raw)
    certificate_config = '/etc/mail-platform/certificates.json'
    if not exists(certificate_config):
        put(certificate_config, canonical({'format':1,'profile':'production','host':site['mail_host'],
            'probe_address':site['public_ipv4'],'trust_store':'/etc/ssl/certs/ca-certificates.crt'}), mode=0o600)
    receipt = {'format':2, 'version':version, 'site':site, 'identities':identities,
        'code':owned, 'unit_files':units,
        'schemas':{n:sha(r) for n,r in bound.items() if n.startswith('blueprint/') and (n.endswith('.sql') or n.endswith('/grants.json'))},
        'blueprints':{n:sha(r) for n,r in bound.items() if n.startswith('blueprint/')
            and not n.startswith(('blueprint/systemd/','blueprint/migrations/')) and n != 'blueprint/update-contract.json'},
        'native_migrations':{'sieve_session_lock':'v1'}}
    if aliases:receipt['code_aliases']=aliases
    for name, value in {'installed-code.json':receipt, 'installed.json':{'version':version,'release':release_sha256},
                        'native-components.json':native, 'policy.json':{'revision':0,'mode':'manual'}}.items():
        target = '/var/lib/mail-platform-update/'+name
        if exists(target):
            raise ValueError('adoption_existing_registration')
        put(target, canonical(value), mode=0o600)
    plan = {'format':1, 'kind':'existing-host-adoption','source':'unregistered-existing-host',
        'target':{'version':version,'release_sha256':release_sha256},'preserve':list(PROTECTED),
        'changes':[{'path':n,'before':old,'after':new,'operation':'replace' if old else 'create'}
                   for n,(_,old,new) in sorted(desired.items())], 'checks':checks}
    if aliases:plan['code_aliases']=aliases
    return plan, {n:row[0] for n,row in desired.items()}, receipt
