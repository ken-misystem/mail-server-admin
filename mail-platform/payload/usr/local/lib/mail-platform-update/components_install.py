"""Assemble component resources using the captured pure renderers and site facts."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from base_configuration import Resource, render as base_files
from configuration_templates import render as private_configurations

CERTIFICATE = '/usr/local/lib/mail-client-certificates-v1'
ACTORS = {'owner': 'mailcert-owner', 'lifecycle': 'mailcert-lifecycle',
          'verifier': 'mailcert-verifier', 'issuer': 'mailcert-issuer', 'gate': 'mailcert-gate'}
PRINCIPALS = {'view_definer': 'mailcert_views_v1', 'identity_reader': 'mailcert_identity_v1',
              'orchestrator': 'mailcert_owner_v1', 'issuer_journal': 'mailcert_issuer_v1',
              'gateway_reader': 'mailcert_gateway_v1', 'lifecycle_provisioner': 'mailcert_lifecycle_v1',
              'session_reader': 'mailcert_session_v1', 'webauthn_verifier': 'mailcert_verify_v1'}


class RecipeFailure(ValueError):
    def __init__(self, operation, process):
        super().__init__('pure_recipe_failed_' + operation)
        self.diagnostic = {'operation': operation, 'exit': process.returncode,
                           'stdout': process.stdout[:2097152].decode('utf-8', 'replace'),
                           'stderr': process.stderr[:65536].decode('utf-8', 'replace')}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def recipe(payload, operation, arguments):
    process = subprocess.run([sys.executable, '-I', '-S', '-B', str(Path(__file__).with_name('recipe_entry.py')),
                              str(payload), operation], input=encoded(arguments), capture_output=True, timeout=30)
    if process.returncode != 0 or process.stderr:
        raise RecipeFailure(operation, process)
    return json.loads(process.stdout)


def assemble(payload, site, identities, passwords, native, call_recipe=recipe):
    payload = Path(payload)
    base = json.loads((payload / 'blueprint/install-recipes.json').read_bytes())
    base['management_entry'] = (payload / 'blueprint/management_entry.php').read_text(encoding='utf-8')
    resources = base_files(site, identities, passwords, base)
    by_path = {item.path: item for item in resources}
    backend = call_recipe(payload, 'backend', {'listeners': {'listeners': [
        {'service': 'imap-login', 'name': 'imap', 'kind': 'inet_listener'},
        {'service': 'pop3-login', 'name': 'pop3', 'kind': 'inet_listener'},
        {'service': 'managesieve-login', 'name': 'sieve', 'kind': 'inet_listener'},
        {'service': 'lmtp', 'name': '/var/spool/postfix/private/dovecot-lmtp', 'kind': 'unix_listener'},
        {'service': 'auth', 'name': '/var/spool/postfix/private/auth', 'kind': 'unix_listener'},
    ]}})
    private_main = by_path['/etc/postfix/main.cf'].raw
    overrides = backend['postfix']
    overrides.update(data_directory='/run/mail-client-certificates-v1/postfix/data',
                     smtpd_data_restrictions='check_policy_service unix:/run/mail-send-limits-v1/policy.sock',
                     smtpd_milters='unix:/run/mail-client-certificates-v1/native/milter.sock, unix:/run/mail-client-certificates-v1/native/rspamd.sock')
    lines = private_main.decode().splitlines()
    kept = [line for line in lines if line.split('=', 1)[0].strip() not in overrides]
    private_main = ('\n'.join(kept) + '\n' + ''.join(key + ' = ' + value + '\n'
                                                  for key, value in overrides.items())).encode()
    private_master = backend['master'].encode()
    resources += [Resource('/etc/mail-client-certificates-v1/dovecot-backend.conf', backend['dovecot'].encode()),
                  Resource('/etc/mail-client-certificates-v1/postfix/main.cf', private_main),
                  Resource('/etc/mail-client-certificates-v1/postfix/master.cf', private_master)]
    artifacts = {'root_certificate': native['ca']['root']['path'],
                 'issuer_certificate': native['ca']['issuer']['path'],
                 'smtpd_sha256': native['executables']['smtpd'],
                 'private_main_sha256': sha(private_main), 'private_master_sha256': sha(private_master),
                 'legacy_settings_sha256': native['settings_sha256']}
    configs = private_configurations(site, {'identities': identities, 'secrets': passwords, 'artifacts': artifacts})
    for path, value in configs.items():
        if path == '/etc/mail-client-certificates-v1/web.json':
            value = dict(value, bytes=encoded({'version': 1, 'owner_uid': identities['mailcert-owner.uid'],
                                               'owner_gid': native['actor_gids']['owner']}))
        resources.append(Resource(path, value['bytes'], value['group'], value['mode'],
                                  preserve=path.endswith('db.json') or path.endswith('admin.php')))
    # The plugin's recovery URL follows the installed webmail root.
    recovery = next(item for item in resources if item.path == '/etc/roundcube/account_recovery.inc.php')
    resources.remove(recovery)
    resources.append(Resource(recovery.path, recovery.raw.replace(
        ('https://' + site['mail_host'] + '/roundcube').encode(), ('https://' + site['mail_host']).encode()),
        recovery.group, recovery.mode))
    peers = {}
    for actor, name in {**ACTORS, 'fpm': 'www-data'}.items():
        peers[actor] = {'uid': identities[name + '.uid'],
                        'gid': identities[name + '.gid'] if actor == 'fpm' else native['actor_gids'][actor],
                        'cgroup': '/system.slice/' + ('php8.4-fpm.service' if actor == 'fpm'
                                                     else 'mail-client-cert-' + actor + '.service')}
    listeners = [{'name': protocol + '_v4', 'protocol': protocol, 'address': [site['public_ipv4'], port]}
                 for protocol, port in [('imaps', 993), ('pop3s', 995), ('submission', 587)]]
    actors = call_recipe(payload, 'certificate', {
        'release': CERTIFICATE, 'manifest_pin': native['certificate_manifest_sha256'], 'peers': peers,
        'groups': {actor: identities[name + '.gid'] for actor, name in
                   [('owner', 'mailcert-owner'), ('gate', 'mailcert-gate'), ('fpm', 'www-data')]},
        'sql_socket': '/run/mysqld/mysqld.sock', 'ca': native['ca'], 'listeners': listeners,
        'host_namespace': native['host_namespace'], 'principals': PRINCIPALS,
        'executables': {'python': '/usr/bin/python3', 'openssl': '/usr/bin/openssl', 'php': '/usr/bin/php8.4'},
        'readiness': '/run/mail-client-certificates-v1/coordination/ready.json',
    })
    for actor, value in actors.items():
        resources.append(Resource('/etc/mail-client-certificates-v1/' + actor + '.json',
                                  encoded(value), ACTORS[actor], 0o640))
    roles = {'owner': ['identity_reader', 'orchestrator', 'gateway_reader', 'session_reader'],
             'lifecycle': ['lifecycle_provisioner'], 'verifier': ['webauthn_verifier'],
             'issuer': ['issuer_journal'], 'gate': ['gateway_reader']}
    for actor, names in roles.items():
        for name in names:
            principal = PRINCIPALS[name]
            value = {'unix_socket': '/run/mysqld/mysqld.sock', 'user': principal,
                     'password': passwords[principal], 'database': 'roundcube' if name in
                     ('session_reader', 'webauthn_verifier') else 'mail_management'}
            resources.append(Resource('/var/lib/mail-client-certificates-v1/credentials/' + actor + '/' + name,
                                      encoded(value), mode=0o600, preserve=True))
    feature_state = call_recipe(payload, 'feature_state', {})
    for name, value in {'configuration.json': feature_state, 'spam-fragment.json': {'sha256': sha(b'\n')},
                         'generation-catalog.json': {'version': 1, 'generations': {}},
                         'DNS-scheduler.json': {'next_after': ''}}.items():
        resources.append(Resource('/var/lib/mail-feature-runtime-v1/' + name, encoded(value), mode=0o600, preserve=True))
    compiler = base['compiler_configuration']
    for directive, number in (('mail_uid', identities['vmail.uid']), ('mail_gid', identities['vmail.gid'])):
        old = directive + ' = 5000'
        if compiler.count(old) != 1:
            raise ValueError('compiler_identity_contract')
        compiler = compiler.replace(old, directive + ' = ' + str(number))
    resources += [Resource('/var/lib/mail-feature-runtime-v1/compile.conf', compiler.encode(), mode=0o600),
                  Resource('/var/lib/mail-feature-public-v1/rspamd-managed.conf', b'\n'),
                  Resource('/etc/mail-management-alerts-v1/discord-webhook.url', b'\n', mode=0o600, preserve=True),
                  Resource('/var/lib/mail-platform-update/policy.json', encoded({'mode': 'manual', 'revision': 0}),
                           mode=0o600, preserve=True)]
    resources += [
        Resource('/etc/systemd/system/mail-client-cert-health.service.d/50-mail-platform.conf',
                 b'[Service]\nSupplementaryGroups=mailcert-owner\n'),
        Resource('/etc/systemd/system/mail-client-cert-postfix-backend.service.d/50-mail-platform.conf',
                 b'[Unit]\nRequires=mail-send-limits-v1.socket rspamd.service\nAfter=mail-send-limits-v1.socket rspamd.service\n'
                 b'[Service]\nBindReadOnlyPaths=/var/spool/postfix/private/mail-send-limits-v1.sock:/run/mail-send-limits-v1/policy.sock\n'
                 b'BindReadOnlyPaths=/run/rspamd/mail-platform-milter.sock:/run/mail-client-certificates-v1/native/rspamd.sock\n'),
        Resource('/etc/systemd/system/rspamd.service.d/50-mail-platform.conf', b'[Service]\nSupplementaryGroups=postfix\n'),
        Resource('/var/www/mail-admin/passkey.js',
                 (payload / 'opt/mail-management/candidates/protection-relay-v1/public/passkey.js').read_bytes()),
    ]
    protection = call_recipe(payload, 'protection', {})
    for name, text in call_recipe(payload, 'AV_config', {}).items():
        resources.append(Resource('/etc/mail-antivirus-v1/' + name, text.encode()))
    loader = base64.b64decode(protection['loader'])
    resources += [Resource('/etc/rspamd/lua.local.d/90-mail-protection-v1.lua', loader),
                  Resource('/var/lib/mail-protection-public-v1/antivirus.lua', base64.b64decode(protection['antivirus'])),
                  Resource('/var/lib/mail-protection-public-v1/attachments.lua', base64.b64decode(protection['attachments']))]
    for prefix in ('/etc/postfix', '/etc/mail-client-certificates-v1/postfix'):
        resources.append(Resource(prefix + '/mail-admin-upstream-passwords', b'', 'postfix', 0o640))
    mapping = {item.path: item.raw for item in resources}
    expected = {kind: {path: sha(mapping[path]) for path in paths} for kind, paths in protection['targets'].items()}
    context = {'engine_uid': identities['mailantivirus.uid'], 'expected': expected,
               'main_baselines': {path: base64.b64encode(mapping[path]).decode() for path in
                                  ('/etc/postfix/main.cf', '/etc/mail-client-certificates-v1/postfix/main.cf')},
               'loader_base': base64.b64encode(b'').decode()}
    resources.append(Resource('/var/lib/mail-protection-admin-v1/context.json', encoded(context), mode=0o600, preserve=True))
    return resources
