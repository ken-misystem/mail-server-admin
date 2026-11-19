"""Fresh-install configuration contracts derived from public runtime consumers.

Templates contain references, never production values. Rendering is pure and keeps
secret bytes separate from the public plan and installation receipt.
"""
import json
import re
from dataclasses import dataclass

from site_bindings import validate


class ConfigurationError(ValueError):
    """A finite error code suitable for a public installation receipt."""


@dataclass(frozen=True)
class Reference:
    section: str
    name: str
    kind: type = str


@dataclass(frozen=True)
class Template:
    path: str
    group: str
    mode: int
    value: dict
    encoding: str = 'json'


def identity(name, field):
    return Reference('identities', name + '.' + field, int)


def artifact(name):
    return Reference('artifacts', name)


def secret(name):
    return Reference('secrets', name)


def database(user, schema=None):
    value = {'user': user, 'password': secret(user)}
    if schema:
        # All supported SQL consumers use the local MariaDB Unix socket.
        value = {'dsn': 'mysql:unix_socket=/run/mysqld/mysqld.sock;dbname='
                 + schema + ';charset=utf8mb4', **value}
    return value


def templates(site):
    validate(site)
    certificate = '/etc/mail-client-certificates-v1/'
    feature = '/etc/mail-feature-runtime-v1/'
    routing = '/etc/mail-domain-routing-v1/'
    alerts = '/etc/mail-management-alerts-v1/'
    source = '/etc/mail-platform/'
    host = site['mail_host']
    admin_database = database('mail_management_app', 'mail_management')
    return [
        Template(certificate + 'health.json', 'root', 0o600, {
            'version': 1, 'gate_uid': identity('mailcert-gate', 'uid'),
            'certificate_source': '/etc/letsencrypt/live/' + host + '/fullchain.pem',
            'key_source': '/etc/letsencrypt/live/' + host + '/privkey.pem',
            'root_certificate': artifact('root_certificate'),
            'issuer_certificate': artifact('issuer_certificate'),
        }),
        Template(certificate + 'milter.json', 'postfix', 0o640, {
            'postfix_uid': identity('postfix', 'uid'),
            'postfix_gid': identity('postfix', 'gid'),
        }),
        Template(certificate + 'smtpd.json', 'postfix', 0o640, {
            'configuration': certificate + 'postfix',
            'binary_sha256': artifact('smtpd_sha256'),
            'pins': {'main.cf': artifact('private_main_sha256'),
                     'master.cf': artifact('private_master_sha256')},
            'postfix_uid': identity('postfix', 'uid'),
            'postfix_gid': identity('postfix', 'gid'),
        }),
        Template(certificate + 'web.json', 'www-data', 0o640, {
            'version': 1, 'owner_uid': identity('mailcert-owner', 'uid'),
            'owner_gid': identity('mailcert-owner', 'gid'),
        }),
        Template(routing + 'reader.json', 'mail-route-collector', 0o440, {
            **database('mail_domain_route_reader'),
            'socket': '/run/mysqld/mysqld.sock',
        }),
        Template(routing + 'runtime.json', 'root', 0o644, {
            'version': 1, 'activation_enabled': True,
            'allowed_postfix_uids': [identity('postfix', 'uid')],
            'collector_uid': identity('mail-route-collector', 'uid'),
            'self_addresses': [site['public_ipv4']],
            'local_transport': 'lmtp:unix:private/dovecot-lmtp',
        }),
        Template('/etc/mail-feature-admin-v1/db.json', 'root', 0o600,
                 database('mail_feature_reader')),
        Template(feature + 'deployment.json', 'root', 0o600, {
            'version': 1, 'legacy_settings_sha256': artifact('legacy_settings_sha256'),
        }),
        Template(feature + 'rspamd-context.json', 'root', 0o644, {
            'uid': identity('_rspamd', 'uid'), 'gid': identity('_rspamd', 'gid'),
            'groups': Reference('identities', '_rspamd.groups', list),
        }),
        Template(alerts + 'public-reader.json', 'mailadmin', 0o640, {
            'version': 1, 'public_gid': identity('mailadmin', 'gid'),
            'worker_uid': identity('mailalerts', 'uid'),
        }),
        Template(alerts + 'runtime.json', 'mailadmin', 0o640, {
            'version': 1, 'enabled': False,
            'channels': {'email': False, 'discord': False},
            'smtp': {'host': '127.0.0.1', 'port': 25, 'sender': 'postmaster@' + host},
            'public_group': identity('mailadmin', 'gid'),
        }),
        Template('/etc/mail-management/admin.php', 'mailadmin', 0o640, {
            'dsn': admin_database['dsn'], 'db_user': admin_database['user'],
            'db_password': admin_database['password'],
            'application_secret': secret('management_application'),
            'state_directory': '/var/lib/mail-management',
            'rp_id': host, 'origin': 'https://' + host,
        }, 'php'),
        Template(source + 'update-source.json', 'root', 0o600, {
            'repository': 'ken-misystem/mail-server-admin',
        }),
        Template(source + 'update-ui.json', 'root', 0o600, {
            'allowed_uid': identity('mailadmin', 'uid'),
        }),
        Template('/etc/mail-pop/worker.json', 'mailpop', 0o640,
                 database('mail_pop_worker', 'mail_management')),
        Template('/etc/mail-send-limits-v1/db.json', 'root', 0o600,
                 database('mail_send_limit_reader')),
        Template('/etc/mail-send-limits-v1/runtime.json', 'root', 0o644, {
            'uid': identity('mailsendlimits', 'uid'),
            'peer_uid': identity('postfix', 'uid'),
            'socket': '/var/spool/postfix/private/mail-send-limits-v1.sock',
            'state': '/var/lib/mail-send-limits-v1',
            'database_socket': '/run/mysqld/mysqld.sock',
        }),
        Template('/etc/roundcube/account_recovery.inc.php', 'www-data', 0o640, {
            'base_url': 'https://' + host + '/roundcube',
            'db_dsn': database('roundcube_recovery', 'mailserver')['dsn'],
            'db_user': 'roundcube_recovery', 'db_pass': secret('roundcube_recovery'),
            'mail_from': 'postmaster@' + host, 'verify_token_lifetime': 3600,
        }, 'php'),
        Template('/etc/roundcube/app-passwords.json', 'www-data', 0o640,
                 database('mail_app_password_ui', 'mailserver')),
        Template('/etc/roundcube/webmail-passkey.json', 'www-data', 0o640,
                 database('roundcube_webmail_passkey', 'mailserver')),
        Template('/etc/roundcube/local_ja_tweaks.php', 'www-data', 0o640,
                 {'username': 'メールアドレス'}, 'php'),
        Template('/etc/roundcube/mail-aliases.php', 'www-data', 0o640,
                 database('mail_alias_ui', 'mail_management'), 'php'),
        Template('/etc/roundcube/mail-pop.json', 'www-data', 0o640,
                 database('mail_pop_ui', 'mail_management')),
    ]


def references(value):
    if isinstance(value, Reference):
        return {value}
    if isinstance(value, dict):
        return set().union(*(references(child) for child in value.values()))
    if isinstance(value, list):
        return set().union(*(references(child) for child in value))
    return set()


def describe(site):
    result = []
    for template in templates(site):
        refs = references(template.value)
        result.append({
            'path': template.path, 'owner': 'root', 'group': template.group,
            'mode': format(template.mode, '04o'), 'encoding': template.encoding,
            'required': sorted(ref.section + '.' + ref.name for ref in refs),
        })
    return result


def resolve(value, inputs):
    if isinstance(value, Reference):
        resolved = inputs.get(value.section, {}).get(value.name)
        if type(resolved) is not value.kind:
            raise ConfigurationError('input_type_' + value.section)
        if value.kind is int and not 0 < resolved < 4294967295:
            raise ConfigurationError('identity_range')
        if value.kind is list and (not resolved or any(
                type(item) is not int or not 0 < item < 4294967295 for item in resolved)):
            raise ConfigurationError('supplementary_groups')
        if value.kind is str and ('\0' in resolved or len(resolved) > 4096):
            raise ConfigurationError('input_string')
        if value.section == 'secrets' and not 32 <= len(resolved) <= 256:
            raise ConfigurationError('secret_size')
        if value.section == 'artifacts':
            if value.name.endswith('_sha256'):
                if not re.fullmatch('[a-f0-9]{64}', resolved):
                    raise ConfigurationError('artifact_digest')
            elif not re.fullmatch('/[A-Za-z0-9/._-]+', resolved) or '..' in resolved.split('/'):
                raise ConfigurationError('artifact_path')
        return resolved
    if isinstance(value, dict):
        return {key: resolve(child, inputs) for key, child in value.items()}
    if isinstance(value, list):
        return [resolve(child, inputs) for child in value]
    return value


def encode(value, encoding):
    body = json.dumps(value, ensure_ascii=True, separators=(',', ':'))
    if encoding == 'php':
        # A PHP single-quoted JSON literal cannot interpolate PHP expressions.
        body = body.replace('\\', '\\\\').replace("'", "\\'")
        return ("<?php\nreturn json_decode('" + body
                + "', true, 32, JSON_THROW_ON_ERROR);\n").encode('ascii')
    return (body + '\n').encode('ascii')


def render(site, inputs):
    """Return private bytes and metadata. Callers must never serialize this result to logs."""
    if set(inputs) != {'identities', 'artifacts', 'secrets'}:
        raise ConfigurationError('input_sections')
    output = {}
    for template in templates(site):
        value = resolve(template.value, inputs)
        output[template.path] = {
            'bytes': encode(value, template.encoding),
            'owner': 'root', 'group': template.group, 'mode': template.mode,
        }
    return output
