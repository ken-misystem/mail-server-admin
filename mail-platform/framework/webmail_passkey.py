"""Dovecot and MariaDB configuration for Roundcube's scoped WebAuthn sessions."""

import re

PRINCIPAL = 'roundcube_webmail_passkey'
SQL_SETUP = (
    """CREATE TABLE mailserver.webmail_passkey_sessions (
      selector BINARY(16) PRIMARY KEY, owner_id BIGINT UNSIGNED NOT NULL,
      auth_epoch BIGINT UNSIGNED NOT NULL, password_hash VARCHAR(96) CHARACTER SET ascii NOT NULL,
      expires_at DATETIME NOT NULL, INDEX (expires_at)
    ) ENGINE=InnoDB""",
    """CREATE TABLE mailserver.webmail_passkey_challenges (
      challenge_hash BINARY(32) PRIMARY KEY, expires_at DATETIME NOT NULL, INDEX (expires_at)
    ) ENGINE=InnoDB""",
    f"""GRANT INSERT, DELETE ON mailserver.webmail_passkey_sessions TO '{PRINCIPAL}'@'localhost'""",
    f"""GRANT SELECT (selector,expires_at) ON mailserver.webmail_passkey_sessions TO '{PRINCIPAL}'@'localhost'""",
    f"""GRANT INSERT, DELETE ON mailserver.webmail_passkey_challenges TO '{PRINCIPAL}'@'localhost'""",
    f"""GRANT SELECT (challenge_hash,expires_at) ON mailserver.webmail_passkey_challenges TO '{PRINCIPAL}'@'localhost'""",
    f"""GRANT SELECT (id,domain_id,active,email,auth_epoch) ON mailserver.virtual_users TO '{PRINCIPAL}'@'localhost'""",
    f"""GRANT SELECT (id,active) ON mailserver.virtual_domains TO '{PRINCIPAL}'@'localhost'""",
)

DOVECOT_CONFIG = '/etc/dovecot/mail-platform-webmail-passkey.conf'
SMTP_SERVICE = 'webmail-submission'


def dovecot_passdb():
    # Only the explicit roundcube submission service and host-local mailbox
    # listeners accept webmail tokens. The certificate gateway uses separate
    # IMAP ports and the normal smtp service. POP never takes these tokens.
    token = '^misw_[0-9a-f]{32}_[A-Za-z0-9_-]{43}$'
    valid = '%{password | if("~", "' + token + '", "1", "0")}'
    selector = ('%{password | if("~", "' + token
                + '", password, "misw_00000000000000000000000000000000") | substr(5, 32)}')
    query = (
        "SELECT s.password_hash AS password,u.email AS user "
        "FROM webmail_passkey_sessions s JOIN virtual_users u ON u.id=s.owner_id "
        "JOIN virtual_domains d ON d.id=u.domain_id "
        "WHERE s.selector=UNHEX('" + selector + "') AND '" + valid + "'='1' "
        "AND BINARY u.email=BINARY LOWER('%{user}') "
        "AND u.active=1 AND d.active=1 AND s.auth_epoch=u.auth_epoch AND s.expires_at>UTC_TIMESTAMP() "
        "AND '%{remote_ip}'='127.0.0.1' AND '%{local_ip}'='127.0.0.1' "
        "AND (('%{protocol}'='imap' AND '%{local_port}'='143') "
        "OR ('%{protocol}'='sieve' AND '%{local_port}'='4190') OR '%{protocol}'='" + SMTP_SERVICE + "') LIMIT 1"
    )
    return ('passdb webmail_passkey {\n driver = sql\n result_success = return-ok\n'
            ' result_failure = continue\n result_internalfail = return-fail\n passdb_sql_query = '
            + query + '\n}\n')


def existing_dovecot_config(source):
    """Prepare a config candidate derived from a 2.4 main config."""
    if DOVECOT_CONFIG in source:
        raise ValueError('existing_webmail_passdb_include')
    version = re.match(r'\Adovecot_config_version\s*=\s*2\.4\.[01][ \t]*\n', source)
    if version is None:
        raise ValueError('unknown_dovecot_config_version')
    return source[:version.end()] + '!include ' + DOVECOT_CONFIG + '\n' + source[version.end():]


def existing_postfix_master(source):
    """Bind the Webmail SASL service name to the existing local 587 only."""
    line = r'(?m)^127\.0\.0\.1:587[ \t]+inet[ \t]+[^\n]+\n(?:[ \t]+[^\n]*\n)*'
    matches = list(re.finditer(line, source))
    if len(matches) != 1:
        raise ValueError('unknown_local_postfix_submission')
    entry = matches[0]
    if 'smtpd_sasl_service' in entry[0] or 'smtpd_sasl_auth_enable' not in entry[0]:
        raise ValueError('unexpected_local_postfix_sasl_configuration')
    insert = source.index('\n', entry.start()) + 1
    option = '  -o { smtpd_sasl_service = ' + SMTP_SERVICE + ' }\n'
    return source[:insert] + option + source[insert:]
