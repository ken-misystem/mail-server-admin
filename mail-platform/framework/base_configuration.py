"""New-host base files. All credentials are generated at the destination."""
from dataclasses import dataclass
import json
import re

from site_bindings import validate


@dataclass(frozen=True)
class Resource:
    path: str
    raw: bytes
    group: str = 'root'
    mode: int = 0o644
    preserve: bool = False


def mysql_map(user, password, schema, query):
    if not re.fullmatch('[A-Za-z0-9_-]{64}', password):
        raise ValueError('generated_map_password')
    return ('hosts = unix:/run/mysqld/mysqld.sock\nuser = ' + user + '\npassword = '
            + password + '\ndbname = ' + schema + '\nquery = ' + query + '\n').encode()


def render(site, identities, passwords, recipes):
    validate(site)
    host = site['mail_host']
    address = site['public_ipv4']
    tls = '/etc/letsencrypt/live/' + host
    files = []

    def add(path, text, group='root', mode=0o644, preserve=False):
        files.append(Resource(path, text.encode() if isinstance(text, str) else text,
                              group, mode, preserve))

    domains = ("SELECT d.name FROM virtual_domains d WHERE d.name='%s' AND d.active=1 UNION "
               "SELECT a.alias_domain FROM virtual_domain_aliases a JOIN virtual_domains d "
               "ON d.id=a.target_domain_id WHERE a.alias_domain='%s' AND a.active=1 AND d.active=1")
    mailboxes = ("SELECT u.email FROM virtual_users u JOIN virtual_domains d ON d.id=u.domain_id "
                 "WHERE u.email='%s' AND u.active=1 AND d.active=1")
    aliases = ("SELECT a.destination FROM virtual_aliases a JOIN virtual_domains d ON d.id=a.domain_id "
               "WHERE a.source='%s' AND a.active=1 AND d.active=1 UNION "
               "SELECT CONCAT(SUBSTRING_INDEX('%s','@',1),'@',d.name) FROM virtual_domain_aliases a "
               "JOIN virtual_domains d ON d.id=a.target_domain_id JOIN virtual_users u ON u.domain_id=d.id "
               "AND u.email=CONCAT(SUBSTRING_INDEX('%s','@',1),'@',d.name) "
               "WHERE a.alias_domain=SUBSTRING_INDEX('%s','@',-1) AND a.active=1 AND d.active=1 AND u.active=1")
    queries = {'domains.cf': domains, 'mailboxes.cf': mailboxes, 'aliases.cf': aliases,
               **recipes['address_preferences']}
    for name, query in queries.items():
        add('/etc/postfix/sql/' + name, mysql_map('mailreader', passwords['mailreader'],
                                                'mailserver', query), 'postfix', 0o640)
    add('/etc/postfix/legacy-smtp-sender-v1.cf', mysql_map(
        'mail_legacy_smtp_maps', passwords['mail_legacy_smtp_maps'], 'mail_management',
        recipes['legacy_sender_query']), 'postfix', 0o640)
    main = {
        'compatibility_level': '3.10', 'myhostname': host, 'myorigin': '$myhostname',
        'mydestination': '$myhostname, localhost', 'inet_interfaces': '127.0.0.1, ' + address,
        'inet_protocols': 'ipv4', 'mynetworks': '127.0.0.0/8',
        'smtpd_relay_restrictions': 'permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination',
        'smtpd_recipient_restrictions': 'check_recipient_access mysql:/etc/postfix/sql/recipient-syntax.cf, '
            'check_policy_service unix:private/mail-feature-access-v1.sock, reject_unlisted_recipient',
        'smtpd_policy_service_default_action': '451 4.3.5 Policy service unavailable',
        'smtpd_policy_service_timeout': '3s', 'smtpd_policy_service_try_limit': '1',
        'smtpd_data_restrictions': 'check_policy_service unix:private/mail-send-limits-v1.sock',
        'smtpd_sasl_auth_enable': 'no', 'smtpd_sasl_type': 'dovecot', 'smtpd_sasl_path': 'private/auth',
        'smtpd_sasl_security_options': 'noanonymous',
        'smtpd_tls_security_level': 'may', 'smtpd_tls_cert_file': tls + '/fullchain.pem',
        'smtpd_tls_key_file': tls + '/privkey.pem', 'smtpd_tls_protocols': '>=TLSv1.2',
        'smtp_tls_security_level': 'may', 'smtp_tls_CAfile': '/etc/ssl/certs/ca-certificates.crt',
        'virtual_mailbox_domains': 'mysql:/etc/postfix/sql/domains.cf',
        'virtual_mailbox_maps': 'mysql:/etc/postfix/sql/mailboxes.cf',
        'virtual_alias_maps': 'mysql:/etc/postfix/sql/variants.cf, mysql:/etc/postfix/sql/aliases.cf',
        'virtual_transport': 'lmtp:unix:private/dovecot-lmtp',
        'transport_maps': 'socketmap:unix:private/mail-domain-routing-v1:route',
        'smtp_host_lookup': 'dns', 'disable_vrfy_command': 'yes',
        'smtpd_authorized_xclient_hosts': '', 'smtpd_authorized_xforward_hosts': '',
        'smtpd_milters': 'unix:/run/rspamd/mail-platform-milter.sock', 'non_smtpd_milters': '$smtpd_milters',
        'milter_default_action': 'tempfail', 'milter_protocol': '6',
        'mailbox_size_limit': '0', 'message_size_limit': '52428800', 'recipient_delimiter': '+',
        'relayhost': '', 'smtpd_reject_unlisted_recipient': 'yes',
        'sender_canonical_maps': 'tcp:127.0.0.1:10001', 'sender_canonical_classes': 'envelope_sender',
        'recipient_canonical_maps': 'tcp:127.0.0.1:10002',
        'recipient_canonical_classes': 'envelope_recipient, header_recipient',
    }
    add('/etc/postfix/main.cf', ''.join(key + ' = ' + value + '\n' for key, value in main.items()))
    master = recipes['postfix_master'].rstrip() + '\n'
    master += address + ':25 inet n - n - 1 postscreen\n'
    master += '127.0.0.1:25 inet n - n - - smtpd\n'
    master += '  -o { smtpd_sasl_auth_enable = yes }\n  -o { smtpd_tls_auth_only = no }\n'
    master += '127.0.0.1:587 inet n - n - - smtpd\n'
    master += '  -o { smtpd_sasl_auth_enable = yes }\n  -o { smtpd_tls_security_level = encrypt }\n'
    master += '  -o { smtpd_relay_restrictions = permit_sasl_authenticated, reject }\n'
    master += address + ':465 inet n - n - 10 smtpd\n'
    options = {
        'smtpd_tls_wrappermode': 'yes', 'smtpd_tls_security_level': 'encrypt',
        'smtpd_tls_auth_only': 'yes', 'smtpd_sasl_auth_enable': 'yes',
        'smtpd_sasl_service': 'legacy-smtp', 'smtpd_sasl_path': 'private/mail-legacy-smtp-v1/auth',
        'smtpd_sender_login_maps': 'mysql:/etc/postfix/legacy-smtp-sender-v1.cf',
        'smtpd_sender_restrictions': 'reject_authenticated_sender_login_mismatch',
        'smtpd_relay_restrictions': 'permit_sasl_authenticated, reject',
    }
    master += ''.join('  -o { ' + key + ' = ' + value + ' }\n' for key, value in options.items())
    master += recipes['POP_ingress_master']
    add('/etc/postfix/master.cf', master)
    add('/etc/mail-legacy-smtp-v1/auth.conf', recipes['legacy_auth'], 'mail-legacy-auth', 0o640)
    add('/etc/mail-legacy-smtp-v1/mysql-auth.conf',
        'mysql /run/mysqld/mysqld.sock {\n user = mail_legacy_smtp_auth\n password = '
        + passwords['mail_legacy_smtp_auth'] + '\n dbname = mail_management\n}\n', 'mail-legacy-auth', 0o640)
    dovecot = f'''dovecot_config_version = 2.4.1
dovecot_storage_version = 2.4.1
protocols = imap pop3 lmtp sieve
listen = 127.0.0.1
ssl = required
ssl_server_cert_file = {tls}/fullchain.pem
ssl_server_key_file = {tls}/privkey.pem
mail_driver = maildir
mail_home = /var/vmail/%{{user | domain}}/%{{user | username}}
mail_path = %{{home}}/Maildir
mail_uid = vmail
mail_gid = vmail
first_valid_uid = {identities['vmail.uid']}
auth_mechanisms = plain login
auth_username_format = %{{user | lower}}
auth_cache_size = 0
auth_verbose_passwords = no
sql_driver = mysql
!include /etc/dovecot/mail-platform-sql.conf
passdb app_passwords {{
 driver = sql
 result_success = return-ok
 result_failure = continue
 result_internalfail = return-fail
 passdb_sql_query = {recipes['app_password_query']}
}}
passdb sql {{
 query = SELECT u.password AS password,u.email AS user FROM virtual_users u JOIN virtual_domains d ON d.id=u.domain_id JOIN mail_management.mail_client_bootstrap_login_owners l ON l.owner_id=u.id WHERE BINARY l.login_name=BINARY LOWER('%{{user}}') AND l.active=1 AND u.active=1 AND d.active=1 LIMIT 1
}}
userdb sql {{
 query = SELECT u.email AS user,CONCAT(u.quota_bytes, 'B') AS quota_storage_size FROM virtual_users u JOIN virtual_domains d ON d.id=u.domain_id WHERE BINARY u.email=BINARY LOWER('%{{user}}') AND u.active=1 AND d.active=1
 iterate_query = SELECT email AS user FROM virtual_users WHERE active=1
}}
service auth {{
 unix_listener /var/spool/postfix/private/auth {{
  mode = 0660
  user = postfix
  group = postfix
 }}
}}
service imap-login {{
 inet_listener imap {{
  port = 143
 }}
 inet_listener imaps {{
  port = 0
 }}
}}
service pop3-login {{
 inet_listener pop3 {{
  port = 110
 }}
 inet_listener pop3s {{
  port = 0
 }}
}}
service lmtp {{
 unix_listener /var/spool/postfix/private/dovecot-lmtp {{
  mode = 0600
  user = postfix
  group = postfix
 }}
}}
protocol lmtp {{
 mail_plugins {{
  sieve = yes
 }}
}}
!include /etc/dovecot/mail-platform-sieve.conf
mail_plugins {{
 quota = yes
 mail_sieve_session_lock = yes
}}
protocol imap {{
 mail_plugins {{
  imap_quota = yes
 }}
}}
quota "User quota" {{
 driver = count
 storage_size = 0
 storage_grace = 0
 enforce = yes
}}
'''
    add('/etc/dovecot/dovecot.conf', dovecot)
    add('/etc/dovecot/mail-platform-sql.conf',
        'mysql /run/mysqld/mysqld.sock {\n user = mailreader\n password = '
        + passwords['mailreader'] + '\n dbname = mailserver\n}\n', 'root', 0o600)
    add('/etc/dovecot/mail-platform-sieve.conf', recipes['sieve_configuration'])
    add('/etc/php/8.4/fpm/pool.d/mail-platform.conf', '''[mail-platform]
user = mailadmin
group = mailadmin
listen = /run/php/mail-platform.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = 12
pm.process_idle_timeout = 20s
clear_env = yes
security.limit_extensions = .php
php_admin_flag[display_errors] = off
php_admin_flag[log_errors] = on
php_admin_value[session.cookie_secure] = 1
php_admin_value[session.cookie_httponly] = 1
php_admin_value[session.cookie_samesite] = Lax
''')
    add('/etc/nginx/sites-enabled/mail-platform.conf', f'''server {{
 listen 443 ssl;
 server_name {host};
 ssl_certificate {tls}/fullchain.pem;
 ssl_certificate_key {tls}/privkey.pem;
 ssl_protocols TLSv1.2 TLSv1.3;
 root /var/lib/roundcube;
 index index.php;
 client_max_body_size 50m;
 location = /mail-admin {{ return 302 /mail-admin/; }}
 location = /mail-admin/passkey.js {{ alias /var/www/mail-admin/passkey.js; }}
 location /mail-admin/ {{
  include fastcgi_params;
  fastcgi_param SCRIPT_FILENAME /var/www/mail-admin/index.php;
  fastcgi_param HTTPS on;
  fastcgi_param HTTP_PROXY "";
  fastcgi_pass unix:/run/php/mail-platform.sock;
 }}
 location / {{ try_files $uri $uri/ /index.php?$query_string; }}
 location ~ ^/(?:config|temp|logs|SQL|bin|installer|vendor)(?:/|$) {{ deny all; }}
 location ~ /\\. {{ deny all; }}
 location ~ \\.php$ {{
  try_files $uri =404;
  include fastcgi_params;
  fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
  fastcgi_param HTTPS on;
  fastcgi_param HTTP_PROXY "";
  fastcgi_pass unix:/run/php/php8.4-fpm.sock;
 }}
}}
''')
    app = '/opt/mail-management/candidates/protection-relay-v1'
    add('/var/www/mail-admin/index.php', recipes['management_entry'], 'mailadmin', 0o640)
    plugins = recipes['roundcube_plugins']
    roundcube = {
        'db_dsnw': 'mysql://roundcube:' + passwords['roundcube'] + '@localhost/roundcube',
        'imap_host': 'ssl://' + host + ':993', 'smtp_host': 'tls://127.0.0.1:587',
        'smtp_conn_options': {'ssl': {'verify_peer': True, 'verify_peer_name': True,
                                      'peer_name': host, 'SNI_enabled': True}},
        'smtp_user': '%u', 'smtp_pass': '%p', 'des_key': passwords['roundcube_session'][:24],
        'support_url': '', 'product_name': 'Webmail', 'language': 'ja_JP',
        'plugins': plugins, 'enable_installer': False,
        'log_driver': 'file', 'log_dir': '/var/log/roundcube', 'log_logins': True,
        'mail_pop_enabled': True, 'mail_aliases_enabled': True,
        'mail_settings_enabled': recipes.get('mail_settings_enabled', False),
        'mail_settings_sieve_peer_name': host,
    }
    from configuration_templates import encode
    body = encode(roundcube, 'php').decode().replace('return json_decode(', '$config = json_decode(', 1)
    add('/etc/roundcube/config.inc.php', body, 'www-data', 0o640)
    add('/etc/rspamd/local.d/worker-proxy.inc', '''bind_socket = "/run/rspamd/mail-platform-milter.sock mode=0660 owner=_rspamd group=postfix";
milter = yes;
upstream "local" { default = yes; self_scan = yes; }
''')
    add('/etc/rspamd/local.d/redis.conf', 'servers = "127.0.0.1";\n')
    add('/etc/rspamd/local.d/settings.conf', recipes['POP_ingress_settings']
        + '.include(try=true) "/var/lib/mail-feature-public-v1/rspamd-managed.conf"\n')
    add('/etc/rspamd/override.d/worker-controller.inc', 'bind_socket = "127.0.0.1:11334";\n')
    add('/etc/fail2ban/jail.d/mail-platform.conf', '''[sshd]
enabled = true
backend = systemd
[dovecot]
enabled = true
backend = systemd
port = 110,143,587,993,995
[postfix-sasl]
enabled = true
backend = systemd
port = 25,465,587
[roundcube-auth]
enabled = true
backend = auto
logpath = /var/log/roundcube/errors.log
port = 80,443
[recidive]
enabled = true
backend = auto
logpath = /var/log/fail2ban.log
''')
    add('/etc/fail2ban/fail2ban.local', '[Definition]\nlogtarget = /var/log/fail2ban.log\n')
    add('/etc/rsyslog.d/mail-platform.conf', 'mail.* -/var/log/mail.log\n')
    add('/etc/default/postsrsd', 'SRS_DOMAIN=' + host + '\nSRS_SECRET=/etc/postsrsd.secret\n'
        + 'SRS_FORWARD_PORT=10001\nSRS_REVERSE_PORT=10002\nSRS_LISTEN_ADDR=127.0.0.1\n')
    add('/etc/postsrsd.secret', passwords['postsrsd_secret'] + '\n', 'root', 0o600, True)
    add('/etc/rspamd/local.d/dkim_signing.conf',
        'selector = "mail";\npath = "/var/lib/rspamd/dkim/$domain.$selector.key";\n'
        'sign_authenticated = true;\nsign_local = true;\nuse_domain = "header";\n')
    return files
