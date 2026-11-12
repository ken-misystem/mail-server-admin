"""Fresh MariaDB schema/least-privilege plan. No production rows are imported."""
from collections import defaultdict
import json
from pathlib import Path
import re


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch('[a-z][a-z0-9_]{0,63}', value):
        raise ValueError('SQL_identifier')
    return '`' + value + '`'


def statements(text):
    """Split exported DDL, honoring quotes and SQL comments."""
    result = []
    current = []
    quote = None
    index = 0
    while index < len(text):
        char = text[index]
        pair = text[index:index + 2]
        if quote:
            current.append(char)
            if char == '\\' and quote != '`' and index + 1 < len(text):
                index += 1
                current.append(text[index])
            elif char == quote:
                if index + 1 < len(text) and text[index + 1] == quote:
                    index += 1
                    current.append(quote)
                else:
                    quote = None
        elif char in "'\"`":
            quote = char
            current.append(char)
        elif pair == '--' and (index + 2 == len(text) or text[index + 2].isspace()):
            end = text.find('\n', index)
            index = len(text) if end < 0 else end
            current.append('\n')
        elif char == '#':
            end = text.find('\n', index)
            index = len(text) if end < 0 else end
            current.append('\n')
        elif pair == '/*':
            end = text.find('*/', index + 2)
            if end < 0:
                raise ValueError('SQL_unclosed_comment')
            if text[index:index + 3] == '/*!':
                raise ValueError('SQL_executable_comment_requires_explicit_recipe')
            index = end + 1
            current.append(' ')
        elif char == ';':
            value = ''.join(current).strip()
            if value:
                result.append(value)
            current = []
        else:
            current.append(char)
        index += 1
    if quote:
        raise ValueError('SQL_unclosed_quote')
    if ''.join(current).strip():
        result.append(''.join(current).strip())
    return result


def principals(metadata):
    names = set()
    for rows in metadata.values():
        for row in rows:
            match = re.fullmatch("'([a-z][a-z0-9_]{0,31})'@'localhost'", row['grantee'])
            if not match:
                raise ValueError('SQL_principal')
            names.add(match[1])
    return sorted(names | {'mailcert_session_v1', 'mailcert_verify_v1', 'roundcube'})


def grants(metadata):
    output = []
    for row in metadata['schema']:
        if row != {'grantee': "'mailreader'@'localhost'", 'privilege': 'SELECT', 'schema': 'mailserver'}:
            raise ValueError('unexpected_schema_grant')
        output.append(('mailserver', '*', "GRANT SELECT ON `mailserver`.* TO 'mailreader'@'localhost'"))
    for row in metadata['table']:
        if row['privilege'] not in ('SELECT', 'INSERT', 'UPDATE', 'DELETE'):
            raise ValueError('SQL_table_privilege')
        table = identifier(row['schema']) + '.' + identifier(row['table'])
        output.append((row['schema'], row['table'], 'GRANT ' + row['privilege'] + ' ON '
                       + table + ' TO ' + row['grantee']))
    grouped = defaultdict(set)
    for row in metadata['column']:
        if row['privilege'] not in ('SELECT', 'INSERT', 'UPDATE'):
            raise ValueError('SQL_column_privilege')
        grouped[(row['schema'], row['table'], row['grantee'], row['privilege'])].add(row['column'])
    for (schema, name, grantee, privilege), columns in sorted(grouped.items()):
        table = identifier(schema) + '.' + identifier(name)
        clause = ','.join(identifier(column) for column in sorted(columns))
        output.append((schema, name, 'GRANT ' + privilege + ' (' + clause + ') ON '
                       + table + ' TO ' + grantee))
    extra = [
        ('mailcert_lifecycle_v1', 'users', 'SELECT', ['user_id', 'username', 'mail_host']),
        ('mailcert_session_v1', 'session', 'SELECT', ['sess_id', 'vars', 'changed']),
        ('mailcert_verify_v1', 'auth_webauthn_users', 'SELECT', ['user_id', 'user_handle']),
        ('mailcert_verify_v1', 'auth_webauthn_credentials', 'SELECT',
         ['id', 'user_id', 'credential_id', 'user_handle', 'credential_record_json', 'transports_json', 'enabled', 'sign_count']),
        ('mailcert_verify_v1', 'auth_webauthn_credentials', 'UPDATE',
         ['credential_record_json', 'sign_count', 'last_used_at']),
    ]
    for user, name, privilege, columns in extra:
        clause = ','.join(identifier(column) for column in columns)
        output.append(('roundcube', name, 'GRANT ' + privilege + ' (' + clause + ') ON `roundcube`.'
                       + identifier(name) + " TO '" + user + "'@'localhost'"))
    output.append(('roundcube', '*', "GRANT SELECT,INSERT,UPDATE,DELETE ON `roundcube`.* TO 'roundcube'@'localhost'"))
    return output


def plan(payload, passwords):
    payload = Path(payload)
    metadata = json.loads((payload / 'blueprint/grants.json').read_bytes())
    users = principals(metadata)
    if not set(users) <= set(passwords):
        raise ValueError('database_credentials_incomplete')
    steps = []
    for name in users:
        password = passwords[name]
        if not re.fullmatch('[A-Za-z0-9_-]{64}', password):
            raise ValueError('generated_database_password_format')
        sql = "CREATE USER '" + name + "'@'localhost' IDENTIFIED BY '" + password + "'"
        if name == 'mailcert_views_v1':
            sql += ' ACCOUNT LOCK'
        steps.append({'label': 'account_' + name, 'sql': sql})
    ddl = statements((payload / 'blueprint/schema.sql').read_text(encoding='utf-8'))
    views = []
    schema = None
    for sql in ddl:
        if sql.startswith('USE '):
            schema = sql.split('`')[1]
        if re.match('CREATE ALGORITHM=', sql):
            name = re.search(r'VIEW `mail_management`[.]`([a-z_]+)`', sql)[1]
            views.append((name, sql))
        else:
            steps.append({'label': 'schema_' + str(len(steps)), 'sql': sql})
    all_grants = grants(metadata)
    view_names = {name for name, _ in views}
    for schema, name, sql in all_grants:
        if schema != 'roundcube' and name not in view_names:
            steps.append({'label': 'base_grant_' + str(len(steps)), 'sql': sql})
    for name, sql in views:
        steps.append({'label': 'view_' + name, 'sql': sql})
        for schema, table, grant in all_grants:
            if schema == 'mail_management' and table == name:
                steps.append({'label': 'view_grant_' + str(len(steps)), 'sql': grant})
    steps.append({'label': 'Dovecot_canonical_login_view', 'sql':
        "GRANT SELECT ON mail_management.mail_client_bootstrap_login_owners TO 'mailreader'@'localhost'"})
    steps.append({'label': 'roundcube_database', 'sql': 'CREATE DATABASE `roundcube` CHARACTER SET utf8mb4'})
    # The installed Debian package supplies its own version-matched core schema.
    steps.append({'label': 'roundcube_package_schema', 'package_schema': True})
    steps.append({'label': 'roundcube_extension_schema', 'sql': 'USE `roundcube`;\n'
                  + (payload / 'blueprint/roundcube-webauthn.sql').read_text(encoding='utf-8')})
    for filename in ('002_auth_factor_recovery.sql', '003_emergency_factor_recovery.sql'):
        steps.append({'label': 'roundcube_' + filename[:-4], 'sql': 'USE `roundcube`;\n'
                      + (payload / 'blueprint' / filename).read_text(encoding='utf-8')})
    for schema, _, sql in all_grants:
        if schema == 'roundcube':
            steps.append({'label': 'roundcube_grant_' + str(len(steps)), 'sql': sql})
    steps.append({'label': 'initial_locks', 'sql':
                  "INSERT INTO mail_management.mail_management_locks(name) VALUES ('alias_namespace'),('admin_roles')"})
    steps.append({'label': 'initial_limits', 'sql':
                  'INSERT INTO mail_management.mail_send_limit_profiles '
                  '(profile,minute_messages,minute_recipients,hour_messages,hour_recipients,revision) '
                  "VALUES ('mailbox',20,50,200,500,1),('legacy',60,100,1000,2000,1)"})
    return {'principals': users, 'steps': steps, 'destructive_rollback': False}


def execute(compiled, commands, transaction, core_schema):
    client = ['/usr/bin/mariadb', '--no-defaults', '--protocol=socket', '--user=root',
              '--batch', '--skip-column-names']
    before = commands.run('empty_database_check', client, (
        "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME IN ('mailserver','mail_management','roundcube');\n"
        "SELECT @@global.general_log,@@global.slow_query_log;\n"
        "SELECT COUNT(*) FROM information_schema.PLUGINS WHERE PLUGIN_STATUS='ACTIVE' AND PLUGIN_TYPE='AUDIT';\n"
    ).encode())
    if before.decode().splitlines() != ['0', '0\t0', '0']:
        raise ValueError('fresh_database_precondition')
    # MariaDB DDL implicitly commits. Every step has its own durable started and
    # completed record. An interrupted started step is held, never replayed.
    session_prefix = b'SET FOREIGN_KEY_CHECKS=0;\n'
    for index, step in enumerate(compiled['steps']):
        sql = 'USE `roundcube`;\n' + core_schema if step.get('package_schema') else step['sql']
        if re.search(r'^\s*(DROP|TRUNCATE|REVOKE)\b', sql, re.I | re.M):
            raise ValueError('destructive_schema_recipe')
        # USE in the saved export is session-scoped, so keep its effective schema
        # explicit on each separate connection.
        if sql.startswith('USE '):
            active_schema = sql.split('`')[1]
        if index == 0:
            active_schema = 'mailserver'
        prefix = session_prefix + ('USE `' + active_schema + '`;\n').encode() if (
            not sql.startswith('CREATE DATABASE') and not sql.startswith('CREATE USER')
            and not sql.startswith('USE ') and active_schema in ('mailserver', 'mail_management')
        ) else session_prefix
        transaction.step(step['label'], lambda sql=sql, prefix=prefix, label=step['label']:
                         commands.run(label, client, prefix + sql.encode() + b';\n', timeout=120))
    result = commands.run('database_schema_readback', client, (
        "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA IN ('mailserver','mail_management');\n"
        'SELECT COUNT(*) FROM mail_management.mail_management_locks;\n'
        'SELECT COUNT(*) FROM mail_management.mail_send_limit_profiles;\n').encode())
    if result.decode().splitlines() != ['39', '2', '2']:
        raise ValueError('database_schema_readback')
