"""Prepare site monitoring configuration, without executing legacy source."""
import ast
import re
from monitor_environment import (MONITOR_CONFIG, monitor_validate, monitor_decode,
    monitor_encode, monitor_targets)

RUNTIME = '/usr/local/lib/mail-management-operations-v1/read_runtime.py'


def trusted(raw, metadata):
    if metadata['uid'] != 0 or metadata['mode'] & 0o022:
        raise ValueError('monitor_environment_source_trust')
    return raw


def discover(raw):
    tree = ast.parse(raw)
    assignments = [n.value for n in tree.body if isinstance(n, ast.Assign) and
                   any(isinstance(t, ast.Name) and t.id == 'COMMANDS' for t in n.targets)]
    if len(assignments) != 1 or not isinstance(assignments[0], ast.Dict):
        raise ValueError('monitor_environment_legacy_commands')
    values = {}
    for key, item in zip(assignments[0].keys, assignments[0].values):
        if isinstance(key, ast.Constant) and key.value in ('queue', 'certificate'):
            if key.value in values: raise ValueError('monitor_environment_duplicate_command')
            values[key.value] = ast.literal_eval(item)
    queue = values.get('queue')
    if queue == ('/usr/sbin/postqueue', '-j'):
        directory = '/etc/postfix'
    elif isinstance(queue, tuple) and len(queue) == 4 and queue[0:2] == ('/usr/sbin/postqueue', '-c') and queue[3] == '-j':
        directory = queue[2]
    else:
        raise ValueError('monitor_environment_legacy_queue')
    cert = values.get('certificate')
    if not isinstance(cert, tuple) or len(cert) != 6 or cert[:3] != ('/usr/bin/openssl', 'x509', '-in') or cert[4:] != ('-noout', '-enddate'):
        raise ValueError('monitor_environment_legacy_certificate')
    match = re.fullmatch(r'/etc/letsencrypt/live/([^/]+)/fullchain.pem', cert[3])
    if not match: raise ValueError('monitor_environment_legacy_certificate_path')
    return monitor_validate({'format':1, 'queue_config_directory':directory, 'certificate_lineage':match[1]})


def initial(site):
    return monitor_validate({'format':1, 'queue_config_directory':'/etc/mail-management-operations-v1/postfix',
                             'certificate_lineage':site['mail_host']})


def adoption(live, exists, root='/'):
    if exists(MONITOR_CONFIG):
        raw = trusted(*live(MONITOR_CONFIG))
        monitor_targets(monitor_decode(raw), root)
        return None  # Existing bytes remain site-owned, including whitespace.
    value = discover(trusted(*live(RUNTIME)))
    monitor_targets(value, root)
    return monitor_encode(value)


def update(live):
    try: raw, metadata = live(MONITOR_CONFIG)
    except FileNotFoundError as error:
        raise ValueError('monitor_environment_explicit_migration_required') from error
    monitor_decode(trusted(raw, metadata))
    return metadata
