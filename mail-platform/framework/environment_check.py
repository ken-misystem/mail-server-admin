"""Read-only fresh-host checks, before credentials, package changes or service changes."""
from collections import defaultdict
import fnmatch
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
try:
    import grp
    import pwd
except ImportError:
    grp = pwd = None

from base_configuration import render as base_files
from configuration_templates import templates
from host_transaction import durable_json


APPLICATION_PACKAGES = (
    'postfix*', 'exim4*', 'sendmail*', 'dovecot*', 'mariadb-server*', 'mysql-server*',
    'percona-server*', 'redis-server', 'rspamd', 'roundcube*', 'nginx*', 'apache2*',
    'lighttpd', 'caddy', 'php*-fpm', 'postsrsd', 'fail2ban', 'ufw',
)
APPLICATION_UNITS = re.compile(
    r'^(?:postfix(?:@[^ ]*)?|exim4|sendmail|dovecot|mariadb|mysql|redis(?:-server)?|rspamd|'
    r'nginx|apache2|httpd|lighttpd|caddy|php[0-9.]+-fpm|postsrsd|fail2ban|ufw)\.(?:service|socket)$')
PORTS = frozenset((25, 110, 143, 443, 465, 587, 993, 995, 3306, 4190, 6379,
                   10001, 10002, 10027, 11332, 11333, 11334))
SHARED_DIRECTORIES = ('/etc', '/etc/systemd/system', '/usr', '/usr/local', '/usr/local/lib',
                      '/usr/local/sbin', '/usr/share', '/opt', '/var', '/var/lib',
                      '/var/log', '/var/spool', '/var/www', '/run', '/run/lock')
RESERVED_DIRECTORIES = ('/var/vmail', '/var/lib/mysql', '/var/lib/redis', '/var/lib/roundcube',
                        '/var/lib/rspamd', '/var/spool/postfix', '/etc/postfix', '/etc/dovecot',
                        '/etc/nginx', '/etc/roundcube', '/etc/rspamd', '/etc/redis',
                        '/etc/mysql', '/etc/ufw', '/etc/fail2ban', '/etc/php',
                        '/var/lib/mail-platform-install', '/var/lib/mail-platform-setup',
                        '/usr/local/lib/mail-platform-setup', '/etc/mail-platform',
                        '/var/lib/mail-platform-update', '/var/www/mail-admin')


def destinations(product, site):
    """Use the package inventory and pure configuration renderer for destination paths."""
    payload = Path(product)/'payload'
    paths = set(RESERVED_DIRECTORIES)
    recipes = json.loads((payload/'blueprint/install-recipes.json').read_bytes())
    recipes['management_entry'] = ''
    for resource in base_files(site, {'vmail.uid': 5000}, defaultdict(lambda: '0'*64), recipes):
        paths.add(resource.path)
    paths.update(template.path for template in templates(site))
    units = set()
    for path in payload.rglob('*'):
        if path.is_symlink():
            raise ValueError('environment_payload_link')
        if not path.is_file():
            continue
        relative = path.relative_to(payload)
        if relative.parts[:2] == ('blueprint', 'systemd'):
            units.add(path.name)
            paths.add('/etc/systemd/system/'+path.name)
            for line in path.read_text().splitlines():
                if line.startswith(('ListenStream=/', 'ListenDatagram=/')):
                    paths.add(line.split('=', 1)[1])
        elif relative.parts[0] != 'blueprint' and relative.as_posix() != 'installer.py':
            paths.add('/'+relative.as_posix())
    # Dedicated application/state/runtime trees are reserved even when empty.
    for path in list(paths):
        parts = Path(path).parts
        if len(parts) > 2 and parts[1] in ('etc', 'opt') and parts[2].startswith(('mail-', 'roundcube-auth')):
            paths.add('/'+ '/'.join(parts[1:3]))
        if len(parts) > 3 and parts[1:3] in (('var', 'lib'), ('var', 'log'), ('var', 'spool')) and parts[3].startswith('mail-'):
            paths.add('/'+ '/'.join(parts[1:4]))
        if len(parts) > 4 and parts[1:4] == ('usr', 'local', 'lib'):
            paths.add('/'+ '/'.join(parts[1:5]))
    paths.add('/usr/sbin/policy-rc.d')
    paths.update(('/etc/letsencrypt/live/'+site['mail_host']+'/'+name) for name in ('fullchain.pem', 'privkey.pem'))
    return sorted(paths), units


def command(arguments):
    try:
        process = subprocess.run(arguments, capture_output=True, timeout=20,
                                 env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    except FileNotFoundError:
        raise ValueError('environment_tool_missing_'+Path(arguments[0]).name) from None
    if process.returncode or process.stderr or len(process.stdout) > 4194304:
        raise ValueError('environment_command_failed_'+Path(arguments[0]).name)
    return process.stdout.decode('utf-8', 'strict')


def network_listeners(proc):
    result = []
    for name, family in (('tcp', 4), ('tcp6', 6)):
        path = proc/'net'/name
        if not path.exists() and family == 6:
            continue
        rows = path.read_text().splitlines()
        if not rows or 'local_address' not in rows[0]:
            raise ValueError('environment_TCP_table')
        for row in rows[1:]:
            fields = row.split()
            if fields[3] != '0A':
                continue
            address, port = fields[1].split(':')
            raw = bytes.fromhex(address)
            # proc renders addresses as native-endian 32-bit words.
            raw = b''.join(raw[index:index+4][::(-1 if sys.byteorder == 'little' else 1)] for index in range(0, len(raw), 4))
            result.append({'address': str(ipaddress.ip_address(raw)), 'port': int(port, 16)})
    return result


def path_observations(paths, root=Path('/')):
    """lstat each parent before descending, without following a destination symlink."""
    observed = {}
    for name in sorted(set(paths)):
        current = root
        for part in Path(name).parts[1:]:
            current = current/part
            logical = '/'+str(current.relative_to(root)).replace('\\', '/')
            if logical not in observed:
                try:
                    info = current.lstat()
                except FileNotFoundError:
                    observed[logical] = {'exists': False}
                else:
                    kind = 'directory' if stat.S_ISDIR(info.st_mode) else 'file' if stat.S_ISREG(info.st_mode) else 'other'
                    if stat.S_ISLNK(info.st_mode):
                        kind = 'symlink'
                    observed[logical] = {'exists': True, 'kind': kind, 'uid': info.st_uid,
                                         'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode)}
                    if kind == 'directory':
                        observed[logical]['read_only'] = bool(os.statvfs(current).f_flag & os.ST_RDONLY)
            item = observed[logical]
            if not item['exists'] or item['kind'] != 'directory':
                break
    return observed


def evaluate(snapshot, reserved, product_units, users, evidence=None):
    findings = []
    def reject(category, item, reason, **facts):
        findings.append(dict(category=category, item=item, reason=reason, **facts))
    if snapshot['OS'] != {'ID': 'debian', 'VERSION_ID': '13'}:
        reject('OS', '/etc/os-release', 'Debian13_required')
    if snapshot['architecture'] != 'x86_64' or snapshot['uid'] != 0:
        reject('OS', 'process', 'amd64_root_required')
    if snapshot['init'] != 'systemd':
        reject('OS', '/proc/1/comm', 'systemd_required')
    for package in snapshot['packages']:
        if any(fnmatch.fnmatchcase(package, pattern) for pattern in APPLICATION_PACKAGES):
            reject('application', package, 'existing_application_package')
    for unit in snapshot['units']:
        if unit in product_units or APPLICATION_UNITS.fullmatch(unit):
            reject('application', unit, 'existing_application_unit')
    for listener in snapshot['listeners']:
        if listener['port'] in PORTS:
            reject('port', str(listener['port']), 'reserved_TCP_port_in_use', address=listener['address'])
    for kind in ('users', 'groups'):
        for name in users:
            if name in snapshot[kind]:
                reject('identity', name, 'existing_'+kind[:-1], numeric_id=snapshot[kind][name])
    paths = snapshot['paths']
    for name in reserved:
        if paths.get(name, {}).get('exists'):
            reject('path', name, 'existing_installation_destination')
    for name, value in paths.items():
        if not value['exists']:
            continue
        if value['kind'] == 'symlink':
            reject('permission', name, 'destination_or_parent_symlink')
        elif value['kind'] == 'directory':
            # The root-owned sticky lock directory is a standard system directory.
            sticky_lock = name == '/run/lock' and value['mode'] & stat.S_ISVTX
            if value['uid'] != 0 or (value['mode'] & 0o022 and not sticky_lock):
                reject('permission', name, 'untrusted_directory_owner_or_write_access', uid=value['uid'], mode=oct(value['mode']))
            if value['read_only']:
                reject('permission', name, 'read_only_destination_filesystem')
        elif name not in reserved:
            reject('path', name, 'parent_is_not_directory')
    if evidence is not None:
        directory = Path(evidence)
        if not directory.is_absolute() or '..' in directory.parts or paths.get(str(evidence), {}).get('exists'):
            reject('evidence', str(evidence), 'new_absolute_evidence_directory_required')
        parent = paths.get(str(directory.parent), {})
        if not parent.get('exists') or parent.get('kind') != 'directory':
            reject('evidence', str(directory.parent), 'existing_evidence_parent_directory_required')
        if any(directory == Path(name) or Path(name) in directory.parents for name in reserved):
            reject('evidence', str(evidence), 'evidence_overlaps_installation_destination')
    return {'format': 1, 'status': 'PASS' if not findings else 'REFUSED', 'findings': findings,
            'checked': {'destination_paths': len(reserved), 'observed_path_components': len(paths),
                        'TCP_listeners': len(snapshot['listeners']), 'packages': len(snapshot['packages']),
                        'unit_files': len(snapshot['units']), 'reserved_TCP_ports': sorted(PORTS)},
            'host_changes': False, 'secret_values_collected': False}


def inspect(product, site, users, evidence=None):
    reserved, units = destinations(product, site)
    paths = [*reserved, *SHARED_DIRECTORIES]
    if evidence is not None:
        paths.append(str(evidence))
    try:
        if os.name != 'posix' or os.geteuid() != 0:
            raise ValueError('Debian_root_required')
        release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
        packages = []
        for row in command(['/usr/bin/dpkg-query', '-W', '-f=${binary:Package}\t${db:Status-Abbrev}\n']).splitlines():
            name, status = row.split('\t')
            if status[1:2] == 'i':
                packages.append(name.split(':', 1)[0])
        unit_rows = command(['/usr/bin/systemctl', 'list-unit-files', '--no-legend', '--no-pager', '--plain'])
        identities = {'users': {}, 'groups': {}}
        for name in users:
            for kind, lookup, field in (('users', pwd.getpwnam, 'pw_uid'), ('groups', grp.getgrnam, 'gr_gid')):
                try:
                    identities[kind][name] = getattr(lookup(name), field)
                except KeyError:
                    pass
        snapshot = {'OS': {key: release.get(key, '').strip('"') for key in ('ID', 'VERSION_ID')},
                    'architecture': os.uname().machine, 'uid': os.geteuid(),
                    'init': Path('/proc/1/comm').read_text().strip(), 'packages': packages,
                    'units': [line.split()[0] for line in unit_rows.splitlines()],
                    'listeners': network_listeners(Path('/proc')),
                    'paths': path_observations(paths), **identities}
        return evaluate(snapshot, reserved, units, users, evidence)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        return {'format': 1, 'status': 'REFUSED', 'findings': [{'category': 'inspection',
                'reason': str(error) if type(error) is ValueError else type(error).__name__}],
                'host_changes': False, 'secret_values_collected': False}


def save_report(directory, report):
    """Optional private evidence only, without changing application configuration."""
    directory = Path(directory)
    if any(row.get('category') == 'evidence' for row in report['findings']):
        raise ValueError('environment_evidence_path_refused')
    if not directory.is_absolute() or os.path.lexists(directory):
        raise ValueError('new_environment_evidence_directory_required')
    for parent in directory.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('environment_evidence_parent_trust')
    directory.mkdir(mode=0o700)
    durable_json(directory/'environment-check.json', report)


def record_report(directory, report):
    """Keep all findings available even when the requested evidence location is unsafe."""
    try:
        save_report(directory, report)
    except (OSError, ValueError) as error:
        report['evidence_error'] = str(error) if type(error) is ValueError else type(error).__name__
