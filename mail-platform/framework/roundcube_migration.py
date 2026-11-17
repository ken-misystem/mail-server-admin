"""Prepare and activate the settings plugin with retained files and CAS recovery."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))

from host_transaction import Files, durable_json, regular
from roundcube_core import render as render_core
from roundcube_plugins import PluginLinks, SOURCE, WEB
from roundcube_settings import POLICY

CONFIG = '/etc/roundcube/config.inc.php'
PLUGIN = SOURCE.lstrip('/')+'/mail_settings/'
MARKER = b'// MI-SYSTEM mail_settings migration v1'


def _identity(path):
    info = path.stat()
    return [info.st_dev, info.st_ino]


def _mapped_ids_safe(raw):
    try:
        rows = [tuple(map(int, line.split())) for line in raw.splitlines()]
    except ValueError:
        return False
    if not rows or len(rows) > 16 or any(len(row) != 3 for row in rows):
        return False
    return all(inside >= 0 and outside >= 0 and length > 0
               and not any(outside <= uid < outside + length for uid in (0, 33))
               for inside, outside, length in rows)


def _separate_rootless_web(row, host):
    """Exclude only positively identified, separately rooted rootless containers.

    A different PID, UID or cgroup alone is insufficient. Host root/www-data
    must not be mapped into the container. Unknown or shared roots still block.
    """
    return (all(uid not in (0, 33) for uid in row['uids'])
            and row['root'] != host['root']
            and row['userns'] != host['userns']
            and row['mntns'] != host['mntns']
            and re.fullmatch(r'0::/user\.slice/user-([0-9]+)\.slice/user@\1\.service/'
                             r'[^\n]+/libpod-payload-[0-9a-f]{64}\n?', row['cgroup']) is not None
            and _mapped_ids_safe(row['uid_map']) and _mapped_ids_safe(row['gid_map']))


def _web_process(process):
    first = (process/'stat').read_text().rsplit(')', 1)[1].split()[19]
    command = (process/'comm').read_text().strip()
    if not command.startswith('php'):
        return None
    uids = [int(value) for value in next(line.split()[1:] for line in
            (process/'status').read_text().splitlines() if line.startswith('Uid:'))]
    if len(uids) != 4:
        raise ValueError('web_process_uid_format')
    row = {'pid':int(process.name), 'starttime':first, 'comm':command, 'uids':uids,
           'cgroup':(process/'cgroup').read_text(), 'root':_identity(process/'root'),
           'userns':_identity(process/'ns/user'), 'mntns':_identity(process/'ns/mnt'),
           'uid_map':(process/'uid_map').read_text(), 'gid_map':(process/'gid_map').read_text()}
    if (first != (process/'stat').read_text().rsplit(')', 1)[1].split()[19]
            or command != (process/'comm').read_text().strip()
            or row['cgroup'] != (process/'cgroup').read_text()
            or row['root'] != _identity(process/'root')
            or row['userns'] != _identity(process/'ns/user')
            or row['mntns'] != _identity(process/'ns/mnt')):
        raise ValueError('web_process_identity_changed')
    final_uids = [int(value) for value in next(line.split()[1:] for line in
                  (process/'status').read_text().splitlines() if line.startswith('Uid:'))]
    if (uids != final_uids or row['uid_map'] != (process/'uid_map').read_text()
            or row['gid_map'] != (process/'gid_map').read_text()):
        raise ValueError('web_process_identity_changed')
    return row


def require_web_quiet(evidence=None, *, allow_active=False):
    """Read-only process check; optionally persist facts before deciding.

    allow_active is for inventory BEFORE the service barrier only. Placement
    and recovery callers retain the default, which rejects remaining workers.
    """
    proc = Path('/proc')
    record = {'format':1, 'allow_active':allow_active, 'processes':[], 'errors':[]}
    host = {'root':_identity(Path('/')), 'userns':_identity(proc/'self/ns/user'),
            'mntns':_identity(proc/'self/ns/mnt')}
    record['host'] = host
    entries = list(proc.iterdir())
    if len(entries) > 4096:
        raise ValueError('web_process_inventory_bound')
    for process in entries:
        if not process.name.isdigit():
            continue
        try:
            row = _web_process(process)
            if row is None:
                continue
        except FileNotFoundError:
            # Ignore only a process that has actually exited. A missing field
            # of a live process must not silently bypass the barrier.
            if process.exists():
                record['errors'].append({'pid':int(process.name), 'reason':'live_process_field_missing'})
            continue
        except (OSError, ValueError, StopIteration, IndexError) as error:
            record['errors'].append({'pid':int(process.name), 'reason':type(error).__name__,
                                     'errno':getattr(error, 'errno', None)})
            continue
        relevant = row['comm'].startswith('php-fpm') or row['uids'][1] == 33
        row['classification'] = ('unrelated_php' if not relevant else
            'separate_rootless' if _separate_rootless_web(row, host) else 'blocking')
        record['processes'].append(row)
    if evidence is not None:
        durable_json(Path(evidence)/('web-processes-'+str(time.time_ns())+'.json'), record)
    if record['errors']:
        raise ValueError('roundcube_web_process_identity_unconfirmed')
    if not allow_active and any(row['classification'] == 'blocking' for row in record['processes']):
        raise ValueError('roundcube_web_workers_active')
    return record


def configuration(raw, peer):
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', peer):
        raise ValueError('roundcube_TLS_peer')
    if not raw.lstrip().startswith(b'<?php') or MARKER in raw:
        raise ValueError('roundcube_configuration_state')
    opening = b'\n<?php\n' if raw.rstrip().endswith(b'?>') else b'\n'
    block = '''// MI-SYSTEM mail_settings migration v1
if (!isset($config['plugins']) || !is_array($config['plugins'])) {
    throw new RuntimeException('Roundcube plugins configuration');
}
$config['plugins'] = array_values(array_diff($config['plugins'], ['managesieve']));
if (!in_array('mail_settings', $config['plugins'], true)) {
    $config['plugins'][] = 'mail_settings';
}
$config['mail_settings_enabled'] = true;
$config['mail_settings_sieve_peer_name'] = '%s';
''' % peer
    return raw+opening+block.encode()


class SettingsMigration:
    def __init__(self, root, evidence):
        self.root = Path(root)
        self.evidence = Path(evidence)
        self.files = Files(root, evidence)
        self.links = PluginLinks(root, self.evidence/'plugin-links.json')

    def snapshot(self, name):
        path = self.files.target(name)
        return regular(path)[1] if os.path.lexists(path) else None

    def prepare(self, payload, peer, extra_targets=None, owned_before=None):
        if (self.evidence/'migration.json').exists():
            raise ValueError('migration_already_prepared')
        targets = {}
        for name, raw in payload.items():
            if name.startswith(PLUGIN):
                if '..' in Path(name).parts or '\\' in name:
                    raise ValueError('migration_payload_path')
                before = self.snapshot('/'+name)
                if before is not None and (before['uid'] != 0 or before['mode'] & 0o022):
                    raise ValueError('existing_plugin_attributes')
                if (before is not None and before['sha256'] != hashlib.sha256(raw).hexdigest()
                        and (owned_before or {}).get('/'+name) != before):
                    raise ValueError('existing_plugin_drift')
                targets['/'+name] = raw
        if PLUGIN+'mail_settings.php' not in payload or not targets:
            raise ValueError('settings_plugin_missing')
        original, info = regular(self.files.target(CONFIG))
        if info['uid'] != 0 or info['mode'] & 0o022:
            raise ValueError('roundcube_configuration_attributes')
        desired = dict(payload)
        desired[POLICY] = b'{"format":1,"mode":"plugin"}'
        for name, raw in render_core(desired, lambda name: regular(self.files.target(name))).items():
            targets['/'+name] = raw
        for name, raw in (extra_targets or {}).items():
            allowed = ('/integration/roundcube-settings.json',
                       '/usr/local/lib/mail-platform-update/roundcube_migration.py',
                       '/usr/local/lib/mail-platform-update/roundcube_plugins.py',
                       '/usr/local/lib/mail-platform-update/roundcube_adoption.py',
                       '/usr/local/lib/mail-platform-update/roundcube_rollout.py')
            if name not in allowed:
                raise ValueError('migration_extra_target_scope')
            targets[name] = raw
        targets[CONFIG] = configuration(original, peer)
        state = self.links.link_state(self.links.path(WEB+'/mail_settings'))
        if state is not None and (state['target'] != SOURCE+'/mail_settings' or state['uid'] != 0):
            raise ValueError('roundcube_plugin_path_conflict')
        stage = self.evidence/'stage'
        stage.mkdir(mode=0o700)
        entries = []
        for index, (name, raw) in enumerate(targets.items()):
            data = stage/str(index)
            data.write_bytes(raw)
            os.chmod(data, 0o600)
            before = self.snapshot(name)
            entries.append({'path':name,'before':before,'stage':str(index),
                'sha256':hashlib.sha256(raw).hexdigest(),
                'mode':before['mode'] if before else 0o644,
                'uid':before['uid'] if before else 0,'gid':before['gid'] if before else 0})
            if name.endswith('.php'):
                result = subprocess.run(['/usr/bin/php8.4','-l',str(data)],capture_output=True,timeout=10)
                if result.returncode:
                    (self.evidence/('lint-'+str(index)+'.stdout')).write_bytes(result.stdout)
                    (self.evidence/('lint-'+str(index)+'.stderr')).write_bytes(result.stderr)
                    raise ValueError('migration_PHP_syntax')
        lock_directory = self.files.target('/var/lib/roundcube/mail-settings-locks')
        lock_before = self.lock_state(lock_directory)
        record = {'format':1,'phase':'prepared','targets':entries,'peer':peer,'link_before':state,
                  'lock_before':lock_before}
        durable_json(self.evidence/'migration.json',record)
        return {'phase':'prepared','files':len(entries),'PHP_syntax':'PASS'}

    def load(self):
        return json.loads((self.evidence/'migration.json').read_bytes())

    @staticmethod
    def lock_state(path):
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 33 or info.st_gid != 33 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('roundcube_lock_directory')
        return {'uid':info.st_uid,'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode),
                'inode':info.st_ino,'device':info.st_dev}

    def activate(self):
        require_web_quiet()
        record = self.load()
        if record['phase'] != 'prepared':
            raise ValueError('migration_phase')
        if self.links.link_state(self.links.path(WEB+'/mail_settings')) != record['link_before']:
            raise ValueError('migration_link_drift')
        for row in record['targets']:
            if self.snapshot(row['path']) != row['before']:
                raise ValueError('migration_precondition_drift')
            if hashlib.sha256((self.evidence/'stage'/row['stage']).read_bytes()).hexdigest() != row['sha256']:
                raise ValueError('migration_stage_drift')
        lock_directory = self.files.target('/var/lib/roundcube/mail-settings-locks')
        if self.lock_state(lock_directory) != record['lock_before']:
            raise ValueError('roundcube_lock_directory_changed')
        if record['lock_before'] is None:
            lock_directory.mkdir(mode=0o700)
            os.chown(lock_directory,33,33)
        record['phase'] = 'activating'
        durable_json(self.evidence/'migration.json', record)
        try:
            for row in record['targets']:
                require_web_quiet()
                raw = (self.evidence/'stage'/row['stage']).read_bytes()
                self.files.write(row['path'],raw,row['mode'],row['uid'],row['gid'])
                if row['path'] == CONFIG:
                    self.links.apply(['mail_settings'])
            record['phase'] = 'active'
            durable_json(self.evidence/'migration.json', record)
        except Exception:
            record['phase'] = 'failed'
            durable_json(self.evidence/'migration.json', record)
            raise
        return {'phase':'active','files':len(record['targets'])}

    def restore(self):
        require_web_quiet()
        record = self.load()
        if record['phase'] in ('published', 'held_published'):
            record['phase'] = 'held_published'
            durable_json(self.evidence/'migration.json', record)
            return {'phase':'held','reason':'published_state_requires_review','held_links':[],
                    'held_files':[row['path'] for row in record['targets']]}
        self.files.entries = [json.loads(path.read_bytes()) for path in sorted(self.evidence.glob('file-entry-*.json'))]
        links = self.links.restore()
        files = self.files.restore()
        record = self.load()
        record['phase'] = 'held' if links['held'] or files['held_paths'] else 'restored'
        durable_json(self.evidence/'migration.json', record)
        return {'phase':record['phase'],'held_links':links['held'],'held_files':files['held_paths']}

    def mark_published(self):
        record = self.load()
        if record['phase'] != 'active':
            raise ValueError('migration_phase')
        record['phase'] = 'published'
        durable_json(self.evidence/'migration.json', record)
        return {'phase':'published'}


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Roundcube settings component migration')
    parser.add_argument('operation', choices=('prepare','activate','mark-published','restore'))
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--payload', type=Path)
    parser.add_argument('--peer')
    arguments = parser.parse_args()
    if os.geteuid() != 0 or not arguments.root.is_absolute() or not arguments.evidence.is_absolute():
        raise ValueError('migration_root_context')
    if arguments.operation == 'prepare':
        if arguments.evidence.exists() or arguments.payload is None or arguments.peer is None:
            raise ValueError('migration_preparation_arguments')
        arguments.evidence.mkdir(mode=0o700)
    info = arguments.evidence.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('migration_evidence_attributes')
    migration = SettingsMigration(arguments.root, arguments.evidence)
    if arguments.operation == 'prepare':
        from install_preparation import read_payload
        result = migration.prepare(read_payload(arguments.payload),arguments.peer)
    elif arguments.operation == 'activate':
        result = migration.activate()
    elif arguments.operation == 'mark-published':
        result = migration.mark_published()
    else:
        result = migration.restore()
    print(json.dumps(result))


if __name__ == '__main__':
    main()
