"""Explicit, journalled Roundcube migration with updater locking and Web drain."""
import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))

from generation_update import GenerationUpdate
from host_transaction import Commands, durable_json, regular
from release import sha
from roundcube_adoption import ReceiptAdoption, RECEIPT, bound_payload
from install_preparation import read_payload
from roundcube_migration import SettingsMigration, require_web_quiet

FPM = 'php8.4-fpm.service'
NGINX = 'nginx.service'
UPDATE_TIMER = 'mail-platform-update.timer'
PROTECTED = ('postfix.service', 'dovecot.service', 'mariadb.service', 'rspamd.service',
             'mail-client-cert-gate.service', 'mail-client-cert-postfix-backend.service')
HELPERS = ('roundcube_migration.py', 'roundcube_plugins.py',
           'roundcube_adoption.py', 'roundcube_rollout.py')


class SettingsRollout:
    def __init__(self, root, evidence, commands=None):
        self.root = Path(root)
        self.evidence = Path(evidence)
        self.commands = commands or Commands(evidence)
        self.commands.sequence = len(list(self.evidence.glob('[0-9][0-9][0-9][0-9]-*.json')))
        self.component = SettingsMigration(root, self.evidence/'component')
        self.adoption = ReceiptAdoption(root, self.evidence/'adoption')
        self.plan_path = self.evidence/'plan.json'
        self.state_path = self.evidence/'rollout.json'

    @contextmanager
    def locked(self):
        directory = self.component.files.target('/run/lock')
        directory.mkdir(mode=0o755, parents=True, exist_ok=True)
        paths = [self.component.files.target('/run/lock/mail-settings-rollout.lock')]
        updater = self.component.files.target('/var/lib/mail-platform-update')
        if os.path.lexists(updater):
            info = updater.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('roundcube_updater_directory_attributes')
            paths.append(updater/'update.lock')
        descriptors = []
        try:
            for path in paths:
                descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
                descriptors.append(descriptor)
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
                    raise ValueError('roundcube_update_lock_attributes')
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise ValueError('roundcube_update_busy')
            yield
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def unit(self, name, allow_missing=False):
        raw = self.commands.run('inspect_' + name.replace('-', '_').replace('.', '_'),
            ['/usr/bin/systemctl', 'show', name, '-p',
             'LoadState,ActiveState,SubState,MainPID,Job,InvocationID'])
        value = dict(line.split('=', 1) for line in raw.decode().splitlines())
        durable_json(self.evidence/('unit-' + name + '.json'), value)
        if allow_missing and value.get('LoadState') == 'not-found':
            value.setdefault('MainPID', '0')
            value.setdefault('InvocationID', '')
            if value.get('ActiveState') == 'inactive' and value.get('Job') in ('', '0'):
                return value
        if name.endswith('.timer'):
            value.setdefault('MainPID', '0')
        if not {'LoadState', 'ActiveState', 'SubState', 'MainPID', 'Job', 'InvocationID'} <= value.keys():
            raise ValueError('roundcube_unit_observation_incomplete')
        if value['Job'] not in ('', '0') or value['LoadState'] != 'loaded':
            raise ValueError('roundcube_unit_not_settled_' + name)
        return value

    def inventory(self, component_only=False):
        values = {name: self.unit(name, allow_missing=component_only and name == UPDATE_TIMER)
                  for name in (FPM, UPDATE_TIMER, NGINX, *PROTECTED)}
        if component_only:
            service = self.unit('mail-platform-update.service', allow_missing=True)
            if service['LoadState'] != 'not-found' or values[UPDATE_TIMER]['LoadState'] != 'not-found':
                raise ValueError('roundcube_component_only_updater_present')
        return values

    def nginx_configuration(self):
        raw = self.commands.run('nginx_configuration', ['/usr/sbin/nginx', '-T'])
        for line in raw.decode().splitlines():
            line = line.split('#', 1)[0].strip()
            if 'worker_shutdown_timeout' not in line:
                continue
            match = re.fullmatch(r'worker_shutdown_timeout\s+(\d+)(ms|s|m|h|d)?\s*;', line)
            if match is None:
                raise ValueError('roundcube_nginx_drain_budget_unverified')
            scale = {'ms': 0.001, 's': 1, 'm': 60, 'h': 3600, 'd': 86400, None: 0.001}
            seconds = int(match[1]) * scale[match[2]]
            if seconds != 0 and seconds < 65:
                raise ValueError('roundcube_nginx_drain_budget_too_short')
        return sha(raw)

    def wait_FastCGI_quiet(self, path):
        deadline = time.monotonic()+60
        while True:
            lines = Path('/proc/net/unix').read_text().splitlines()[1:]
            active = [line for line in lines if len(line.split()) == 8
                      and line.split()[7] == path and line.split()[5] == '03']
            if not active:
                return
            if time.monotonic() >= deadline:
                raise ValueError('roundcube_FastCGI_requests_pending')
            time.sleep(0.1)

    def write_state(self, state):
        durable_json(self.state_path, state)

    def prepare(self, payload, previous_recipe, peer, hostname, fpm_socket, component_only=False):
        if self.plan_path.exists():
            raise ValueError('roundcube_rollout_already_prepared')
        self.evidence.mkdir(mode=0o700)
        with self.locked():
            actual = self.commands.run('hostname', ['/usr/bin/hostname', '-f']).decode().strip()
            if actual != hostname:
                raise ValueError('roundcube_hostname_mismatch')
            # Generation copies need their own route transition. This component targets
            # the direct OS FPM installed by the standard installer.
            availability = self.root/'etc/mail-platform/availability.json'
            if availability.exists() and any(item['kind'] == 'web'
                    for item in json.loads(regular(availability)[0])['components'].values()):
                raise ValueError('roundcube_generation_route_migration_required')
            pending = self.root/'var/lib/mail-platform-update/transaction.json'
            if pending.exists() and json.loads(regular(pending)[0])['phase'] not in ('complete', 'rolled_back'):
                raise ValueError('roundcube_unfinished_update')
            before = self.inventory(component_only)
            if before[FPM]['ActiveState'] != 'active' or before[FPM]['SubState'] != 'running':
                raise ValueError('roundcube_FPM_baseline')
            if before[NGINX]['ActiveState'] != 'active' or before[NGINX]['SubState'] != 'running':
                raise ValueError('roundcube_nginx_baseline')
            nginx_digest = self.nginx_configuration()
            if not Path(fpm_socket).is_absolute() or not str(fpm_socket).startswith('/run/') or '..' in Path(fpm_socket).parts:
                raise ValueError('roundcube_FPM_socket_path')
            extras = {}
            receipt = None
            if component_only:
                if any(os.path.lexists(self.component.files.target(name)) for name in (
                        RECEIPT, '/var/lib/mail-platform-update/installed.json',
                        '/etc/mail-platform/availability.json')):
                    raise ValueError('roundcube_component_only_receipt_present')
                files = read_payload(payload)
            else:
                receipt = json.loads(regular(self.component.files.target(RECEIPT))[0])
                if peer != receipt['site']['mail_host']:
                    raise ValueError('roundcube_site_TLS_peer_mismatch')
                files = bound_payload(payload, receipt)
                extras['/integration/roundcube-settings.json'] = files['integration/roundcube-settings.json']
                for name in HELPERS:
                    target = 'usr/local/lib/mail-platform-update/' + name
                    extras['/' + target] = files[target]
            (self.evidence/'component').mkdir(mode=0o700)
            self.component.prepare(files, peer, extra_targets=extras,
                                   owned_before=receipt['code'] if receipt else None)
            adopted = None
            if receipt:
                adopted = self.adoption.prepare(payload, previous_recipe,
                    json.loads((self.evidence/'component/migration.json').read_bytes()))
            staged = {path.relative_to(self.evidence).as_posix(): regular(path)[1]
                      for folder in ('component/stage', 'adoption')
                      for path in sorted((self.evidence/folder).glob('*')) if path.is_file()}
            staged['component/migration.json'] = regular(self.evidence/'component/migration.json')[1]
            plan = {'format': 1, 'hostname': hostname, 'FPM_socket': str(fpm_socket),
                    'before_units': before, 'prepared_files': staged, 'adoption': adopted,
                    'component_only': component_only,
                    'nginx_configuration_sha256': nginx_digest}
            durable_json(self.plan_path, plan)
            self.write_state({'phase': 'prepared', 'operation_started': None, 'published': False})
        return {'phase': 'prepared', 'plan_sha256': regular(self.plan_path)[1]['sha256']}

    def operation(self, state, action, name):
        state['operation_started'] = {'action': action, 'unit': name}
        self.write_state(state)
        arguments = ['/usr/bin/systemctl', action, '--quiet', name]
        if action == 'drain':
            arguments = ['/usr/bin/systemctl', 'kill', '--kill-whom=main', '--signal=SIGQUIT', name]
        self.commands.run(action, arguments, timeout=70)
        deadline = time.monotonic() + 60
        while True:
            observed = self.unit(name)
            wanted = 'inactive' if action in ('drain', 'stop') else 'active'
            if observed['ActiveState'] == wanted and (wanted == 'active' or observed['MainPID'] == '0'):
                break
            if time.monotonic() >= deadline:
                raise ValueError('roundcube_service_transition_timeout')
            time.sleep(0.1)
        state['operation_started'] = None
        state['last_' + name] = observed
        self.write_state(state)

    def verify_files(self):
        record = json.loads((self.evidence/'component/migration.json').read_bytes())
        for row in record['targets']:
            expected = {key: row[key] for key in ('sha256', 'mode', 'uid', 'gid')}
            if regular(self.component.files.target(row['path']))[1] != expected:
                raise ValueError('roundcube_rollout_file_drift')
        if (self.evidence/'adoption').exists():
            self.adoption.check()
        elif os.path.lexists(self.component.files.target(RECEIPT)):
            raise ValueError('roundcube_component_only_receipt_appeared')

    def probe(self, path):
        logical = self.root/str(path).lstrip('/')
        info = logical.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid not in (0, 33):
            raise ValueError('roundcube_FPM_socket_attributes')
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(5)
            connection.connect(str(logical))
            GenerationUpdate.fcgi_probe(connection, {
                'request': '/var/lib/roundcube/index.php', 'reply': 'name="_token"'})

    def apply(self, plan_sha256):
        with self.locked():
            if regular(self.plan_path)[1]['sha256'] != plan_sha256:
                raise ValueError('roundcube_approved_plan_mismatch')
            state = json.loads(self.state_path.read_bytes())
            if state['phase'] != 'prepared':
                raise ValueError('roundcube_rollout_phase')
            plan = json.loads(self.plan_path.read_bytes())
            actual = self.commands.run('hostname', ['/usr/bin/hostname', '-f']).decode().strip()
            if actual != plan['hostname'] or self.inventory(plan['component_only']) != plan['before_units']:
                raise ValueError('roundcube_rollout_baseline_drift')
            if self.nginx_configuration() != plan['nginx_configuration_sha256']:
                raise ValueError('roundcube_nginx_configuration_drift')
            for name, attributes in plan['prepared_files'].items():
                if regular(self.evidence/name)[1] != attributes:
                    raise ValueError('roundcube_prepared_evidence_drift')
            migration = json.loads((self.evidence/'component/migration.json').read_bytes())
            for row in migration['targets']:
                if self.component.snapshot(row['path']) != row['before']:
                    raise ValueError('roundcube_live_precondition_drift')
            if plan['component_only']:
                if os.path.lexists(self.component.files.target(RECEIPT)):
                    raise ValueError('roundcube_component_only_receipt_appeared')
            else:
                adoption = json.loads((self.evidence/'adoption/adoption.json').read_bytes())
                if regular(self.component.files.target(RECEIPT))[1] != adoption['before']:
                    raise ValueError('roundcube_live_receipt_drift')
            state['phase'] = 'applying'
            self.write_state(state)
            try:
                if plan['before_units'][UPDATE_TIMER]['ActiveState'] == 'active':
                    self.operation(state, 'stop', UPDATE_TIMER)
                self.operation(state, 'drain', NGINX)
                self.wait_FastCGI_quiet(plan['FPM_socket'])
                self.operation(state, 'drain', FPM)
                require_web_quiet()
                self.component.activate()
                if not plan['component_only']:
                    self.adoption.activate()
                self.verify_files()
                self.commands.run('FPM_syntax', ['/usr/sbin/php-fpm8.4', '-t'])
                self.component.mark_published()
                state['published'] = True
                state['phase'] = 'publishing'
                self.write_state(state)
                self.operation(state, 'start', FPM)
                self.probe(plan['FPM_socket'])
                self.operation(state, 'start', NGINX)
                for name in PROTECTED:
                    if self.unit(name) != plan['before_units'][name]:
                        raise ValueError('roundcube_protected_service_drift')
                self.verify_files()
                if plan['before_units'][UPDATE_TIMER]['ActiveState'] == 'active':
                    self.operation(state, 'start', UPDATE_TIMER)
                state['phase'] = 'complete'
                self.write_state(state)
                return {'phase': 'complete', 'mail_services_preserved': True}
            except Exception as error:
                failure = {'class': type(error).__name__, 'reason': str(error),
                           'traceback': traceback.format_exc()}
                durable_json(self.evidence/'failure.json', failure)
                state['failure'] = {'class': type(error).__name__}
                self.write_state(state)
                recovery = self.recover_locked()
                durable_json(self.evidence/'failure-recovery.json', recovery)
                raise

    def recover_locked(self):
        state = json.loads(self.state_path.read_bytes())
        plan = json.loads(self.plan_path.read_bytes())
        component = json.loads((self.evidence/'component/migration.json').read_bytes())
        if state['published'] or component['phase'] in ('published', 'held_published') or state['operation_started']:
            return {'phase': 'held', 'reason': 'published_or_uncertain_operation'}
        # A preflight prevents receipt/file divergence when an unknown writer intervened.
        for folder in ('component', 'adoption'):
            for entry in sorted((self.evidence/folder).glob('file-entry-*.json')):
                row = json.loads(entry.read_bytes())
                try:
                    current = regular(self.component.files.target(row['path']))[1]
                except (OSError, ValueError):
                    return {'phase': 'held', 'reason': 'unknown_file_change'}
                if row['phase'] != 'written' or current != row['after']:
                    return {'phase': 'held', 'reason': 'unknown_file_change'}
        link_receipt = self.evidence/'component/plugin-links.json'
        if link_receipt.exists():
            for row in json.loads(link_receipt.read_bytes())['entries']:
                try:
                    current = self.component.links.link_state(self.component.links.path(row['path']))
                except ValueError:
                    return {'phase': 'held', 'reason': 'unknown_plugin_link'}
                expected = row['after'] if row['before'] is None else row['before']
                if current != expected or expected is None:
                    return {'phase': 'held', 'reason': 'unknown_plugin_link'}
        nginx = self.unit(NGINX)
        expected_nginx = state.get('last_' + NGINX, plan['before_units'][NGINX])
        if nginx != expected_nginx:
            return {'phase': 'held', 'reason': 'unknown_nginx_state'}
        current = self.unit(FPM)
        if current['ActiveState'] not in ('active', 'inactive'):
            return {'phase': 'held', 'reason': 'unknown_FPM_state'}
        if current['ActiveState'] == 'active':
            # Before drain, no files can have changed. A running FPM with file journals
            # requires inspection and cannot be treated as a safe unpublished rollback.
            if list((self.evidence/'component').glob('file-entry-*.json')):
                return {'phase': 'held', 'reason': 'unexpected_Web_restart'}
            if current != json.loads(self.plan_path.read_bytes())['before_units'][FPM]:
                return {'phase': 'held', 'reason': 'unknown_FPM_state'}
        else:
            require_web_quiet()
            restored = self.component.restore()
            if restored['phase'] != 'restored':
                return {'phase': 'held', 'reason': 'component_recovery_held'}
            if (self.evidence/'adoption').exists() and self.adoption.restore()['status'] != 'restored':
                return {'phase': 'held', 'reason': 'receipt_recovery_held'}
            self.operation(state, 'start', FPM)
        if self.unit(NGINX) != nginx:
            return {'phase': 'held', 'reason': 'unknown_nginx_state'}
        if nginx['ActiveState'] == 'inactive':
            self.operation(state, 'start', NGINX)
        if plan['before_units'][UPDATE_TIMER]['ActiveState'] == 'active':
            self.operation(state, 'start', UPDATE_TIMER)
        state['phase'] = 'restored'
        self.write_state(state)
        return {'phase': 'restored', 'mail_and_user_state_preserved': True}

    def recover(self):
        with self.locked():
            return self.recover_locked()


def main():
    parser = argparse.ArgumentParser(description='Explicit Roundcube plugin rollout')
    parser.add_argument('operation', choices=('prepare', 'apply', 'restore'))
    parser.add_argument('--root', type=Path, default=Path('/'))
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--payload', type=Path)
    parser.add_argument('--previous-recipe', type=Path)
    parser.add_argument('--peer')
    parser.add_argument('--hostname')
    parser.add_argument('--FPM-socket', default='/run/php/php8.4-fpm.sock')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--plan-sha256')
    parser.add_argument('--component-only', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    if os.geteuid() != 0 or not args.root.is_absolute() or not args.evidence.is_absolute():
        raise ValueError('roundcube_rollout_root_context')
    if args.operation != 'prepare':
        info = args.evidence.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('roundcube_rollout_evidence_permissions')
    rollout = SettingsRollout(args.root, args.evidence)
    if args.operation == 'prepare':
        if None in (args.payload, args.peer, args.hostname) or not args.component_only and args.previous_recipe is None:
            raise ValueError('roundcube_rollout_preparation_arguments')
        previous = regular(args.previous_recipe)[0] if args.previous_recipe else None
        result = rollout.prepare(args.payload, previous, args.peer,
                                 args.hostname, args.FPM_socket, args.component_only)
    else:
        if not args.apply or args.operation == 'apply' and not args.plan_sha256:
            raise ValueError('roundcube_rollout_explicit_apply_required')
        result = rollout.apply(args.plan_sha256) if args.operation == 'apply' else rollout.recover()
    print(json.dumps(result))


if __name__ == '__main__':
    main()
