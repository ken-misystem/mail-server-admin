"""Explicit root-only publication after isolated UI enrollment and passkey verification."""
import json
import os
from pathlib import Path
import re

from host_transaction import Commands, Files, Transaction, durable_json, regular
from host_install import Installer
from setup_access import ACCESS, STATE, GUARD, WEB, LOCAL_WEB, PUBLIC_WEB, access_metadata


def close_barriers(installer):
    from host_install import plan, BASE_SERVICES
    from setup_access import guarded_units
    units = guarded_units(plan(installer.product, installer.site)['units'], BASE_SERVICES)
    triggers = [name for name in units if name.endswith(('.socket', '.timer'))]
    installer.commands.run('close_publication_triggers', ['/usr/bin/systemctl', 'stop', '--quiet', *triggers])
    installer.commands.run('close_publication_barriers', ['/usr/bin/systemctl', 'stop', '--quiet',
                           'mail-platform-setup-ui-approved.service', GUARD])
    concrete = [name for name in units if '@.' not in name]
    observed = installer.commands.run('closed_publication_states', ['/usr/bin/systemctl', 'show', *concrete,
                                      '-p', 'Id,ActiveState,SubState,MainPID,Job'])
    if any(line in (b'ActiveState=active', b'ActiveState=activating') for line in observed.splitlines()):
        raise ValueError('publication_close_incomplete')


def root_json(path):
    raw, metadata = regular(path)
    if metadata['uid'] != 0 or metadata['mode'] & 0o022:
        raise ValueError('setup_private_state_trust')
    return json.loads(raw)


def administrator_operation(commands, access, action, password=None, repeat=None):
    value = {'action': action, 'administrator': access['administrator']}
    if action != 'check':
        value.update(password=password, repeat=repeat)
    raw = commands.run('setup_administrator_'+action, ['/usr/bin/php8.4', '-d', 'display_errors=0',
                       '-d', 'log_errors=0', '/usr/local/lib/mail-platform-update/bootstrap_access_admin.php'],
                       (json.dumps(value)+'\n').encode())
    result = json.loads(raw)
    if result.get('status') != 'ok':
        raise ValueError('setup_administrator_operation')
    return result['administrator']


def execute(product, site, evidence, action, password, repeat, confirm_host=None):
    if os.name != 'posix' or os.geteuid() != 0:
        raise ValueError('Debian_root_required')
    if action not in ('publish', 'reissue'):
        raise ValueError('setup_action')
    import fcntl
    lock = os.open('/run/lock/mail-platform-install.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(lock)
        if info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
            raise ValueError('installation_lock_attributes')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state, access = root_json(STATE), root_json(ACCESS)
        if state.get('phase') != 'setup' or state.get('site') != site:
            raise ValueError('isolated_setup_required')
        if action == 'publish' and confirm_host != site['mail_host']:
            raise ValueError('publication_host_confirmation_required')
        evidence = Path(evidence)
        if not evidence.is_absolute() or evidence.exists():
            raise ValueError('new_evidence_directory_required')
        for parent in evidence.parents:
            info = parent.lstat()
            if parent.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('setup_evidence_parent_trust')
        transaction = Transaction(evidence)
        commands = Commands(evidence)
        if action == 'reissue':
            if access.get('phase') != 'setup':
                raise ValueError('temporary_access_already_completed')
            administrator = administrator_operation(commands, access, 'reissue', password, repeat)
            durable_json(ACCESS, access_metadata(administrator), mode=0o640, gid=regular(ACCESS)[1]['gid'])
            transaction.finish('complete', action='initial_access_reissue')
            return {'status': 'complete', 'phase': 'isolated_setup', 'evidence': str(evidence)}
        administrator_operation(commands, access, 'check')
        receipt = root_json('/var/lib/mail-platform-update/installed-code.json')
        for name, expected in receipt['code'].items():
            if regular(name)[1] != expected:
                raise ValueError('setup_installed_code_drift')
        nginx, metadata = regular(WEB)
        if nginx.decode().count(LOCAL_WEB) != 1 or PUBLIC_WEB in nginx.decode():
            raise ValueError('isolated_web_configuration_changed')
        installer = Installer(product, site, '/unused', evidence)
        installer.ids = receipt['identities']
        installer.files, installer.commands = Files('/', evidence), commands
        installer.transaction = transaction
        try:
            if access.get('phase') != 'complete':
                administrator = administrator_operation(commands, access, 'complete', password, repeat)
                durable_json(ACCESS, {'format': 1, 'phase': 'complete', 'administrator': administrator},
                             mode=0o640, gid=regular(ACCESS)[1]['gid'])
            durable_json(STATE, {'format': 1, 'phase': 'activating', 'site': site,
                                 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()})
            commands.run('open_publication_barrier', ['/usr/bin/systemctl', 'start', GUARD])
            installer.activate_public_services()
            installer.files.write(WEB, nginx.replace(LOCAL_WEB.encode(), PUBLIC_WEB.encode()),
                                  metadata['mode'], metadata['uid'], metadata['gid'])
            commands.run('public_nginx_syntax', ['/usr/sbin/nginx', '-t'])
            # nginx cannot replace a loopback-bound socket with a wildcard during reload.
            commands.run('public_nginx_restart', ['/usr/bin/systemctl', 'restart', 'nginx.service'])
            installer.public_health()
            durable_json(STATE, {'format': 1, 'phase': 'published', 'site': site})
            transaction.finish('complete', action='explicit_publication')
            return {'status': 'complete', 'phase': 'published', 'evidence': str(evidence)}
        except Exception as error:
            failure = {'exception': type(error).__name__,
                       'reason': str(error) if isinstance(error, ValueError) else 'operation_failed',
                       'credentials_and_DB_preserved': True}
            durable_json(evidence/'publication-failure.json', failure)
            arguments = getattr(error, 'record', {}).get('argv', [])
            if arguments and re.fullmatch(r'[A-Za-z0-9_.@-]+\.(?:service|socket|target|timer)', arguments[-1]):
                try:
                    commands.run('publication_failed_unit_state', ['/usr/bin/systemctl', 'show', arguments[-1],
                                 '-p', 'Id,LoadState,ActiveState,SubState,Result,ExecMainStatus,MainPID,Job'])
                    commands.run('publication_failed_unit_journal', ['/usr/bin/journalctl', '--no-pager',
                                 '-n', '60', '-o', 'json', '-u', arguments[-1], '-u', GUARD])
                except Exception as diagnostic:
                    durable_json(evidence/'publication-diagnostic-failure.json', {'exception':type(diagnostic).__name__})
            durable_json(STATE, {'format': 1, 'phase': 'failed', 'site': site})
            try:
                close_barriers(installer)
                restored = installer.files.restore()
            except Exception as recovery:
                restored = {'status': 'held', 'exception': type(recovery).__name__}
            durable_json(evidence/'publication-failure.json', dict(failure, restore=restored))
            if restored['status'] == 'restored':
                durable_json(STATE, {'format': 1, 'phase': 'setup', 'site': site})
                commands.run('restore_isolated_UI', ['/usr/bin/systemctl', 'start', 'nginx.service'])
            transaction.finish('failed', action='explicit_publication', recovery=restored)
            raise
    finally:
        os.close(lock)
