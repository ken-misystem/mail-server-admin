"""Journal the one-time adoption of real FPM pools and the SQL policy frontend."""
from pathlib import Path
import json
import os
import re
import time
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from availability_plan import configuration
from generation_front import read_route
from generation_update import GenerationUpdate
from host_transaction import Commands, CommandFailure, Files, durable_json, regular
from release import canonical, sha
from policy_binding import DROPIN, CONTENT

STATE = Path('/var/lib/mail-platform-update')
CONFIG = Path('/etc/mail-platform/availability.json')
REGISTRATION = Path('/etc/mail-platform/site-generations.json')
BOOT_UNIT = 'mail-platform-site-generations.service'
LEGACY = ('mail-client-cert-owner.service', 'mail-client-cert-gate.socket', 'mail-client-cert-gate.service',
          'mail-client-cert-postfix-backend.service', 'mail-send-limits-v1.socket',
          'mail-send-limits-v1.service', 'php8.4-fpm.service')


def inspect(commands, name):
    raw = commands.run('site_unit', ['systemctl', 'show', name, '-p', 'ActiveState,SubState,MainPID,Job'])
    result = dict(line.split('=', 1) for line in raw.decode().splitlines())
    result.setdefault('MainPID', '0')
    return result


def health(directory, commands=None):
    """Fresh, non-accounting health through the installed component identities."""
    raw, metadata = regular(CONFIG)
    if metadata['uid'] != 0 or metadata['mode'] != 0o600:
        raise ValueError('site_generation_configuration_trust')
    config = configuration(json.loads(raw))
    engine = GenerationUpdate('/unused', directory, commands=commands)
    for item in config['components'].values():
        engine.probe({'configuration': item}, read_route(item['route']))
    return {'status': 'healthy', 'components': list(config['components'])}


def start_current(directory, operation=None, commands=None):
    registration, metadata = regular(REGISTRATION)
    if metadata['uid'] != 0 or metadata['mode'] != 0o600:
        raise ValueError('site_generation_registration_trust')
    registered = json.loads(registration)
    config = configuration(json.loads(regular(CONFIG)[0]))
    if sha(canonical(config)) != registered['configuration_sha256']:
        raise ValueError('site_generation_configuration_changed')
    for path, expected in registered['static_files'].items():
        if regular(path)[1] != expected:
            raise ValueError('site_generation_static_file_changed')
    commands = commands or Commands(directory)
    def start(unit):
        if operation is None:
            commands.run('site_start', ['systemctl', 'start', '--quiet', unit])
        else:
            operation('start', unit)
    started = set()
    for component in config['components'].values():
        route = read_route(component['route'])
        unit = component['unit'].replace('@.', '@'+route['generation']+'.')
        if unit in started:
            continue
        inventory = Path(config['generation_root'])/next(name for name, item in config['components'].items()
                      if item['unit'] == component['unit'])/route['generation']/'inventory.json'
        if not inventory.is_file():
            raise ValueError('site_generation_inventory_missing')
        root = inventory.parent/'root'
        for name, expected in json.loads(regular(inventory)[0]).items():
            if regular(root/name)[1] != expected:
                raise ValueError('site_generation_inventory_changed')
        start(unit)
        started.add(unit)
    for unit in registered['front_units']:
        start(unit)
    deadline = time.monotonic()+60
    while True:
        try:
            return health(directory, commands)
        except (OSError, ValueError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.5)


class SiteEnrollment:
    def __init__(self, directory):
        self.directory = Path(directory)
        if self.directory.parent != STATE or not self.directory.name.startswith('site-enrollment-'):
            raise ValueError('site_generation_transaction_scope')
        metadata = self.directory.stat()
        if self.directory.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o077:
            raise ValueError('site_generation_transaction_trust')
        self.commands = Commands(self.directory)
        self.files = Files('/', self.directory)
        self.record_path = self.directory/'site-enrollment.json'

    def save(self):
        durable_json(self.record_path, self.record)

    def operation(self, action, unit):
        observed = inspect(self.commands, unit)
        known = self.record['last_units'].get(unit)
        if observed['ActiveState'] == 'active' and (known is None or known.get('MainPID','0') != observed['MainPID']):
            raise ValueError('site_generation_unit_replaced')
        if action == 'stop' and known is None:
            raise ValueError('site_generation_unit_not_owned')
        self.record['operation_started'] = {'action': action, 'unit': unit}
        self.save()
        try:
            self.commands.run('site_'+action, ['systemctl', action, '--quiet', unit], timeout=90)
        except CommandFailure as error:
            failed = inspect(self.commands, unit)
            self.record['operation_failure'] = {'command': error.record, 'observed': failed}
            if (not error.record['timed_out'] and error.record['spawn_error'] is None
                    and failed['ActiveState'] in ('inactive','failed') and failed['MainPID']=='0'
                    and failed.get('Job','') in ('','[]','0')):
                self.record['operation_started'] = None
                self.record['last_units'][unit] = failed
            self.save()
            raise
        self.record['operation_started'] = None
        self.record['last_units'][unit] = inspect(self.commands, unit)
        for linked in list(self.record['last_units']):
            if linked == unit:
                continue
            current = inspect(self.commands, linked)
            old = self.record['last_units'][linked]
            if old['ActiveState'] == current['ActiveState'] == 'active' and old.get('MainPID','0') != current['MainPID']:
                raise ValueError('site_generation_linked_unit_replaced')
            if current['ActiveState'] != old['ActiveState']:
                self.record['last_units'][linked] = current
        self.save()

    def apply(self, config, resources, adopted_code):
        if CONFIG.exists() or REGISTRATION.exists() or self.record_path.exists():
            raise ValueError('site_generation_already_registered')
        config = configuration(config)
        if regular(DROPIN)[0] != CONTENT:
            raise ValueError('site_generation_stop_binding_requires_migration')
        raw, receipt_metadata = regular(STATE/'installed-code.json')
        receipt = json.loads(raw)
        if receipt_metadata['uid'] != 0 or receipt_metadata['mode'] != 0o600 or not receipt['version'].startswith('0.4.'):
            raise ValueError('site_generation_receipt')
        for name, expected in receipt['code'].items():
            if regular(name)[1] != expected:
                raise ValueError('site_generation_owned_code_changed')
        allowed = ('/etc/mail-platform/', '/etc/systemd/system/mail-platform-',
                   '/etc/systemd/system/php8.4-fpm.service.d/', '/etc/systemd/system/mail-send-limits-v1.service.d/')
        if any(not path.startswith(allowed) or '..' in Path(path).parts for path in resources):
            raise ValueError('site_generation_resource_scope')
        if any(not path.startswith('/usr/local/lib/mail-platform-update/') and path != '/usr/local/lib/mail-send-limits-v1/runtime.py' for path in adopted_code):
            raise ValueError('site_generation_code_scope')
        for root in {root for item in config['components'].values() for root in item['roots']}:
            source = Path(root)
            if not source.is_dir():
                raise ValueError('site_generation_code_directory')
            for path in (source, *source.rglob('*')):
                metadata = path.lstat()
                if path.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o022:
                    raise ValueError('site_generation_source_requires_review:'+str(path))
        before = {unit: inspect(self.commands, unit) for unit in LEGACY}
        for unit in ('php8.4-fpm.service', 'mail-send-limits-v1.socket', 'mail-client-cert-gate.service'):
            if before[unit]['ActiveState'] != 'active':
                raise ValueError('site_generation_initial_service_state')
        self.record = {'phase': 'prepared', 'before_units': before, 'last_units': dict(before),
                       'operation_started': None, 'old_receipt': receipt, 'directories': [],
                       'receipt_metadata': receipt_metadata, 'boot_enabled': False}
        self.save()
        generation = 'g'+receipt['version'].replace('.', 'x')
        for unit in LEGACY:
            if before[unit]['ActiveState'] == 'active':
                self.operation('stop', unit)
        for path, raw in adopted_code.items():
            self.files.write(path, raw, 0o644)
        for path, (raw, mode) in resources.items():
            self.files.write(path, raw, mode)
        self.files.write(str(CONFIG), canonical(config), 0o600)
        for name, component in config['components'].items():
            directory = Path(config['generation_root'])/name/generation
            directory.mkdir(parents=True, mode=0o755)
            os.chmod(directory, 0o755)
            self.record['directories'].append(str(directory))
            self.save()
            for root in component['roots']:
                destination = directory/'root'/root.lstrip('/')
                destination.parent.mkdir(parents=True, exist_ok=True)
                GenerationUpdate.snapshot(root, destination)
            inventory = {path.relative_to(directory/'root').as_posix(): regular(path)[1]
                         for path in (directory/'root').rglob('*') if path.is_file()}
            durable_json(directory/'inventory.json', inventory)
            if component['template']:
                config_raw, config_meta = regular(component['template'])
                target = directory/'fpm.conf'
                target.write_bytes(config_raw.replace(b'%i', generation.encode()))
                os.chmod(target, config_meta['mode'])
                self.commands.run('site_FPM_lint', ['php-fpm8.4', '-t', '-y', str(target)])
            self.files.write(component['route'], canonical({'generation': generation,
                'socket': component['runtime']+'/'+generation+'/backend.sock'}), 0o644)
        front_units = ['php8.4-fpm.service', 'mail-send-limits-v1.socket', 'mail-send-limits-v1.service']
        infrastructure = [path for path in receipt['code'] if path.startswith('/usr/local/lib/mail-platform-update/')]
        static = {path: regular(path)[1] for path in [*resources, *adopted_code, *infrastructure]
                  if path != '/usr/local/lib/mail-send-limits-v1/runtime.py'}
        self.files.write(str(REGISTRATION), canonical({'format': 1, 'front_units': front_units,
                         'static_files': static, 'configuration_sha256': sha(canonical(config))}), 0o600)
        self.commands.run('site_systemd_reload', ['systemctl', 'daemon-reload'])
        self.record['phase'] = 'starting'
        self.save()
        start_current(self.directory, self.operation, self.commands)
        for unit in ('mail-client-cert-postfix-backend.service', 'mail-client-cert-gate.socket',
                     'mail-client-cert-gate.service', 'mail-client-cert-owner.service'):
            if before[unit]['ActiveState'] == 'active':
                self.operation('start', unit)
        self.record['phase'] = 'healthy'
        self.save()
        current = dict(receipt, code=dict(receipt['code']))
        for path in adopted_code:
            current['code'][path] = regular(path)[1]
        self.files.write(str(STATE/'installed-code.json'), canonical(current), 0o600)
        self.commands.run('site_boot_enable', ['systemctl', 'enable', BOOT_UNIT])
        self.record['boot_enabled'] = True
        self.record['phase'] = 'complete'
        self.save()
        return {'phase': 'complete', 'version': receipt['version'], 'components': list(config['components'])}

    def rollback(self):
        self.record = json.loads(regular(self.record_path)[0])
        self.files.entries = [json.loads(path.read_bytes()) for path in sorted(self.directory.glob('file-entry-*.json'))]
        if self.record['operation_started']:
            raise ValueError('site_generation_operation_unknown')
        if self.record['phase'] == 'complete':
            raise ValueError('site_generation_published_recovery_requires_review')
        if not self.files.entries and not self.record['directories']:
            for unit in reversed(LEGACY):
                if self.record['before_units'][unit]['ActiveState']=='active' and inspect(self.commands,unit)['ActiveState']=='inactive':
                    self.operation('start',unit)
            self.record['phase']='rolled_back'
            self.save()
            return {'phase':'rolled_back','configuration_writes':0,'application_state_preserved':True}
        for unit in LEGACY:
            if inspect(self.commands, unit)['ActiveState'] == 'active':
                self.operation('stop', unit)
        if CONFIG.exists():
            config = configuration(json.loads(regular(CONFIG)[0]))
            units = {item['unit'].replace('@.', '@'+read_route(item['route'])['generation']+'.')
                     for item in config['components'].values()}
            for unit in units:
                self.operation('stop', unit)
        restored = self.files.restore()
        if restored['status'] != 'restored':
            raise ValueError('site_generation_restore_held')
        for name in self.record['directories']:
            directory = Path(name)
            if directory.is_symlink() or not directory.is_dir() or not str(directory).startswith('/var/lib/mail-platform-generations/'):
                raise ValueError('site_generation_retained_directory_scope')
            retained = directory.with_name(directory.name+'.retained-'+self.directory.name)
            if retained.exists():
                raise ValueError('site_generation_retained_directory_collision')
            directory.rename(retained)
        self.commands.run('site_restore_systemd', ['systemctl', 'daemon-reload'])
        for unit in reversed(LEGACY):
            if self.record['before_units'][unit]['ActiveState'] == 'active':
                self.operation('start', unit)
        self.record['phase'] = 'rolled_back'
        self.save()
        return {'phase': 'rolled_back', 'application_state_preserved': True}


def main():
    if os.geteuid() != 0:
        raise ValueError('site_generation_root_required')
    if sys.argv[1:2] in (['plan'], ['apply']):
        import argparse
        from site_configuration import prepare
        parser = argparse.ArgumentParser()
        parser.add_argument('action', choices=['plan','apply'])
        parser.add_argument('--payload', type=Path, required=True)
        args = parser.parse_args()
        if CONFIG.exists() or REGISTRATION.exists():
            raise ValueError('site_generation_already_registered')
        receipt = json.loads(regular(STATE/'installed-code.json')[0])
        config, resources, adopted = prepare(args.payload, receipt)
        preview = {'version':receipt['version'],'components':list(config['components']),
                   'configuration_sha256':sha(canonical(config)),
                   'resources':{path:{'sha256':sha(raw),'mode':mode} for path,(raw,mode) in resources.items()},
                   'adopted_code':{path:sha(raw) for path,raw in adopted.items()}}
        if args.action == 'plan':
            print(json.dumps({'phase':'planned', **preview}))
            return
        directory = STATE/('site-enrollment-'+str(time.time_ns()))
        directory.mkdir(mode=0o700)
        durable_json(directory/'plan.json', preview)
        engine = SiteEnrollment(directory)
        try:
            result = engine.apply(config, resources, adopted)
        except Exception as error:
            durable_json(directory/'failure.json', {'class':type(error).__name__,'reason':str(error)})
            if engine.record_path.exists():
                durable_json(directory/'recovery.json', engine.rollback())
            raise
        durable_json(directory/'result.json', result)
        print(json.dumps(result))
        return
    directory = STATE/('site-boot-'+str(time.time_ns()))
    directory.mkdir(mode=0o700)
    if sys.argv[1:] == ['reload-web']:
        config = configuration(json.loads(regular(CONFIG)[0]))
        units = {item['unit'].replace('@.', '@'+read_route(item['route'])['generation']+'.')
                 for item in config['components'].values() if item['kind'] == 'web'}
        commands = Commands(directory)
        for unit in units:
            commands.run('site_reload_FPM', ['systemctl', 'reload', '--quiet', unit])
        print(json.dumps({'phase': 'reloaded', 'units': sorted(units)}))
    elif sys.argv[1:]:
        raise ValueError('site_generation_operation')
    else:
        print(json.dumps(start_current(directory)))


if __name__ == '__main__':
    main()
