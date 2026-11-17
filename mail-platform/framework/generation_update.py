"""Format-2 update hook using pre-enrolled component units and stable frontends."""
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import struct
import time
import uuid

from availability_plan import configuration, impact, select
from code_update import CodeUpdate, render
from generation_front import control, read_route
from host_transaction import durable_json, regular
from release import canonical, sha


class GenerationUpdate(CodeUpdate):
    allow_registered_additions = False
    def __init__(self, payload, transaction, root='/', commands=None):
        super().__init__(payload, transaction, root, commands)
        self.record_path = self.directory/'generation-update.json'

    def update_contract(self, receipt, config, changes=None):
        return json.loads((self.payload/'blueprint/update-contract.json').read_bytes())

    def new_path_allowed(self, target, config):
        return self.allow_registered_additions and any(target.startswith(root+'/')
            for component in config['components'].values() for root in component['roots'])

    def partition_changes(self, changes, config):
        return changes

    def select_changes(self, contract, config, changes):
        return select(contract, config, changes)

    def next_generation(self, version):
        return 'g' + version.replace('.', 'x')

    def updated_generation_receipt(self):
        receipt = dict(self.record['old_receipt'], code=dict(self.record['old_receipt']['code']))
        for target in self.record['changes']:
            receipt['code'][target] = self.live(target)[1]
        receipt['version'] = self.record['contract']['to_version']
        return receipt

    def plan(self):
        if self.record_path.exists():
            raise ValueError('generation_transaction_exists')
        raw, config_metadata = self.live('/etc/mail-platform/availability.json')
        if config_metadata['uid'] != 0 or config_metadata['mode'] != 384:
            raise ValueError('availability_configuration_permissions')
        config = configuration(json.loads(raw))
        templates = {}
        for component in config['components'].values():
            for source in ('/etc/systemd/system/' + component['unit'], component['template']):
                if source:
                    _, attributes = self.live(source)
                    if attributes['uid'] != 0 or attributes['mode'] & 18:
                        raise ValueError('generation_installed_template_permissions')
                    templates[source] = attributes
        receipt_raw, receipt_metadata = self.live('/var/lib/mail-platform-update/installed-code.json')
        if receipt_metadata['uid'] != 0 or receipt_metadata['mode'] != 384:
            raise ValueError('availability_receipt_permissions')
        receipt = json.loads(receipt_raw)
        self.check_aliases(receipt)
        contract = self.update_contract(receipt, config)
        bundle = json.loads((self.payload.parent / 'bundle.json').read_bytes())
        if receipt['format'] != 2 or contract['from_version'] != receipt['version'] or contract['to_version'] != bundle['version']:
            raise ValueError('availability_installed_version')
        bound = self.render(receipt)
        changes = {}
        for name, raw in bound.items():
            if name.startswith('blueprint/'):
                continue
            target = '/' + name
            before = receipt['code'].get(target)
            if before is None:
                if not self.new_path_allowed(target, config) or os.path.lexists(self.files.target(target)):
                    raise ValueError('availability_code_addition_requires_adoption')
            elif self.live(target)[1] != before:
                raise ValueError('availability_installed_drift:' + target)
            if before is None or sha(raw) != before['sha256']:
                metadata = before or {'uid': 0, 'gid': receipt['identities']['mailadmin.gid']
                    if target.startswith('/opt/mail-management/') else 0,
                    'mode': 0o640 if target.startswith('/opt/mail-management/') else 0o644}
                changes[target] = {'source': name, 'before': before, 'sha256': sha(raw),
                                   'attributes': metadata}
        if set(receipt['code']) - {'/' + name for name in bound}:
            raise ValueError('availability_code_removal')
        for name, expected in receipt['unit_files'].items():
            current, metadata = self.live('/etc/systemd/system/' + name)
            if metadata != expected or sha(bound['blueprint/systemd/' + name]) != sha(current):
                raise ValueError('availability_unit_migration_required')
        changes = self.partition_changes(changes, config)
        contract = self.update_contract(receipt, config, changes)
        owners = self.select_changes(contract, config, changes)
        generation = self.next_generation(bundle['version'])
        components = {}
        for name in contract['components']:
            component = config['components'][name]
            route_raw, route_metadata = regular(component['route'], 16384)
            route = read_route(component['route'])
            status = control(component['control'], 'status')
            if not status['accepting'] or set(status['active']) - {route['generation']}:
                raise ValueError('availability_previous_generation_pending')
            directory = Path(config['generation_root']) / name / generation
            if directory.exists():
                raise ValueError('availability_generation_exists')
            components[name] = {
                'configuration': component, 'old_route': route,
                'old_route_raw': route_raw.decode(), 'old_route_metadata': route_metadata,
                'front_pid': status['pid'], 'directory': str(directory),
                'phase': 'planned', 'operation_started': None}
            old_unit = component['unit'].replace('@.', '@' + route['generation'] + '.')
            observed = self.unit(old_unit)
            if observed['ActiveState'] != 'active' or observed['MainPID'] == '0':
                raise ValueError('generation_previous_unit_not_running')
            components[name]['old_unit_state'] = observed
        self.record = {
            'phase': 'planned', 'contract': contract, 'config': config,
            'config_metadata': config_metadata, 'receipt_before': receipt_metadata,
            'old_receipt': receipt, 'changes': changes, 'owners': owners,
            'components': components, 'generation': generation}
        self.record['templates'] = templates
        self.groups()
        self.save()
        return {'phase': 'planned', 'files': len(changes), 'impact': impact({name: item['configuration'] for name, item in components.items()})}

    @staticmethod
    def snapshot(source, destination, logical_root=None, aliases=None):
        from code_aliases import snapshot_tree
        return snapshot_tree(source,destination,logical_root or str(source),aliases or {})

    def stage(self):
        self.load()
        if self.record['phase'] != 'planned':
            raise ValueError('generation_stage_order')
        bound = self.render(self.record['old_receipt'])
        for name, item in self.record['components'].items():
            directory = Path(item['directory'])
            directory.mkdir(parents=True, mode=0o755)
            os.chmod(directory, 0o755)
            item['code_links']={}
            for root in item['configuration']['roots']:
                destination = directory/'root'/root.lstrip('/')
                destination.parent.mkdir(parents=True, exist_ok=True)
                item['code_links'][root]=self.snapshot(self.files.target(root), destination, root,
                    self.record['old_receipt'].get('code_aliases',{}))
            for target, change in self.record['changes'].items():
                if name not in self.record['owners'][target]:
                    continue
                raw = bound[change['source']]
                if sha(raw) != change['sha256']:
                    raise ValueError('generation_staged_drift')
                path = directory/'root'/target.lstrip('/')
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
                if change['before'] is None:
                    os.chmod(path, change['attributes']['mode'])
                    os.chown(path, change['attributes']['uid'], change['attributes']['gid'])
                if path.suffix in ('.php', '.inc'):
                    self.commands.run('generation_PHP_lint', ['/usr/bin/php8.4', '-n', '-l', str(path)])
                if path.suffix == '.py':
                    compile(raw, str(path), 'exec')
            inventory = {}
            for path in sorted((directory/'root').rglob('*')):
                if path.is_file():
                    with path.open('rb') as stream:
                        os.fsync(stream.fileno())
                    raw, attributes = regular(path)
                    inventory[path.relative_to(directory/'root').as_posix()] = attributes
            durable_json(directory/'inventory.json', inventory)
            item['inventory_sha256'] = sha(canonical(inventory))
            template = item['configuration']['template']
            if template:
                raw, metadata = regular(template)
                if metadata['uid'] != 0 or metadata['mode'] & 0o022:
                    raise ValueError('generation_template_trust')
                config = raw.replace(b'%i', self.record['generation'].encode())
                config_path = directory/'fpm.conf'
                config_path.write_bytes(config)
                os.chown(config_path, 0, metadata['gid'])
                os.chmod(config_path, metadata['mode'])
                with config_path.open('rb') as stream:
                    os.fsync(stream.fileno())
                self.commands.run('generation_FPM_lint', ['/usr/sbin/php-fpm8.4', '-t', '-y', str(directory/'fpm.conf')])
            for folder in [*(directory/'root').rglob('*'), directory/'root', directory]:
                if folder.is_dir() and not folder.is_symlink():
                    descriptor = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
            item['phase'] = 'staged'
            self.save()
        self.record['phase'] = 'staged'
        self.save()
        return {'phase': 'staged'}

    def front(self, item, operation):
        response = control(item['configuration']['control'], operation)
        if response['pid'] != item['front_pid']:
            raise ValueError('generation_front_restarted')
        return response

    def service(self, item, action, generation):
        unit = item['configuration']['unit'].replace('@.', '@'+generation+'.')
        observed = self.unit(unit)
        known = self.record.get('started_unit_states', {}).get(unit)
        if known is None and generation == item['old_route']['generation']:
            known = item['old_unit_state']
        if observed['ActiveState'] == 'active':
            if known is None or observed['MainPID'] != known['MainPID']:
                raise ValueError('generation_unit_state_changed')
        elif observed['ActiveState'] != 'inactive' or observed['MainPID'] != '0' or (action == 'stop' and known is not None):
            raise ValueError('generation_unit_state_changed')
        item['operation_started'] = {'action': action, 'unit': unit}
        self.save()
        self.commands.run('generation_'+action, ['/usr/bin/systemctl', action, '--quiet', unit], timeout=60)
        state = self.unit(unit)
        expected = 'active' if action == 'start' else 'inactive'
        if (state['ActiveState'] != expected or (action == 'stop' and state['MainPID'] != '0')
                or (action == 'start' and state['MainPID'] == '0')):
            raise ValueError('generation_service_state')
        if action == 'start':
            self.record.setdefault('started_unit_states', {})[unit] = state
        item['operation_started'] = None
        self.save()

    def drain(self, item, generation):
        deadline = time.monotonic() + item['configuration']['drain_seconds']
        while True:
            state = self.front(item, 'status')
            if not state['active'].get(generation):
                return
            if time.monotonic() >= deadline:
                raise ValueError('generation_drain_pending')
            time.sleep(0.05)

    def probe(self, item, route):
        probe = item['configuration']['health']
        if 'peer_uid' in probe:
            self.commands.run('generation_policy_probe',
                ['/usr/bin/python3','-I','-S','-B',str(Path(__file__).with_name('generation_probe.py'))],
                canonical(dict(probe,socket=route['socket'])),timeout=5)
            return
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(3)
            connection.connect(route['socket'])
            if probe['kind'] == 'fcgi':
                self.fcgi_probe(connection, probe, self.directory)
                return
            connection.sendall(probe['request'].encode())
            data = bytearray()
            while len(data) < 65536:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                data.extend(chunk)
                if probe['reply'].encode() in data:
                    return
        raise ValueError('generation_protocol_health')

    @staticmethod
    def fcgi_probe(connection, probe, diagnostic_directory=None):
        def record(kind, body):
            return struct.pack('!BBHHBB', 1, kind, 1, len(body), 0, 0) + body

        values = {'REQUEST_METHOD': 'GET', 'SCRIPT_FILENAME': probe['request'],
                  'SCRIPT_NAME': '/health.php', 'REQUEST_URI': '/health.php',
                  'SERVER_PROTOCOL': 'HTTP/1.1', 'GATEWAY_INTERFACE': 'CGI/1.1'}
        values.update(probe.get('parameters', {}))
        parameters = bytearray()
        for name, value in values.items():
            left, right = name.encode(), value.encode()
            for data in (left, right):
                parameters.extend(bytes([len(data)]) if len(data) < 128 else struct.pack('!I', len(data) | 0x80000000))
            parameters.extend(left + right)
        connection.sendall(record(1, struct.pack('!HB5x', 1, 0)) + record(4, parameters) + record(4, b'') + record(5, b''))

        def exactly(length):
            output = bytearray()
            while len(output) < length:
                data = connection.recv(length - len(output))
                if not data:
                    raise ValueError('generation_FCGI_truncated')
                output.extend(data)
            return bytes(output)

        output = bytearray()
        while len(output) < 65536:
            version, kind, request_id, length, padding, reserved = struct.unpack('!BBHHBB', exactly(8))
            if version != 1 or request_id != 1:
                raise ValueError('generation_FCGI_header')
            body = exactly(length)
            exactly(padding)
            if kind == 6:
                output.extend(body)
            if kind == 7 and body:
                if diagnostic_directory is not None:
                    durable_json(Path(diagnostic_directory)/('FCGI-failure-'+uuid.uuid4().hex+'.json'),
                                 {'request':probe['request'],'stderr_hex':body.hex(),'stdout_hex':output.hex()})
                raise ValueError('generation_FCGI_error')
            if kind == 3:
                if len(body) != 8 or body[:5] != b'\0' * 5 or probe['reply'].encode() not in output:
                    raise ValueError('generation_FCGI_health')
                return
        raise ValueError('generation_FCGI_size')

    def verify_inventory(self, item):
        directory = Path(item['directory'])
        from code_aliases import tree_links
        for root in item['configuration']['roots']:
            actual_links=tree_links(directory/'root'/root.lstrip('/'),root,
                self.record['old_receipt'].get('code_aliases',{}))
            if actual_links!=item.get('code_links',{}).get(root,{}):
                raise ValueError('generation_inventory_links_changed')
        inventory = json.loads(regular(directory/'inventory.json')[0])
        if sha(canonical(inventory)) != item['inventory_sha256']:
            raise ValueError('generation_inventory_changed')
        actual = {path.relative_to(directory/'root').as_posix(): regular(path)[1]
                  for path in (directory/'root').rglob('*') if path.is_file()}
        if actual != inventory:
            raise ValueError('generation_code_changed')

    def activate(self):
        self.load()
        if self.record['phase'] != 'staged':
            raise ValueError('generation_activate_order')
        if self.live('/etc/mail-platform/availability.json')[1] != self.record['config_metadata']:
            raise ValueError('generation_configuration_CAS')
        for source, expected in self.record['templates'].items():
            if self.live(source)[1] != expected:
                raise ValueError('generation_template_CAS')
        for name, item in self.record['components'].items():
            self.verify_inventory(item)
            component = item['configuration']
            new_route = {'generation': self.record['generation'], 'socket': str(Path(component['runtime']) / self.record['generation'] / 'backend.sock')}
            item['new_route'] = new_route
            item['phase'] = 'starting'
            self.save()
        for group in self.groups():
            first = group[0]
            if first['configuration']['kind'] == 'writer':
                for item in group:
                    self.front(item, 'pause')
                for item in group:
                    self.drain(item, item['old_route']['generation'])
                self.service(first, 'stop', first['old_route']['generation'])
                for item in group:
                    item['phase'] = 'old_stopped'
                self.save()
            self.service(first, 'start', self.record['generation'])
            for item in group:
                self.probe(item, item['new_route'])
                if regular(item['configuration']['route'])[1] != item['old_route_metadata']:
                    raise ValueError('generation_route_CAS')
            for item in group:
                item['phase'] = 'switch_started'
                self.save()
                before = item['old_route_metadata']
                durable_json(item['configuration']['route'], item['new_route'], mode=before['mode'], uid=before['uid'], gid=before['gid'])
                item['phase'] = 'switched'
                self.save()
            for item in group:
                self.front(item, 'resume')
        self.record['phase'] = 'activated'
        self.save()
        return {'phase': 'activated'}

    def health(self):
        self.load()
        if self.record['phase'] != 'activated':
            raise ValueError('generation_health_order')
        for item in self.record['components'].values():
            if read_route(item['configuration']['route']) != item['new_route']:
                raise ValueError('generation_health_route')
            self.verify_inventory(item)
            if not self.front(item,'status')['accepting']:
                raise ValueError('generation_front_not_accepting')
            self.probe(item, item['new_route'])
        self.retire_groups()
        # Synchronize owned live snapshots for the next legacy receipt/render comparison.
        for target, change in self.record['changes'].items():
            actual = self.live(target)[1] if os.path.lexists(self.files.target(target)) else None
            if actual != change['before']:
                raise ValueError('generation_owned_code_CAS')
            item = self.record['components'][self.record['owners'][target][0]]
            raw = regular(Path(item['directory'])/'root'/target.lstrip('/'))[0]
            before = change.get('attributes', change['before'])
            self.files.write(target, raw, before['mode'], before['uid'], before['gid'])
        if self.live('/var/lib/mail-platform-update/installed-code.json')[1] != self.record['receipt_before']:
            raise ValueError('generation_receipt_CAS')
        receipt = self.updated_generation_receipt()
        self.files.write('/var/lib/mail-platform-update/installed-code.json', canonical(receipt), 0o600)
        self.record['phase'] = 'healthy'
        self.save()
        return {'phase': 'healthy','retirement_pending':self.record['retirement_pending']}

    def groups(self):
        groups = {}
        for item in self.record['components'].values():
            key = item['configuration']['unit']
            if key in groups and groups[key][0]['old_route']['generation']!=item['old_route']['generation']:
                raise ValueError('generation_shared_unit_route_mismatch')
            groups.setdefault(key, []).append(item)
        return list(groups.values())

    def retire_groups(self):
        pending = []
        for group in self.groups():
            first = group[0]
            if all((item['phase'] == 'retired' for item in group)):
                continue
            if first['configuration']['kind'] == 'writer':
                for item in group:
                    item['phase'] = 'retired'
                continue
            states = [self.front(item, 'status') for item in group]
            active = any((state['active'].get(item['old_route']['generation'], 0) for item, state in zip(group, states)))
            if active:
                for item in group:
                    item['phase'] = 'retirement_pending'
                pending.extend((name for name, item in self.record['components'].items() if item in group))
                continue
            old = first['configuration']['unit'].replace('@.', '@' + first['old_route']['generation'] + '.')
            observed = self.unit(old)
            if observed['ActiveState'] == 'active':
                if observed['MainPID'] != first['old_unit_state']['MainPID']:
                    raise ValueError('generation_previous_unit_replaced')
                self.service(first, 'stop', first['old_route']['generation'])
            elif observed['ActiveState'] != 'inactive' or observed['MainPID'] != '0':
                raise ValueError('generation_previous_unit_state_unknown')
            for item in group:
                item['phase'] = 'retired'
        self.record['retirement_pending'] = pending
        self.save()
        return pending

    def retire(self):
        self.load()
        if self.record['phase'] != 'healthy' or any((item['operation_started'] for item in self.record['components'].values())):
            raise ValueError('generation_retirement_order')
        if self.live('/etc/mail-platform/availability.json')[1] != self.record['config_metadata']:
            raise ValueError('generation_configuration_CAS')
        for item in self.record['components'].values():
            if read_route(item['configuration']['route']) != item['new_route']:
                raise ValueError('generation_retirement_route_changed')
            self.verify_inventory(item)
        return {'phase': 'retirement_pending' if self.retire_groups() else 'retired', 'retirement_pending': self.record['retirement_pending']}

    def rollback(self):
        if not self.record_path.exists():
            return {'phase': 'rolled_back'}
        self.load()
        if any((item['operation_started'] for item in self.record['components'].values())):
            raise ValueError('generation_operation_unknown')
        for item in self.record['components'].values():
            route = read_route(item['configuration']['route'])
            if route not in (item['old_route'], item.get('new_route')):
                raise ValueError('generation_rollback_unknown_route')
        for group in reversed(self.groups()):
            routes = {}
            for item in group:
                route = read_route(item['configuration']['route'])
                if route not in (item['old_route'], item.get('new_route')):
                    raise ValueError('generation_rollback_unknown_route')
                routes[item['configuration']['route']] = route
            if all((item['phase'] in ('planned', 'staged') for item in group)):
                continue
            for item in group:
                self.front(item, 'pause')
            for item in group:
                if item.get('new_route'):
                    self.drain(item, item['new_route']['generation'])
            first = group[0]
            if any((item.get('new_route') for item in group)):
                self.service(first, 'stop', first['new_route']['generation'])
            self.service(first, 'start', first['old_route']['generation'])
            for item in group:
                self.probe(item, item['old_route'])
                path = item['configuration']['route']
                if read_route(path) != routes[path]:
                    raise ValueError('generation_rollback_route_CAS')
                before = item['old_route_metadata']
                durable_json(path, item['old_route'], mode=before['mode'], uid=before['uid'], gid=before['gid'])
                self.front(item, 'resume')
                item['phase'] = 'restored'
            self.save()
        result = self.files.restore()
        if result['status'] != 'restored':
            raise ValueError('generation_rollback_held')
        self.record['phase'] = 'rolled_back'
        self.save()
        return {'phase': 'rolled_back', 'data_preserved': True}
