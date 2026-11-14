"""Release-specific code updates using the installed ownership receipt and durable CAS."""
import json
import os
from pathlib import Path, PurePosixPath

from host_transaction import Commands, Files, durable_json, regular
from host_install import LEGACY_UNITS
from identity_bindings import bind as bind_identities
from install_preparation import baseline_identities, read_payload
from profile_bindings import bind as bind_profile
from site_bindings import bind as bind_site, rebase
from release import sha, version
from roundcube_core import TARGETS as ROUNDCUBE_TARGETS,render as render_roundcube_core
from sieve_lock import MODULE as SIEVE_MODULE

CERTIFICATE = 'usr/local/lib/mail-client-certificates-v1/'
PREFIXES = ('usr/local/lib/', 'usr/local/sbin/', 'opt/mail-management/',
            'opt/roundcube-auth/', 'usr/share/roundcube/plugins/', 'opt/mail-antivirus-v1/',
            'etc/mail-legacy-smtp-v1/', 'integration/roundcube-patches/', 'integration/roundcube-settings.json')


def contract(value, receipt, units):
    fields = {'format', 'from_version', 'to_version', 'pause', 'stop', 'start', 'reload', 'health'}
    if set(value) != fields or value['format'] != 1:
        raise ValueError('update_contract_shape')
    if receipt.get('format') != 2 or value['from_version'] != receipt['version']:
        raise ValueError('update_receipt_or_source_version')
    if version(value['to_version']) <= version(receipt['version']):
        raise ValueError('update_version_order')
    allowed = set(receipt['unit_files']) | set(units)
    for action in ('pause', 'stop', 'start', 'reload', 'health'):
        names = value[action]
        if type(names) is not list or len(names) != len(set(names)):
            raise ValueError('update_unit_list')
        if any(type(name) is not str or name not in allowed for name in names):
            raise ValueError('update_unit_scope')
    if set(value['stop']) != set(value['start']):
        raise ValueError('update_stop_start_inventory')
    if any(not name.endswith('.timer') for name in value['pause']):
        raise ValueError('update_pause_timer_scope')
    if set(value['stop']) & set(value['pause'] + value['reload']):
        raise ValueError('update_duplicate_service_operation')
    if not value['health']:
        raise ValueError('update_health_required')
    return value


def render(payload, receipt, read_live, *, certificate_adoption=False):
    files = read_payload(payload)
    files.pop('installer.py', None)
    bound = bind_site(files, receipt['site'])
    bound, _ = bind_identities(bound, receipt['identities'], baseline_identities(payload))
    bound = bind_profile(bound)
    blueprints = {name: sha(raw) for name, raw in bound.items()
                  if name.startswith('blueprint/') and not name.startswith('blueprint/systemd/')
                  and name != 'blueprint/update-contract.json' and not name.startswith('blueprint/migrations/')}
    if blueprints != receipt['blueprints']:
        raise ValueError('release_requires_configuration_migration_hook')
    schema = {name: sha(raw) for name, raw in bound.items()
              if name.startswith('blueprint/') and (name.endswith('.sql') or name.endswith('/grants.json'))}
    if schema != receipt['schemas']:
        raise ValueError('release_requires_schema_migration_hook')
    guard = CERTIFICATE+'guard.so'
    if '/'+guard in receipt['code']:
        bound[guard] = read_live('/'+guard)[0]
    manifest_name = CERTIFICATE+'runtime-manifest.json'
    current = json.loads(read_live('/'+manifest_name)[0])
    updated = json.loads(bound[manifest_name])
    for field in ('guard_pin', 'python_pin', 'openssl_pin', 'php_pin'):
        updated[field] = current[field]
    updated['pins'] = {name: sha(bound[CERTIFICATE+name]) for name in updated['pins']}
    baseline = dict(bound)
    bound[manifest_name] = (json.dumps(updated, sort_keys=True, indent=2)+'\n').encode()
    output = rebase(bound, baseline)
    if SIEVE_MODULE in receipt['code']:
        output[SIEVE_MODULE.lstrip('/')] = read_live(SIEVE_MODULE)[0]
    if sha(output[manifest_name]) != sha(read_live('/'+manifest_name)[0]) and not certificate_adoption:
        raise ValueError('certificate_runtime_requires_dedicated_release_hook')
    for name in ('runtime.py','binding.py','collector_core.py','split_core.py','split_runtime.py','cold_exec.py','scale_core.py'):
        path='usr/local/lib/mail-quota-v1/'+name
        if path in output and sha(output[path])!=receipt['code'].get('/'+path,{}).get('sha256'):
            raise ValueError('quota_runtime_requires_dedicated_release_hook')
    binding = receipt.get('certificate_binding')
    if binding:
        from certificate_adoption import bind_gate_unit
        output = bind_gate_unit(output, binding, read_live)
    output.update(render_roundcube_core(output,read_live))
    return output


class CodeUpdate:
    def __init__(self, payload, transaction, root='/', commands=None):
        self.payload = Path(payload)
        self.directory = Path(transaction)
        self.root = Path(root)
        self.commands = commands or Commands(self.directory)
        self.commands.sequence = len(list(self.directory.glob('[0-9][0-9][0-9][0-9]-*.json')))
        self.files = Files(self.root, self.directory)
        self.record_path = self.directory/'code-update.json'

    def live(self, name):
        return regular(self.files.target(name))

    def render(self, receipt):
        return render(self.payload, receipt, self.live)

    def save(self):
        durable_json(self.record_path, self.record)

    def load(self):
        raw, metadata = regular(self.record_path)
        if metadata['uid'] != os.geteuid() or metadata['mode'] & 0o077:
            raise ValueError('update_transaction_permissions')
        self.record = json.loads(raw)
        self.files.entries = [json.loads(path.read_bytes()) for path in sorted(self.directory.glob('file-entry-*.json'))]

    def unit(self, name):
        raw = self.commands.run('inspect_'+name.replace('-', '_').replace('.', '_').replace('@', '_'),
            ['/usr/bin/systemctl', 'show', name, '-p', 'ActiveState,SubState,MainPID,Job'])
        result = dict(line.split('=', 1) for line in raw.decode().splitlines())
        if name.endswith('.socket') and 'MainPID' not in result:
            result['MainPID'] = '0'
        if (name.endswith('.socket') and result.get('ActiveState') == 'active'
                and result.get('SubState') in ('listening', 'running')):
            result['SubState'] = 'listening'
        if not {'ActiveState', 'SubState', 'MainPID', 'Job'} <= result.keys():
            raise ValueError('unit_state_incomplete')
        if result.get('Job') not in ('', '0'):
            raise ValueError('unit_has_pending_job')
        return result

    def operation(self, action, name):
        self.record['operation_started'] = {'action': action, 'unit': name}
        self.save()
        self.commands.run(action+'_'+name.replace('-', '_').replace('.', '_'),
                          ['/usr/bin/systemctl', action, '--quiet', name], timeout=120)
        observed = self.unit(name)
        if action == 'stop' and (observed['ActiveState'] != 'inactive' or observed['MainPID'] != '0'):
            raise ValueError('unit_stop_incomplete')
        self.record['last_units'][name] = observed
        self.record['operation_started'] = None
        self.save()

    def plan(self):
        if self.record_path.exists():
            raise ValueError('update_transaction_already_planned')
        raw, metadata = self.live('/var/lib/mail-platform-update/installed-code.json')
        if metadata['uid'] != 0 or metadata['mode'] != 0o600:
            raise ValueError('installed_receipt_permissions')
        receipt = json.loads(raw)
        allowed_units = {'nginx.service', 'php8.4-fpm.service', 'postfix.service', 'dovecot.service',
                         'rspamd.service', 'mariadb.service', 'redis-server.service', 'postsrsd.service',
                         'fail2ban.service', 'rsyslog.service', 'ufw.service'}
        value = json.loads((self.payload/'blueprint/update-contract.json').read_bytes())
        checked = contract(value, receipt, allowed_units)
        release = json.loads((self.payload.parent/'bundle.json').read_bytes())
        if checked['to_version'] != release['version']:
            raise ValueError('release_contract_version_mismatch')
        bound = self.render(receipt)
        release_units = {name.removeprefix('blueprint/systemd/') for name in bound
                         if name.startswith('blueprint/systemd/')}
        if release_units - set(receipt['unit_files']) - LEGACY_UNITS:
            raise ValueError('release_unit_addition_requires_migration_hook')
        candidates = {}
        for name, content in bound.items():
            if name.startswith('blueprint/'):
                continue
            if (not name.startswith(PREFIXES) and '/'+name != SIEVE_MODULE) or '..' in PurePosixPath(name).parts or '\\' in name:
                raise ValueError('update_code_path_scope')
            path = '/'+name
            before = receipt['code'].get(path)
            if before is None and name in ROUNDCUBE_TARGETS:
                before=self.live(path)[1]
            if before is not None and self.live(path)[1] != before:
                raise ValueError('installed_code_drift:'+path)
            if before is None and os.path.lexists(self.files.target(path)):
                raise ValueError('new_code_collision:'+path)
            mode, gid = (0o640, receipt['identities']['mailadmin.gid']) if name.startswith('opt/mail-management/') else (0o644, 0)
            after = {'sha256': sha(content), 'uid': 0, 'gid': gid, 'mode': mode}
            if before != after:
                candidates[path] = {'before': before, 'after': after, 'source': name}
        if set(receipt['code']) - {'/'+name for name in bound}:
            raise ValueError('release_code_removal_requires_migration_hook')
        for name, before in receipt['unit_files'].items():
            path = '/etc/systemd/system/'+name
            if self.live(path)[1] != before:
                raise ValueError('installed_unit_drift:'+name)
            source = 'blueprint/systemd/'+name
            if source not in bound:
                raise ValueError('release_unit_removal_requires_migration_hook')
            after = {'sha256': sha(bound[source]), 'uid': 0, 'gid': 0, 'mode': 0o644}
            if before != after:
                candidates[path] = {'before': before, 'after': after, 'source': source}
        operations = set(checked['pause']+checked['stop']+checked['reload'])
        if any(name not in operations for name in receipt['unit_files']
               if '/etc/systemd/system/'+name in candidates):
            raise ValueError('changed_unit_missing_lifecycle_operation')
        if any(path.endswith(('.php', '.inc')) for path in candidates) and 'php8.4-fpm.service' not in checked['stop']:
            raise ValueError('PHP_update_requires_FPM_stop_start')
        availability = self.files.target('/etc/mail-platform/availability.json')
        if availability.exists():
            from availability_plan import configuration
            registered = configuration(json.loads(regular(availability)[0]))
            if any(path.startswith(root+'/') for path in candidates
                   for component in registered['components'].values() for root in component['roots']):
                raise ValueError('registered_components_require_format_2')
            registration = self.files.target('/etc/mail-platform/site-generations.json')
            if registration.exists() and set(candidates) & json.loads(regular(registration)[0])['static_files'].keys():
                raise ValueError('registered_infrastructure_requires_migration')
        planned_units = set().union(*(set(checked[name]) for name in ('pause', 'stop', 'start', 'reload', 'health')))
        original_units = {name: self.unit(name) for name in sorted(planned_units)}
        self.record = {'phase': 'planned', 'contract': checked, 'old_receipt': receipt,
                       'receipt_before': metadata, 'candidates': candidates, 'before_units': original_units,
                       'last_units': dict(original_units), 'operation_started': None, 'activated': False}
        self.save()
        return {'phase': 'planned', 'files': len(candidates), 'version': checked['to_version']}

    def stage(self):
        self.load()
        if self.record['phase'] != 'planned':
            raise ValueError('update_stage_order')
        output = self.directory/'staged-code'
        output.mkdir(mode=0o700)
        bound = self.render(self.record['old_receipt'])
        for path, entry in self.record['candidates'].items():
            raw = bound[entry['source']]
            if sha(raw) != entry['after']['sha256']:
                raise ValueError('update_stage_source_drift')
            target = output/path.lstrip('/')
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(raw)
            if target.suffix == '.py':
                compile(raw, path, 'exec')
            if target.suffix in ('.php', '.inc'):
                self.commands.run('PHP_lint', ['/usr/bin/php8.4', '-n', '-l', str(target)])
        unit_files = [str(output/path.lstrip('/')) for path in self.record['candidates']
                      if path.startswith('/etc/systemd/system/') and Path(path).suffix in ('.service','.socket','.timer')]
        if unit_files:
            self.commands.run('unit_lint', ['/usr/bin/systemd-analyze', 'verify', *unit_files])
        self.record['phase'] = 'staged'
        self.save()
        return {'phase': 'staged'}

    def activate(self):
        self.load()
        if self.record['phase'] != 'staged':
            raise ValueError('update_activate_order')
        value = self.record['contract']
        self.record['phase'] = 'activation_started'
        self.record['activated'] = True
        self.save()
        for name in value['pause']+value['stop']:
            if self.record['before_units'][name]['ActiveState'] == 'active':
                self.operation('stop', name)
        for path, entry in self.record['candidates'].items():
            target = self.files.target(path)
            current = self.live(path)[1] if os.path.lexists(target) else None
            if current != entry['before']:
                raise ValueError('activation_CAS_conflict:'+path)
            raw = regular(self.directory/'staged-code'/path.lstrip('/'))[0]
            if sha(raw) != entry['after']['sha256']:
                raise ValueError('staged_code_drift')
            self.files.write(path, raw, entry['after']['mode'], entry['after']['uid'], entry['after']['gid'])
        if any(path.startswith('/etc/systemd/system/') for path in self.record['candidates']):
            self.commands.run('systemd_reload', ['/usr/bin/systemctl', 'daemon-reload'])
        for name in value['start']:
            if self.record['before_units'][name]['ActiveState'] == 'active':
                self.operation('start', name)
        for name in value['reload']:
            if self.record['before_units'][name]['ActiveState'] == 'active':
                self.operation('reload', name)
        for name in value['pause']:
            if self.record['before_units'][name]['ActiveState'] == 'active':
                self.operation('start', name)
        self.record['phase'] = 'activated'
        self.save()
        return {'phase': 'activated'}

    def health(self):
        self.load()
        if self.record['phase'] != 'activated':
            raise ValueError('update_health_order')
        for path, item in self.record['candidates'].items():
            if self.live(path)[1] != item['after']:
                raise ValueError('update_health_file_drift')
        for name in self.record['contract']['health']:
            self.commands.run('health_'+name.replace('-', '_').replace('.', '_'),
                              ['/usr/bin/systemctl', 'is-active', '--quiet', name])
        if self.live('/var/lib/mail-platform-update/installed-code.json')[1] != self.record['receipt_before']:
            raise ValueError('installed_receipt_CAS_conflict')
        receipt = self.updated_receipt()
        self.files.write('/var/lib/mail-platform-update/installed-code.json',
                         (json.dumps(receipt, sort_keys=True, indent=2)+'\n').encode(), 0o600)
        self.record['phase'] = 'healthy'
        self.save()
        return {'phase': 'healthy', 'version': receipt['version']}

    def updated_receipt(self):
        receipt = dict(self.record['old_receipt'])
        receipt['code'] = dict(receipt['code'])
        receipt['unit_files'] = dict(receipt['unit_files'])
        for path, item in self.record['candidates'].items():
            if path.startswith('/etc/systemd/system/'):
                receipt['unit_files'][Path(path).name] = item['after']
            else:
                receipt['code'][path] = item['after']
        receipt['version'] = self.record['contract']['to_version']
        return receipt

    def rollback(self):
        if not self.record_path.exists():
            return {'phase': 'rolled_back', 'changes': 0}
        self.load()
        if self.record['phase'] == 'rolled_back':
            self.verify_completed_rollback()
            return {'phase': 'rolled_back', 'operations': 0, 'data_preserved': True}
        if self.record['operation_started']:
            raise ValueError('unfinished_service_operation_requires_review')
        for entry in self.files.entries:
            if self.files.mark_unapplied(entry) or entry['phase'] == 'restored':
                continue
            if entry['phase'] != 'written' or self.live(entry['path'])[1] != entry['after']:
                raise ValueError('rollback_held_unknown_file_state')
        value = self.record['contract']
        if self.record['activated']:
            for name in value['pause']+value['stop']:
                current = self.unit(name)
                if current != self.record['last_units'][name]:
                    raise ValueError('rollback_held_unit_drift')
            for name in value['pause']+value['stop']:
                if self.unit(name)['ActiveState'] == 'active':
                    self.operation('stop', name)
        result = self.files.restore()
        if result['status'] != 'restored':
            raise ValueError('rollback_held_file_restore')
        if self.record['activated']:
            if any(path.startswith('/etc/systemd/system/') for path in self.record['candidates']):
                self.commands.run('restore_systemd', ['/usr/bin/systemctl', 'daemon-reload'])
            for name in value['start']+value['pause']:
                if self.record['before_units'][name]['ActiveState'] == 'active':
                    self.operation('start', name)
            for name in value['reload']:
                if self.record['before_units'][name]['ActiveState'] == 'active':
                    self.operation('reload', name)
            self.observe_restored_units()
        self.record['phase'] = 'rolled_back'
        self.save()
        return {'phase': 'rolled_back', 'data_preserved': True}

    def verify_completed_rollback(self):
        """A resumed composite recovery must not restart already restored services."""
        if self.record['operation_started']:
            raise ValueError('unfinished_service_operation_requires_review')
        expected = {}
        for entry in self.files.entries:
            if entry['preserve']:
                continue
            if entry['phase'] != 'restored':
                raise ValueError('rollback_journal_incomplete')
            expected.setdefault(entry['path'], entry['before'])
        for name, metadata in expected.items():
            actual = self.live(name)[1] if os.path.lexists(self.files.target(name)) else None
            if actual != metadata:
                raise ValueError('completed_rollback_file_drift')
        if self.record['activated']:
            self.observe_restored_units()
            self.save()

    def observe_restored_units(self):
        observations = {name: {'expected': expected, 'actual': self.unit(name),
                              'original': self.record.get('before_units', {}).get(name)}
                        for name, expected in self.record['last_units'].items()}
        durable_json(self.directory/'restored-unit-observations.json', observations)
        for item in observations.values():
            if item['actual'] == item['expected']:
                continue
            original = item['original']
            if not original or original['ActiveState'] != 'inactive' or item['actual'] != original:
                raise ValueError('completed_rollback_unit_drift')
        self.record['last_units'] = {name: item['actual'] for name, item in observations.items()}
