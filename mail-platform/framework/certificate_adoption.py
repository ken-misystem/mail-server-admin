"""One-time, journalled adoption of the certificate lifecycle in an existing site."""
import copy
import json
import os
from pathlib import Path
import shlex

from code_update import CodeUpdate, CERTIFICATE, render
from host_transaction import durable_json, regular
from release import canonical, sha
from certificate_state import require, trusted, require_settled, STATE

RECEIPT = '/var/lib/mail-platform-update/installed-code.json'
GATE = '/etc/systemd/system/mail-client-cert-gate.service'
CONFIG = '/etc/mail-client-certificates-v1/'
STATIC = ('/usr/local/lib/mail-platform-update/', '/'+CERTIFICATE)
HEALTH = '/usr/local/lib/mail-client-cert-public-v1/health.py'
UNITS = ('mail-platform-acme.service', 'mail-platform-acme.timer')
ACTORS = ('owner', 'lifecycle', 'verifier', 'issuer', 'gate')
SERVICES = tuple('mail-client-cert-'+name+'.service' for name in ACTORS)
STOP = ('mail-client-cert-owner.service', 'mail-client-cert-gate.socket',
        'mail-client-cert-gate.service', 'mail-client-cert-lifecycle.service',
        'mail-client-cert-verifier.service', 'mail-client-cert-issuer.service')
DESCRIPTOR = 'blueprint/migrations/certificates-v1/manifest.json'
PENDING = STATE/'migration-pending.json'


def attributes(raw, mode=0o644, gid=0):
    return {'sha256': sha(raw), 'uid': 0, 'gid': gid, 'mode': mode}


def bind_gate_unit(bound, binding, read_live):
    require(set(binding) == {'canonical_sha256', 'adopted'}, 'certificate_unit_binding_shape')
    name = 'blueprint/systemd/mail-client-cert-gate.service'
    require(sha(bound[name]) == binding['canonical_sha256'], 'certificate_unit_requires_migration')
    raw, actual = read_live(GATE)
    require(actual == binding['adopted'], 'certificate_unit_binding_drift')
    return dict(bound, **{name: raw})


def enrolled_view(unit, commands):
    """Accept the two exact public bind mounts produced by gate enrollment."""
    raw = commands.run('certificate_gate_binds', ['systemctl', 'show',
        'mail-client-cert-gate.service', '-p', 'BindReadOnlyPaths', '--value']).decode().strip()
    pairs = [value.removesuffix(':rbind') for value in shlex.split(raw)]
    if not pairs:
        return None
    require(len(pairs) == 2, 'certificate_enrollment_bind_inventory')
    targets = {}
    for pair in pairs:
        parts = pair.split(':')
        require(len(parts) == 2, 'certificate_enrollment_bind_shape')
        targets[parts[1]] = Path(parts[0])
    require(set(targets) == {'/'+CERTIFICATE.rstrip('/'), CONFIG+'gate.json'},
            'certificate_enrollment_bind_targets')
    release = targets['/'+CERTIFICATE.rstrip('/')]
    config = targets[CONFIG+'gate.json']
    directory = release.parent
    require(release == directory/'certificate' and config == directory/'gate.json'
            and str(directory).startswith('/var/lib/mail-platform-update/enrollment/'),
            'certificate_enrollment_bind_source')
    from certificate_enrollment import verify_stage
    record = verify_stage(directory)
    for source, target in targets.items():
        line = ('BindReadOnlyPaths='+str(target)+':'+source).encode()
        require(unit.splitlines().count(line) == 1, 'certificate_enrollment_unit_binding')
    return {'directory': str(directory), 'record': record,
            'lines': ['BindReadOnlyPaths='+str(value)+':'+key for key, value in targets.items()]}


class CertificateAdoption(CodeUpdate):
    def __init__(self, payload, transaction, root='/', commands=None):
        super().__init__(payload, transaction, root, commands)
        self.record_path = self.directory/'certificate-adoption.json'

    def put(self, path, raw, mode=0o644, gid=0):
        before = self.live(path)[1] if os.path.lexists(self.files.target(path)) else None
        after = attributes(raw, mode, gid)
        if before == after:
            return
        destination = self.directory/'certificate-stage'/path.lstrip('/')
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        destination.write_bytes(raw)
        os.chmod(destination, 0o600)
        self.record['candidates'][path] = {'before': before, 'after': after}

    def operation(self, action, name):
        previous = dict(self.record['last_units'])
        super().operation(action, name)
        observed = {unit: self.unit(unit) for unit in STOP}
        durable_json(self.directory/'unit-observation.json', {
            'action': action, 'unit': name, 'before': previous, 'after': observed})
        for unit, value in observed.items():
            old = previous[unit]
            if unit == name or value == old:
                continue
            if action == 'stop':
                require(value['ActiveState'] == 'inactive' and value['MainPID'] == '0',
                        'certificate_stop_dependency_state')
            else:
                require(old['ActiveState'] == 'inactive' and value['ActiveState'] == 'active'
                        and self.record['before_units'][unit]['ActiveState'] == 'active',
                        'certificate_start_dependency_state')
        self.record['last_units'] = observed
        self.save()

    def plan(self):
        require(not self.record_path.exists(), 'certificate_adoption_exists')
        descriptor = json.loads((self.payload/DESCRIPTOR).read_bytes())
        require(descriptor == {'format': 1, 'kind': 'certificate-lifecycle-v1'},
                'certificate_adoption_descriptor')
        raw, metadata = self.live(RECEIPT)
        require(metadata['uid'] == 0 and metadata['mode'] == 0o600, 'certificate_receipt_permissions')
        receipt = json.loads(raw)
        require(receipt['format'] == 2 and receipt['version'].startswith(('0.3.', '0.4.')),
                'certificate_adoption_source')
        rendering_receipt = receipt
        if (self.payload/'blueprint/migrations/sieve-lock-v1/manifest.json').is_file():
            from sieve_migration import SieveMigration, SOURCE
            SieveMigration(self.payload, self.directory).descriptor(receipt)
            rendering_receipt = dict(receipt, blueprints=dict(receipt['blueprints'],
                **{SOURCE: sha((self.payload/SOURCE).read_bytes())}))
        bound = render(self.payload, rendering_receipt, self.live, certificate_adoption=True)
        future = copy.deepcopy(receipt)
        self.record = {'phase': 'planning', 'candidates': {}, 'old_receipt': receipt,
                       'operation_started': None, 'last_units': {}, 'before_units': {}}
        for target, expected in receipt['code'].items():
            # All existing code is pinned before any unit is stopped.
            require(self.live(target)[1] == expected, 'certificate_installed_code_drift:'+target)
        manifest = '/'+CERTIFICATE+'runtime-manifest.json'
        old_manifest = json.loads(self.live(manifest)[0])
        unit_raw, unit_meta = self.live(GATE)
        view = enrolled_view(unit_raw, self.commands)
        if view:
            from certificate_enrollment import gate_unit
            canonical_gate = bound['blueprint/systemd/mail-client-cert-gate.service']
            require(sha(canonical_gate) == receipt['unit_files']['mail-client-cert-gate.service']['sha256'],
                    'certificate_enrollment_original_unit_changed')
            expected_unit = gate_unit(canonical_gate, '/'+CERTIFICATE.rstrip('/'),
                                      CONFIG+'gate.json', view['directory'])
            require(unit_raw == expected_unit, 'certificate_enrollment_unit_drift')
            gate = json.loads(trusted(Path(view['directory'])/'gate.json')[0])
            original_gate = json.loads(self.live(CONFIG+'gate.json')[0])
            require({key: value for key, value in gate.items() if key not in ('manifest_sha256', 'backend_fronts')}
                    == {key: value for key, value in original_gate.items() if key != 'manifest_sha256'},
                    'certificate_enrollment_configuration_drift')
            for line in view['lines']:
                unit_raw = unit_raw.replace((line+'\n').encode(), b'')
            self.put(GATE, unit_raw, unit_meta['mode'], unit_meta['gid'])
            future['unit_files']['mail-client-cert-gate.service'] = attributes(unit_raw, unit_meta['mode'], unit_meta['gid'])
            future['certificate_binding'] = {'canonical_sha256': sha(bound['blueprint/systemd/mail-client-cert-gate.service']),
                                             'adopted': future['unit_files']['mail-client-cert-gate.service']}
            bound['blueprint/systemd/mail-client-cert-gate.service'] = unit_raw
        else:
            require(unit_meta == receipt['unit_files']['mail-client-cert-gate.service'],
                    'certificate_gate_unit_drift')
            gate = json.loads(self.live(CONFIG+'gate.json')[0])
        for name, raw in bound.items():
            target = '/'+name
            if name.startswith('blueprint/'):
                continue
            if not (target.startswith(STATIC) or target == HEALTH):
                continue
            if target not in receipt['code']:
                require(not os.path.lexists(self.files.target(target)), 'certificate_new_code_collision')
            previous = receipt['code'].get(target, attributes(raw))
            self.put(target, raw, previous['mode'], previous['gid'])
            future['code'][target] = attributes(raw, previous['mode'], previous['gid'])
        require(set(old_manifest['pins']) <= set(json.loads(bound[manifest.lstrip('/')])['pins']),
                'certificate_runtime_pin_removal')
        digest = sha(bound[manifest.lstrip('/')])
        for actor in ACTORS:
            path = CONFIG+actor+'.json'
            original, meta = self.live(path)
            value = gate if actor == 'gate' else json.loads(original)
            if actor != 'gate' or view is None:
                require(value['manifest_sha256'] == sha(self.live(manifest)[0]),
                        'certificate_actor_manifest_drift')
            value = dict(value, manifest_sha256=digest)
            if value != json.loads(original):
                self.put(path, canonical(value), meta['mode'], meta['gid'])
        for name in UNITS:
            path = '/etc/systemd/system/'+name
            require(name in receipt['unit_files'] or not os.path.lexists(self.files.target(path)),
                    'certificate_new_unit_collision')
            raw = bound['blueprint/systemd/'+name]
            self.put(path, raw)
            future['unit_files'][name] = attributes(raw)
        dropins = {
            '/etc/systemd/system/mail-client-cert-owner.service.d/70-ca-IPC.conf':
                b'[Service]\nSupplementaryGroups=mailcert-gate\n',
            '/etc/systemd/system/mail-client-cert-health.service.d/70-certificate-lock.conf':
                b'[Service]\nReadWritePaths=/run/lock\n'}
        for path, raw in dropins.items():
            require(not os.path.lexists(self.files.target(path)) or self.live(path)[1] == attributes(raw),
                    'certificate_dropin_collision')
            self.put(path, raw)
        certificate_config = '/etc/mail-platform/certificates.json'
        if not os.path.lexists(self.files.target(certificate_config)):
            self.put(certificate_config, canonical({'format': 1, 'profile': 'production',
                'host': receipt['site']['mail_host'], 'probe_address': receipt['site']['public_ipv4'],
                'trust_store': '/etc/ssl/certs/ca-certificates.crt'}), 0o600)
        registration = '/etc/mail-platform/site-generations.json'
        if os.path.lexists(self.files.target(registration)):
            raw, meta = self.live(registration)
            value = json.loads(raw)
            for target in value['static_files']:
                require(self.live(target)[1] == value['static_files'][target],
                        'certificate_registered_static_drift')
            for target, item in self.record['candidates'].items():
                if target.startswith('/usr/local/lib/mail-platform-update/') or target in value['static_files']:
                    value['static_files'][target] = item['after']
            self.put(registration, canonical(value), meta['mode'], meta['gid'])
        self.put(RECEIPT, canonical(future), 0o600)
        self.record['future_receipt'] = future
        self.record['needs_restart'] = any(path.startswith('/'+CERTIFICATE) or path == HEALTH
            or path.startswith(CONFIG) or path == GATE or '/mail-client-cert-' in path
            for path in self.record['candidates'])
        self.record['before_units'] = {name: self.unit(name) for name in STOP}
        require(all(value['ActiveState'] in ('active', 'inactive') for value in self.record['before_units'].values()),
                'certificate_adoption_initial_unit_state')
        self.record['last_units'] = dict(self.record['before_units'])
        self.record.update(phase='planned', enrolled=view is not None)
        self.save()
        return {'phase': 'planned', 'files': len(self.record['candidates']), 'enrolled_view': view is not None}

    def future_live(self, path):
        if not hasattr(self, 'record'):
            self.load()
        item = self.record['candidates'].get(path)
        if self.record['phase'] in ('planned', 'staged') and item:
            raw = regular(self.directory/'certificate-stage'/path.lstrip('/'))[0]
            require(sha(raw) == item['after']['sha256'], 'certificate_stage_drift')
            return raw, item['after']
        return self.live(path)

    def stage(self):
        self.load()
        require(self.record['phase'] == 'planned', 'certificate_adoption_stage_order')
        units = []
        for path, item in self.record['candidates'].items():
            raw = self.future_live(path)[0]
            if path.endswith('.py'):
                compile(raw, path, 'exec')
            if path.startswith('/etc/systemd/system/') and path.endswith(('.service', '.timer')):
                units.append(str(self.directory/'certificate-stage'/path.lstrip('/')))
        self.commands.run('certificate_units_verify', ['systemd-analyze', 'verify', *units])
        self.record['phase'] = 'staged'
        self.save()
        return {'phase': 'staged'}

    def apply(self):
        self.load()
        require(self.record['phase'] == 'staged', 'certificate_adoption_apply_order')
        require_settled()
        for path, item in self.record['candidates'].items():
            actual = self.live(path)[1] if os.path.lexists(self.files.target(path)) else None
            require(actual == item['before'], 'certificate_adoption_CAS:'+path)
        STATE.mkdir(mode=0o700, exist_ok=True)
        require(STATE.stat().st_uid == 0 and not STATE.stat().st_mode & 0o077, 'certificate_state_permissions')
        durable_json(PENDING, {'format': 1, 'phase': 'changing', 'evidence': str(self.directory)})
        self.record['phase'] = 'stopping'
        self.save()
        stop_units = STOP if self.record['needs_restart'] else ()
        for name in stop_units:
            require(self.unit(name) == self.record['before_units'][name], 'certificate_unit_state_changed')
        for name in stop_units:
            if self.record['before_units'][name]['ActiveState'] == 'active':
                self.operation('stop', name)
        pending = self.commands.run('certificate_pending_downloads', ['mariadb', '--batch', '--skip-column-names', '-e',
            "SET SESSION time_zone='+00:00'; START TRANSACTION READ ONLY; SELECT COUNT(*) FROM mail_management.mail_client_downloads WHERE state IN ('ready','consumed','unknown') AND expires_at>UTC_TIMESTAMP(); ROLLBACK;"])
        require(pending.strip() == b'0', 'certificate_pending_downloads')
        for path, item in self.record['candidates'].items():
            actual = self.live(path)[1] if os.path.lexists(self.files.target(path)) else None
            require(actual == item['before'], 'certificate_adoption_CAS:'+path)
            raw = regular(self.directory/'certificate-stage'/path.lstrip('/'))[0]
            require(sha(raw) == item['after']['sha256'], 'certificate_stage_drift')
            self.files.write(path, raw, item['after']['mode'], 0, item['after']['gid'])
        self.record['phase'] = 'written'
        self.save()
        self.commands.run('certificate_daemon_reload', ['systemctl', 'daemon-reload'])
        for name in reversed(stop_units):
            if self.record['before_units'][name]['ActiveState'] == 'active':
                self.operation('start', name)
        from ca_rotation import verify_runtime, observe_gate
        verify_runtime(self.commands)
        if self.record['needs_restart'] and self.record['before_units']['mail-client-cert-gate.service']['ActiveState'] == 'active':
            observe_gate(self.commands)
        self.record['phase'] = 'adopted'
        self.save()
        durable_json(PENDING, {'format': 1, 'phase': 'complete', 'evidence': str(self.directory)})
        return {'phase': 'adopted', 'ACME_timer_state_preserved': True, 'data_and_credentials_preserved': True}

    def rollback(self):
        if not self.record_path.exists():
            return {'phase': 'not_started'}
        self.load()
        require(self.record['operation_started'] is None, 'certificate_adoption_operation_unknown')
        if self.record['phase'] in ('planned', 'staged', 'rolled_back'):
            self.record['phase'] = 'rolled_back'
            self.save()
            return {'phase': 'rolled_back', 'writes': 0}
        if PENDING.exists():
            pending = json.loads(trusted(PENDING, private=True)[0])
            require(pending['evidence'] == str(self.directory), 'certificate_other_migration_pending')
        durable_json(PENDING, {'format': 1, 'phase': 'restoring', 'evidence': str(self.directory)})
        stop_units = STOP if self.record['needs_restart'] else ()
        observed = {name: self.unit(name) for name in stop_units}
        durable_json(self.directory/'rollback-unit-observation.json', {
            'expected': self.record['last_units'], 'actual': observed})
        require(all(observed[name] == self.record['last_units'][name] for name in stop_units),
                'certificate_adoption_recovery_unit_changed')
        for name in stop_units:
            current = self.unit(name)
            if current['ActiveState'] == 'active':
                self.operation('stop', name)
        result = self.files.restore()
        require(result['status'] == 'restored', 'certificate_adoption_restore_held')
        self.commands.run('certificate_restore_daemon_reload', ['systemctl', 'daemon-reload'])
        for name in reversed(stop_units):
            if self.record['before_units'][name]['ActiveState'] == 'active':
                self.operation('start', name)
        self.record['phase'] = 'rolled_back'
        self.save()
        durable_json(PENDING, {'format': 1, 'phase': 'restored', 'evidence': str(self.directory)})
        return {'phase': 'rolled_back', 'data_and_credentials_preserved': True}
