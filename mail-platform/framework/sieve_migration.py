"""Signed, one-time adoption of the native Sieve session lock on a 0.3.x host."""
import json
import os
from pathlib import Path
import re
import subprocess

from code_update import CodeUpdate, render
from release import sha
from sieve_lock import MODULE, SOURCE, validate
from policy_binding import DROPIN, CONTENT, ensure_directories, probe

DESCRIPTOR = 'blueprint/migrations/sieve-lock-v1/manifest.json'
PREFIX = 'blueprint/migrations/sieve-lock-v1/'
CONFIGURATION = '/etc/dovecot/dovecot.conf'
ANCHOR = b'mail_plugins {\n quota = yes\n}'
REPLACEMENT = b'mail_plugins {\n quota = yes\n mail_sieve_session_lock = yes\n}'


def native_hook(payload, directory, action):
    """Use one explicit native path exception outside the legacy updater mount view."""
    unit = 'mail-platform-sieve-migrate-' + directory.name.removeprefix('transaction-') + '-' + action + '.service'
    command = ['/usr/bin/systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit='+unit,
               '--property=Type=exec', '--property=User=root', '--property=Group=root',
               '--property=NoNewPrivileges=yes', '--property=ProtectSystem=strict',
               '--property=ProtectHome=yes', '--property=PrivateTmp=yes', '--property=UMask=0077',
               '--property=CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETUID CAP_SETGID',
               '--property=AmbientCapabilities=CAP_SETUID',
               '--property=ReadWritePaths=/etc /var /opt /usr/local /usr/share/roundcube /usr/lib/dovecot/modules',
               '--property=RuntimeMaxSec=600', '--property=MemoryMax=512M', '--property=MemorySwapMax=0',
               '--property=CPUQuota=100%', '--property=RestrictAddressFamilies=AF_UNIX',
               '/usr/bin/python3', '-I', '-S', '-B', str(payload/'installer.py'), action,
               '--transaction', str(directory), '--native-migration-child']
    return subprocess.run(command, capture_output=True, timeout=620)


def check_native_child(directory, action):
    expected = 'mail-platform-sieve-migrate-' + directory.name.removeprefix('transaction-') + '-' + action + '.service'
    if Path('/proc/self/cgroup').read_text().strip() != '0::/system.slice/'+expected:
        raise ValueError('sieve_migration_native_unit_scope')
    from host_transaction import durable_json
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    durable_json(directory/('native-unit-'+action+'.json'),
                 {'unit': expected, 'uid': os.geteuid(),
                  'capabilities': {name: status[name].strip() for name in ('CapEff', 'CapPrm', 'CapBnd', 'CapAmb')},
                  'NoNewPrivileges': status['NoNewPrivs'].strip(),
                  'native_directory_readonly': bool(os.statvfs('/usr/lib/dovecot/modules').f_flag & os.ST_RDONLY)})


def add_assets(files, kit, old_receipt):
    """Add public native assets and the precise approved source blueprint inventory."""
    receipt = json.loads(Path(old_receipt).read_bytes())
    blueprints = receipt['blueprints']
    if (not receipt['version'].startswith('0.3.') or type(blueprints) is not dict or SOURCE in blueprints
            or any(not name.startswith('blueprint/') or not re.fullmatch('[a-f0-9]{64}', value)
                   for name, value in blueprints.items())):
        raise ValueError('sieve_migration_asset_source')
    module = (Path(kit)/'sieve-session-lock.so').read_bytes()
    metadata = json.loads((Path(kit)/'sieve-session-lock.json').read_bytes())
    validate(module, metadata, files['payload/'+SOURCE])
    descriptor = {'format': 1, 'kind': 'sieve-lock-v1', 'from_blueprints': blueprints, 'module_metadata': metadata}
    files['payload/'+DESCRIPTOR] = (json.dumps(descriptor, sort_keys=True, indent=2)+'\n').encode()
    files['payload/'+PREFIX+'module.so'] = module


class SieveMigration(CodeUpdate):
    def descriptor(self, receipt):
        value = json.loads((self.payload / DESCRIPTOR).read_bytes())
        if set(value) != {'format', 'kind', 'from_blueprints', 'module_metadata'} or value['format'] != 1 or value['kind'] != 'sieve-lock-v1':
            raise ValueError('sieve_migration_descriptor')
        if not receipt['version'].startswith('0.3.') or receipt['blueprints'] != value['from_blueprints']:
            raise ValueError('sieve_migration_source_receipt')
        if SOURCE in receipt['blueprints'] or MODULE in receipt['code']:
            raise ValueError('sieve_migration_already_installed')
        module = (self.payload / PREFIX / 'module.so').read_bytes()
        validate(module, value['module_metadata'], (self.payload / SOURCE).read_bytes())
        return value, module

    def render(self, receipt):
        value, module = self.descriptor(receipt)
        augmented = dict(receipt, blueprints=dict(receipt['blueprints'], **{SOURCE: sha((self.payload / SOURCE).read_bytes())}))
        bound = render(self.payload, augmented, self.live)
        configuration, _ = self.live(CONFIGURATION)
        if configuration.count(ANCHOR) != 1 or b'mail_sieve_session_lock' in configuration:
            raise ValueError('sieve_migration_configuration_requires_review')
        bound[PREFIX + 'module.so'] = module
        bound[PREFIX + 'dovecot.conf'] = configuration.replace(ANCHOR, REPLACEMENT)
        bound[PREFIX + 'policy-stops.conf'] = CONTENT
        return bound

    def plan(self):
        result = super().plan()
        if 'dovecot.service' not in self.record['contract']['stop'] or 'dovecot.service' not in self.record['contract']['health']:
            raise ValueError('sieve_migration_requires_Dovecot_session_retirement')
        stopped = self.record['contract']['stop']
        required = ['mail-client-cert-owner.service','mail-client-cert-gate.socket',
                    'mail-client-cert-gate.service','mail-client-cert-postfix-backend.service',
                    'postfix.service','mail-send-limits-v1.socket','mail-send-limits-v1.service',
                    'mail-feature-admin-v1.service']
        if (any(unit not in stopped for unit in required)
                or [stopped.index(unit) for unit in required] != sorted(stopped.index(unit) for unit in required)):
            raise ValueError('sieve_migration_policy_socket_dependencies_require_maintenance_order')
        starts = self.record['contract']['start']
        resumed = ['mail-send-limits-v1.socket','mail-feature-admin-v1.service','mail-send-limits-v1.service','postfix.service',
                   'mail-client-cert-postfix-backend.service','mail-client-cert-gate.socket',
                   'mail-client-cert-gate.service','mail-client-cert-owner.service']
        if [starts.index(unit) for unit in resumed] != sorted(starts.index(unit) for unit in resumed):
            raise ValueError('sieve_migration_policy_socket_dependencies_require_resume_order')
        bound = self.render(self.record['old_receipt'])
        if os.path.lexists(self.files.target(MODULE)):
            raise ValueError('sieve_migration_module_collision')
        configuration = self.live(CONFIGURATION)[1]
        if configuration['uid'] != 0 or configuration['mode'] & 0o022:
            raise ValueError('sieve_migration_configuration_trust')
        binding = self.live(DROPIN)[1] if os.path.lexists(self.files.target(DROPIN)) else None
        if binding is not None and self.live(DROPIN)[0] != CONTENT:
            raise ValueError('sieve_migration_stop_binding_requires_review')
        for target, source, before, mode in [(MODULE, PREFIX+'module.so', None, 0o644),
                                              (CONFIGURATION, PREFIX+'dovecot.conf', configuration, configuration['mode']),
                                              (DROPIN, PREFIX+'policy-stops.conf', binding, 0o644)]:
            self.record['candidates'][target] = {'before': before,
                'after': {'sha256': sha(bound[source]), 'mode': mode,
                          'uid': 0 if before is None else before['uid'], 'gid': 0 if before is None else before['gid']},
                'source': source}
        self.record['sieve_source_blueprint'] = sha((self.payload / SOURCE).read_bytes())
        self.save()
        return dict(result, files=len(self.record['candidates']), migration='sieve-lock-v1',
                    existing_Sieve_sessions='closed by the required Dovecot stop before code replacement')

    def activate(self):
        ensure_directories()
        return super().activate()

    def health(self):
        self.load()
        self.operation('start', 'mail-feature-admin-v1.service')
        self.operation('start', 'mail-send-limits-v1.service')
        probe(self.commands)
        result = super().health()
        self.commands.run('sieve_native_configuration', ['/usr/bin/doveconf', '-h', 'mail_plugins'])
        return result

    def updated_receipt(self):
        receipt = super().updated_receipt()
        receipt['code'].pop(CONFIGURATION)
        receipt['unit_files'].pop(Path(DROPIN).name)
        receipt['blueprints'] = dict(receipt['blueprints'], **{SOURCE: self.record['sieve_source_blueprint']})
        receipt['native_migrations'] = dict(receipt.get('native_migrations', {}), sieve_session_lock='v1')
        return receipt
