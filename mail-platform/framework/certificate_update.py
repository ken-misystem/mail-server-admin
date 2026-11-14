"""Compose certificate adoption with the existing release update transaction."""
from certificate_adoption import CertificateAdoption, STOP
from certificate_state import certificate_lock
from generation_update import GenerationUpdate
from code_update import CodeUpdate


def native_hook(payload, directory, action):
    """Give the signed adoption hook its required lock and optional native-module paths."""
    from pathlib import Path
    import subprocess
    unit = 'mail-platform-certificate-migrate-'+directory.name.removeprefix('transaction-')+'-'+action+'.service'
    writable = '/etc /var /opt /usr/local /usr/share/roundcube /run/lock'
    if (Path(payload)/'blueprint/migrations/sieve-lock-v1/manifest.json').is_file():
        writable += ' /usr/lib/dovecot/modules'
    return subprocess.run(['/usr/bin/systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit='+unit,
        '--property=Type=exec', '--property=User=root', '--property=Group=root',
        '--property=NoNewPrivileges=yes', '--property=ProtectSystem=strict', '--property=ProtectHome=yes',
        '--property=PrivateTmp=yes', '--property=UMask=0077',
        '--property=CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETUID CAP_SETGID',
        '--property=AmbientCapabilities=CAP_SETUID', '--property=ReadWritePaths='+writable,
        '--property=RuntimeMaxSec=900', '--property=MemoryMax=1G', '--property=MemorySwapMax=0',
        '--property=CPUQuota=200%', '--property=RestrictAddressFamilies=AF_UNIX',
        '/usr/bin/python3', '-I', '-S', '-B', str(Path(payload)/'installer.py'), action,
        '--transaction', str(directory), '--native-migration-child'], capture_output=True, timeout=920)


def check_native_child(directory, action):
    import os
    from pathlib import Path
    from host_transaction import durable_json
    from certificate_state import require
    expected = 'mail-platform-certificate-migrate-'+directory.name.removeprefix('transaction-')+'-'+action+'.service'
    require(Path('/proc/self/cgroup').read_text().strip() == '0::/system.slice/'+expected,
            'certificate_migration_native_unit_scope')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    durable_json(directory/('certificate-native-'+action+'.json'), {
        'unit': expected, 'uid': os.geteuid(), 'NoNewPrivileges': status['NoNewPrivs'].strip(),
        'capabilities': {name: status[name].strip() for name in ('CapEff','CapPrm','CapBnd','CapAmb')},
        'lock_writable_mount': not bool(os.statvfs('/run/lock').f_flag & os.ST_RDONLY)})


class CertificateUpdate:
    def __init__(self, payload, directory, root='/', commands=None):
        from pathlib import Path
        import json
        self.adoption = CertificateAdoption(payload, Path(directory)/'certificate-adoption', root)
        contract = json.loads((Path(payload)/'blueprint/update-contract.json').read_bytes())
        base = GenerationUpdate if contract['format'] == 2 else CodeUpdate
        if contract['format'] != 2 and (Path(payload)/'blueprint/migrations/sieve-lock-v1/manifest.json').is_file():
            from sieve_migration import SieveMigration
            base = SieveMigration
        adoption = self.adoption

        class PreparedUpdate(base):
            allow_registered_additions = True
            def live(self, name):
                return adoption.future_live(name)

        self.engine = PreparedUpdate(payload, directory, root, commands)

    def plan(self):
        self.adoption.directory.mkdir(mode=0o700)
        adoption = self.adoption.plan()
        return dict(self.engine.plan(), certificate_adoption=adoption)

    def stage(self):
        self.adoption.stage()
        return self.engine.stage()

    def activate(self):
        # The parent updater owns update.lock. Serialise certificate jobs separately.
        with certificate_lock(update=False):
            self.adoption.apply()
        self.handoff_actor_states(self.adoption, self.engine, 'before-application')
        return self.engine.activate()

    def health(self):
        return self.engine.health()

    def retire(self):
        return self.engine.retire()

    def rollback(self):
        if self.adoption.record_path.exists():
            self.adoption.load()
            if self.adoption.record['phase'] == 'rolled_back':
                return {'phase': 'rolled_back', 'operations': 0}
        restored = self.engine.rollback()
        with certificate_lock(update=False):
            if getattr(self.engine, 'record', {}).get('activated'):
                self.handoff_actor_states(self.engine, self.adoption, 'after-rollback')
            certificate = self.adoption.rollback()
        return dict(restored, certificate_adoption=certificate)

    def handoff_actor_states(self, source, destination, label):
        """Carry only recorded actor transitions across the two recovery journals."""
        from certificate_state import require
        from host_transaction import durable_json
        source.load()
        destination.load()
        common = set(STOP) & source.record.get('last_units', {}).keys() & destination.record.get('last_units', {}).keys()
        observations = {}
        for name in sorted(common):
            expected = source.record['last_units'][name]
            actual = destination.unit(name)
            observations[name] = {'previous': destination.record['last_units'][name],
                                  'expected': expected, 'actual': actual}
        if not observations:
            return
        durable_json(self.adoption.directory/('actor-handoff-'+label+'.json'), observations)
        require(source.record.get('operation_started') is None, 'certificate_handoff_operation_unknown')
        require(all(item['actual'] == item['expected'] for item in observations.values()),
                'certificate_handoff_actor_state_changed')
        for name, item in observations.items():
            destination.record['last_units'][name] = item['actual']
        destination.save()
