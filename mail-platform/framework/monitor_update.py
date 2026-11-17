"""Add site-owned monitoring references before a signed code update.

The old collector must match its installed ownership receipt. No old code is
executed. Created configuration is retained on rollback; existing bytes are
never rewritten. The ordinary engine still owns every service/code operation.
"""
import json
import os
from pathlib import Path

from host_transaction import Files, durable_json, regular
from monitor_binding import RUNTIME, adoption, trusted
from monitor_environment import MONITOR_CONFIG, monitor_decode, monitor_targets
from release import sha

DESCRIPTOR = 'blueprint/migrations/monitor-environment-v1.json'
CONTRACT = {'format': 1, 'source': 'installed-collector-commands',
            'existing': 'preserve', 'rollback': 'retain-created-config'}


def wrap(base):
    class MonitoringUpdate(base):
        def __init__(self, payload, transaction, root='/', commands=None):
            super().__init__(payload, transaction, root, commands)
            if json.loads((Path(payload)/DESCRIPTOR).read_bytes()) != CONTRACT:
                raise ValueError('monitor_migration_descriptor')
            self.monitor_path = self.directory/'monitor-migration.json'
            self.monitor_files = Files(self.root, self.directory/'monitor-configuration')

        def actual(self, name):
            return super().live(name)

        def monitor_check(self):
            raw, metadata = regular(self.monitor_path)
            if metadata['uid'] != 0 or metadata['mode'] != 0o600:
                raise ValueError('monitor_migration_journal_trust')
            record = json.loads(raw)
            target = self.files.target(MONITOR_CONFIG)
            if os.path.lexists(target):
                current = self.actual(MONITOR_CONFIG)
                if current[1] != record['expected'] or current[0].decode() != record['raw']:
                    raise ValueError('monitor_migration_configuration_drift')
                monitor_targets(monitor_decode(trusted(*current)), self.root)
            elif record['existing'] or record['phase'] == 'written':
                raise ValueError('monitor_migration_configuration_missing')
            else:
                old, info = self.actual(RUNTIME)
                if info != record['source']:
                    raise ValueError('monitor_migration_source_drift')
                monitor_targets(monitor_decode(record['raw'].encode()), self.root)
            return record

        def live(self, name):
            if name == MONITOR_CONFIG and self.monitor_path.exists():
                record = self.monitor_check()
                return record['raw'].encode(), record['expected']
            return self.actual(name)

        def plan(self):
            if self.monitor_path.exists():
                raise ValueError('monitor_migration_already_planned')
            exists = lambda name: os.path.lexists(self.files.target(name))
            present = exists(MONITOR_CONFIG)
            source = None
            if not present:
                receipt_raw, receipt_meta = self.actual('/var/lib/mail-platform-update/installed-code.json')
                if receipt_meta['uid'] != 0 or receipt_meta['mode'] != 0o600:
                    raise ValueError('monitor_migration_receipt_trust')
                source = self.actual(RUNTIME)[1]
                if json.loads(receipt_raw)['code'].get(RUNTIME) != source:
                    raise ValueError('monitor_migration_unowned_collector')
            raw = adoption(self.actual, exists, self.root)
            if present:
                raw, expected = self.actual(MONITOR_CONFIG)
            else:
                expected = {'sha256': sha(raw), 'uid': 0, 'gid': 0, 'mode': 0o644}
            durable_json(self.monitor_path, {'phase': 'planned', 'existing': present,
                'source': source, 'raw': raw.decode(), 'expected': expected})
            return super().plan()

        def stage(self):
            self.monitor_check()
            return super().stage()

        def load(self):
            self.monitor_check()
            return super().load()

        def activate(self):
            record = self.monitor_check()
            if record['phase'] != 'planned':
                raise ValueError('monitor_migration_activation_order')
            if not record['existing']:
                self.monitor_files.state.mkdir(mode=0o700)
                self.monitor_files.write(MONITOR_CONFIG, record['raw'].encode(), preserve=True,
                                         expected_before=None)
            record['phase'] = 'written'
            durable_json(self.monitor_path, record)
            self.monitor_check()
            return super().activate()

        def rollback(self):
            if self.monitor_path.exists():
                self.monitor_check()
            return super().rollback()

    return MonitoringUpdate
