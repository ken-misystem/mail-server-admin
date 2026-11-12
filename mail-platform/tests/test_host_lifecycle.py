"""New service order, recovery and target compiler identity checks."""
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

PRODUCT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(PRODUCT / 'framework'), str(Path(__file__).parent)]
import host_install
from components_install import assemble
from test_host_candidate import facts, passwords, native_facts, SITE

UNITS = ['mail-send-limits-v1.socket', 'mail-send-limits-v1.service',
         'mail-feature-access-v1.socket', 'mail-feature-access-v1.service',
         'mail-client-cert-gate.socket', 'mail-client-cert-gate.service',
         'mail-feature-config-v1.service', 'mail-platform-update.timer']


class Recorder:
    def __init__(self, failure=None):
        self.calls = []
        self.failure = failure

    def run(self, label, argv, *unused, **kwargs):
        self.calls.append(argv)
        if label == self.failure:
            raise RuntimeError('injected_native_failure')
        return b''


def model(failure=None, active=False):
    installer = host_install.Installer(PRODUCT, SITE, 'synthetic-kit', 'synthetic-evidence')
    installer.commands = Recorder(failure)
    installer.files = types.SimpleNamespace(restore=lambda *a: {'status': 'restored', 'held_paths': []},
                                           write=lambda *a, **k: None)
    installer.activation_attempted = active
    return installer


class LifecycleChecks(unittest.TestCase):
    def test_start_and_enable_cover_persistent_and_socket_workers(self):
        installer = model()
        with patch.object(host_install, 'plan', return_value={'units': UNITS}):
            installer.start()
        calls = installer.commands.calls
        starts = [row[2] for row in calls if row[:2] == ['/usr/bin/systemctl', 'start']]
        for unit in host_install.PERSISTENT:
            self.assertIn(unit, starts)
        for unit in UNITS:
            self.assertIn(unit, starts)
        self.assertLess(starts.index('mail-legacy-smtp-auth.service'), starts.index('postfix.service'))
        self.assertLess(starts.index('mail-management-log-viewer.service'), starts.index('mail-feature-config-v1.service'))
        enabled = next(row for row in calls if row[1] == 'enable')
        self.assertTrue(set(host_install.PERSISTENT) <= set(enabled))

    def test_unknown_socket_service_is_refused(self):
        installer = model()
        with patch.object(host_install, 'plan', return_value={'units': ['unknown.socket']}):
            with self.assertRaisesRegex(ValueError, 'socket_service_inventory'):
                installer.start()

    def test_rollback_stops_sockets_before_services(self):
        installer = model(active=True)
        installer.started = ['postfix.service']
        with patch.object(host_install, 'plan', return_value={'units': UNITS}):
            result = installer.restore()
        stopped = [row[-1] for row in installer.commands.calls if row[1] == 'stop']
        self.assertTrue(all(name.endswith('.socket') for name in stopped[:3]))
        self.assertEqual(result['status'], 'restored')
        self.assertTrue(result['DB_and_credentials_preserved'])

    def test_stop_failure_is_retained_and_other_recovery_continues(self):
        installer = model('restore_mail_send_limits_v1_socket', active=True)
        with patch.object(host_install, 'plan', return_value={'units': UNITS}):
            result = installer.restore()
        self.assertEqual(result['status'], 'held')
        self.assertEqual(result['held_units'], ['mail-send-limits-v1.socket'])
        self.assertEqual(installer.commands.calls[-1], ['/usr/bin/systemctl', 'daemon-reload'])

    def test_pre_activation_recovery_does_not_stop_unstarted_stack(self):
        installer = model()
        installer.started = ['mariadb.service']
        result = installer.restore()
        stopped = [row[-1] for row in installer.commands.calls if row[1] == 'stop']
        self.assertEqual(stopped, ['mariadb.service'])
        self.assertEqual(result['status'], 'restored')

    def test_compiler_uses_target_vmail_UID_and_GID(self):
        values = assemble(PRODUCT / 'payload', SITE, facts(), passwords(), native_facts())
        compiler = next(row.raw.decode() for row in values if row.path.endswith('/compile.conf'))
        self.assertIn('mail_uid = ' + str(facts()['vmail.uid']), compiler)
        self.assertIn('mail_gid = ' + str(facts()['vmail.gid']), compiler)
        self.assertNotIn('= 5000', compiler)

    def test_Dovecot_view_grant_has_only_three_public_columns(self):
        from database_install import plan
        compiled = plan(PRODUCT / 'payload', passwords())
        row = next(row for row in compiled['steps'] if row['label'] == 'Dovecot_canonical_login_view')
        self.assertEqual(row['sql'], "GRANT SELECT ON mail_management.mail_client_bootstrap_login_owners TO 'mailreader'@'localhost'")
        import re
        ddl = (PRODUCT / 'payload/blueprint/schema.sql').read_text(encoding='utf-8')
        view = re.search(r'CREATE ALGORITHM=TEMPTABLE.*?VIEW `mail_management`[.]`mail_client_bootstrap_login_owners` AS (.*?);', ddl)[1]
        self.assertEqual(re.findall(r' AS `([^`]+)`', view.split(' union all ')[0]), ['login_name', 'owner_id', 'active'])


if __name__ == '__main__':
    unittest.main()
