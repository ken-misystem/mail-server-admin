"""Only new installation assembly changes and lifecycle boundaries."""
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

PRODUCT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PRODUCT / 'framework'))
sys.path.insert(0, str(Path(__file__).parent))
from test_host_candidate import facts, passwords, native_facts, SITE
from base_configuration import render
from host_install import Installer
from identity_bindings import bind
from install_preparation import baseline_identities, read_payload
from profile_bindings import bind as profile
import github


class HostDelta(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = read_payload(PRODUCT / 'payload')
        cls.bound, cls.guards = bind(cls.payload, facts(), baseline_identities(PRODUCT / 'payload'))
        recipes = json.loads(cls.payload['blueprint/install-recipes.json'])
        recipes['management_entry'] = cls.payload['blueprint/management_entry.php'].decode()
        cls.config = {row.path: row.raw.decode() for row in render(SITE, facts(), passwords(), recipes)}
        cls.recipes = recipes

    def test_POP_ingress_is_separate_and_nonchroot(self):
        master = self.config['/etc/postfix/master.cf']
        self.assertIn('127.0.0.1:10027', master)
        self.assertIn('mail-platform-milter.sock', master)

    def test_Roundcube_logical_IMAP_and_local_SMTP_TLS_name(self):
        config = self.config['/etc/roundcube/config.inc.php']
        self.assertIn('ssl://' + SITE['mail_host'] + ':993', config)
        self.assertIn('tls://127.0.0.1:587', config)
        self.assertIn('peer_name', config)
        self.assertIn('127.0.0.1:587', self.config['/etc/postfix/master.cf'])

    def test_passwords_are_64_hex_characters(self):
        import inspect
        self.assertIn('secrets.token_hex(32)', inspect.getsource(Installer.assemble))
        for value in passwords().values():
            self.assertRegex(value, r'^[0-9a-f]{64}$')

    def test_full_hidden_passkey_dependency_closure(self):
        prefix = 'usr/share/roundcube/plugins/.passkey-management-v2-mobile-fixed/local_auth/src/'
        self.assertEqual(sum(name.startswith(prefix) for name in self.payload), 38)
        self.assertIn('opt/roundcube-auth/vendor/autoload.php', self.payload)
        self.assertIn('blueprint/003_emergency_factor_recovery.sql', self.payload)

    def test_four_PyMySQL_consumers_use_same_artifact(self):
        names = [name for name in self.payload if name.endswith('pymysql-1.2.3-py3-none-any.whl')]
        self.assertEqual(len(names), 4)
        self.assertEqual(len({self.payload[name] for name in names}), 1)

    def test_AV_and_Roundcube_group_guards_follow_target(self):
        av = self.bound['opt/mail-antivirus-v1/identity_guard.py'].decode()
        self.assertIn('os.getegid()==' + str(facts()['_rspamd.gid']), av)
        pop = self.bound['usr/share/roundcube/plugins/mail_pop/mail_pop.php'].decode()
        self.assertIn("$info['gid']!==" + str(facts()['www-data.gid']), pop)

    def test_monitor_collector_UI_and_alerts_include_updater(self):
        output = profile(self.bound)
        for name in ('usr/local/lib/mail-management-operations-v1/read_runtime.py',
                     'usr/local/lib/mail-management-alerts-v1/channel_delivery.py',
                     'opt/mail-management/candidates/protection-relay-v1/src/OperationsSnapshot.php',
                     'opt/mail-management/candidates/protection-relay-v1/src/OperationsStatusController.php'):
            for unit in ('mail-platform-update.service', 'mail-platform-update.timer',
                         'mail-platform-update-ui.service', 'mail-platform-update-ui.socket'):
                self.assertIn(unit.encode(), output[name])
        namespace = {}
        source = output['usr/local/lib/mail-management-operations-v1/read_runtime.py'].decode()
        exec(source.split('COMMANDS = {')[0], namespace)
        self.assertEqual(len(namespace['UNITS']), 59)
        self.assertIn('mail-platform-update.service', namespace['ONESHOTS'])

    def test_optional_external_recovery_and_captcha_disabled(self):
        self.assertNotIn('turnstile', self.recipes['roundcube_plugins'])
        self.assertNotIn('local_password_recovery', self.recipes['roundcube_plugins'])
        self.assertIn('account_recovery', self.recipes['roundcube_plugins'])

    def test_five_jails_match_management_contract(self):
        import re
        self.assertEqual(re.findall(r'^\[([^]]+)\]', self.config['/etc/fail2ban/jail.d/mail-platform.conf'], re.M),
                         ['sshd', 'dovecot', 'postfix-sasl', 'roundcube-auth', 'recidive'])

    def test_empty_GitHub_release_list_is_normal(self):
        with patch.object(github, 'request', return_value=b'[]'):
            self.assertIsNone(github.latest('Yaruani/mail-server-admin'))

    def test_drafts_and_prereleases_are_not_selected(self):
        rows = [{'tag_name': 'v3.0.0', 'draft': True}, {'tag_name': 'v2.0.0', 'prerelease': True}]
        with patch.object(github, 'request', return_value=json.dumps(rows).encode()):
            self.assertIsNone(github.latest('Yaruani/mail-server-admin'))

    def test_stable_release_selection_uses_numeric_version(self):
        assets = [{'name': name, 'id': index + 1} for index, name in
                  enumerate(('mail-platform.tar.gz', 'release.json', 'release.sig'))]
        rows = [{'tag_name': name, 'assets': assets} for name in ('v1.9.0', 'v1.10.0', 'v1.2.0')]
        with patch.object(github, 'request', return_value=json.dumps(rows).encode()):
            self.assertEqual(github.latest('Yaruani/mail-server-admin')['tag'], 'v1.10.0')

    def test_all_phase_boundaries_stop_without_replaying(self):
        phases = ['packages', 'identities', 'assemble', 'database', 'files', 'native_validation',
                  'administrator', 'start', 'health']
        methods = {'files': 'write_files'}
        for failure in [None] + phases:
            with self.subTest(failure=failure):
                observed = []
                installer = object.__new__(Installer)
                installer.evidence = Path('synthetic-evidence')
                def step(name, operation):
                    observed.append(name)
                    return operation()
                installer.transaction = types.SimpleNamespace(step=step, finish=lambda *a, **k: observed.append('finish'))
                for name in phases:
                    def operation(name=name, **unused):
                        if name == failure:
                            raise ValueError('injected_' + name)
                    setattr(installer, methods.get(name, name), operation)
                installer.seal_installation = lambda: observed.append('receipt')
                if failure is None:
                    self.assertEqual(installer.execute_steps({})['status'], 'complete')
                    self.assertEqual(observed, phases + ['receipt', 'finish'])
                else:
                    with self.assertRaisesRegex(ValueError, 'injected_'):
                        installer.execute_steps({})
                    self.assertEqual(observed, phases[:phases.index(failure) + 1])


if __name__ == '__main__':
    unittest.main()
