"""New ownership, routing-contract and secondary-recipient boundaries."""
import copy
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'framework'))
from availability_plan import configuration, select
from generation_units import fpm
from release import canonical, sha
from secondary_mx import registry, recipient_action, render


def configured():
    return {'format': 1, 'generation_root': '/var/lib/mail-platform-update/generations',
            'components': {'web': {'kind': 'web', 'roots': ['/opt/web'],
                'route': '/etc/mail-platform/web-route.json', 'control': '/run/web/control.sock',
                'runtime': '/run/mail-platform-generations/web', 'unit': 'mail-platform-web@.service',
                'template': '/etc/mail-platform/web-fpm.conf', 'drain_seconds': 3,
                'health': {'kind': 'fcgi', 'request': '/opt/web/health.php', 'reply': 'READY'}}}}


class AvailabilityDelta(unittest.TestCase):
    def contract(self, config):
        return {'format': 2, 'from_version': '0.1.1', 'to_version': '0.1.2',
                'components': ['web'], 'configuration_sha256': sha(canonical(config))}

    def test_exact_component_ownership(self):
        config = configured()
        self.assertEqual(select(self.contract(config), config, ['/opt/web/index.php']),
                         {'/opt/web/index.php': ['web']})

    def test_changed_delivery_code_is_uncovered(self):
        config = configured()
        with self.assertRaisesRegex(ValueError, 'uncovered_code'):
            select(self.contract(config), config, ['/usr/local/lib/mail-send-limits-v1/launch.py'])

    def test_shared_dependency_requires_every_consumer(self):
        config = configured()
        config['components']['other'] = copy.deepcopy(config['components']['web'])
        with self.assertRaisesRegex(ValueError, 'uncovered_code'):
            select(self.contract(config), config, ['/opt/web/shared.php'])
        contract = self.contract(config)
        contract['components'].append('other')
        self.assertEqual(select(contract, config, ['/opt/web/shared.php'])['/opt/web/shared.php'], ['web', 'other'])

    def test_config_changes_require_new_signed_contract(self):
        config = configured()
        contract = self.contract(config)
        config['components']['web']['drain_seconds'] = 4
        with self.assertRaisesRegex(ValueError, 'configuration_drift'):
            select(contract, config, ['/opt/web/index.php'])

    def test_nested_roots_within_component_rejected(self):
        config = configured()
        config['components']['web']['roots'].append('/opt/web/vendor')
        with self.assertRaisesRegex(ValueError, 'root_overlap'):
            configuration(config)

    def test_no_version_downgrade(self):
        config = configured()
        contract = self.contract(config)
        contract['to_version'] = '0.1.0'
        with self.assertRaisesRegex(ValueError, 'contract_version'):
            select(contract, config, ['/opt/web/index.php'])

    def test_generation_unit_has_process_and_code_isolation(self):
        value = fpm('web', '/var/lib/mail-platform-update/generations',
                    '/run/mail-platform-generations/web', ['/opt/web'], 'www-data', 'www-data')
        self.assertIn(b'BindReadOnlyPaths=', value['unit'])
        self.assertIn(b'KillSignal=SIGQUIT', value['unit'])
        self.assertIn(b'CapabilityBoundingSet=\n', value['unit'])
        self.assertNotIn(b'php8.4-fpm.service', value['unit'])

    def test_template_identity_injection_rejected(self):
        with self.assertRaises(ValueError):
            fpm('web', '/var/lib/gen', '/run/gen', ['/opt/web'], 'www-data\nUser=root', 'www-data')

    def snapshot(self):
        return {'format': 1, 'generation': 4, 'issued': 100, 'expires': 200,
                'domains': ['example.test'], 'recipients': ['user@example.test', 'alias@example.test']}

    def test_recipient_and_alias(self):
        for address in ('user@example.test', 'alias@example.test'):
            self.assertEqual(recipient_action(self.snapshot(), address, 150), 'DUNNO')

    def test_unknown_and_relay_rejected(self):
        self.assertTrue(recipient_action(self.snapshot(), 'absent@example.test', 150).startswith('550'))
        self.assertTrue(recipient_action(self.snapshot(), 'user@outside.test', 150).startswith('554'))

    def test_expiry_is_temporary_failure(self):
        self.assertTrue(recipient_action(self.snapshot(), 'user@example.test', 200).startswith('451'))

    def test_catchall_is_explicit(self):
        value = self.snapshot()
        value['recipients'].append('@example.test')
        self.assertEqual(recipient_action(value, 'new@example.test', 150), 'DUNNO')

    def test_recipient_cross_domain_and_config_injection(self):
        value = self.snapshot()
        value['recipients'].append('user@outside.test')
        with self.assertRaisesRegex(ValueError, 'recipient_domain'):
            registry(value, 150)
        from secondary_mx import hostname
        with self.assertRaises(ValueError):
            hostname('mx.test\nrelay_domains = *')


class AvailabilityOperationalChecks(unittest.TestCase):
    def current_registry(self):
        import time
        now=int(time.time())
        return {'format':1,'generation':1,'issued':now-1,'expires':now+60,
                'domains':['example.test'],'recipients':['user@example.test']}

    def test_filter_and_size_enrollment_are_mandatory(self):
        value=self.current_registry()
        with self.assertRaisesRegex(ValueError,'filter_enrollment_required'):
            render(value,'secondary.example.test','primary.example.test','/etc/secondary',7200,1)
        with self.assertRaisesRegex(ValueError,'message_limit_required'):
            render(value,'secondary.example.test','primary.example.test','/etc/secondary',7200,1,
                   milter_socket='/run/secondary/filter.sock')

    def test_filter_failure_is_closed_and_transport_is_fixed(self):
        result=render(self.current_registry(),'secondary.example.test','primary.example.test','/etc/secondary',7200,1,
                      milter_socket='/run/secondary/filter.sock',message_size_limit=10485760)
        self.assertIn(b'milter_default_action = tempfail',result['main.cf'])
        self.assertIn(b'reject_unauth_destination',result['main.cf'])
        self.assertEqual(result['transport'],b'example.test relay:[primary.example.test]:25\n')

    def test_FPM_readiness_and_logging_match_systemd(self):
        result=fpm('web','/var/lib/mail-platform-generations','/run/mail-platform-generations/web',
                   ['/opt/web'],'www-data','www-data')
        self.assertIn(b'Type=notify\n',result['unit'])
        self.assertIn('error_log = syslog',result['fpm_config_template'])
        self.assertIn('user = www-data',result['fpm_config_template'])

    def test_signed_impact_preview_is_bounded(self):
        from availability_plan import release_impact
        value={'format':2,'components':['web']}
        result=release_impact({'payload/blueprint/update-contract.json':(canonical(value),0o644)})
        self.assertEqual(result['components'],['web'])
        with self.assertRaisesRegex(ValueError,'preview_components'):
            release_impact({'payload/blueprint/update-contract.json':(canonical({'format':2,'components':['<script>']}),0o644)})


if __name__ == '__main__':
    unittest.main()
