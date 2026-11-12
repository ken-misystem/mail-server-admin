"""New host recipe/model checks. No OS, database or service commands are executed."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import unittest

PRODUCT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PRODUCT / 'framework'))
from base_configuration import render as render_base
from components_install import assemble, recipe
from database_install import grants, plan as database_plan, principals, statements
from host_install import Installer, plan as host_plan
from configuration_templates import references, templates

SITE = json.loads((PRODUCT / 'site.example.json').read_bytes())


def facts():
    identities = {}
    users = json.loads((PRODUCT / 'payload/blueprint/identities.json').read_bytes())['users']
    for index, name in enumerate(sorted(set(users) | {'mailadmin', 'vmail', 'www-data'})):
        identities[name + '.uid'] = 21000 + index
        identities[name + '.gid'] = 31000 + index
    identities['_rspamd.groups'] = [identities['_rspamd.gid']]
    return identities


def passwords():
    metadata = json.loads((PRODUCT / 'payload/blueprint/grants.json').read_bytes())
    return {name: 'a' * 64 for name in set(principals(metadata)) |
            {'management_application', 'roundcube_session', 'postsrsd_secret'}}


def native_facts():
    return {'owner_lifecycle_activation_cutoff': 1700000000,
            'ca': {name: {'path': '/var/lib/mail-platform-pki/' + name, 'sha256': 'a' * 64}
                   for name in ('root', 'issuer', 'root_crl', 'custody', 'restoration', 'custody_statement')},
            'executables': {'smtpd': 'b' * 64}, 'certificate_manifest_sha256': 'c' * 64,
            'settings_sha256': hashlib.sha256(b'{}').hexdigest(), 'host_namespace': [4, 1234],
            'actor_gids': {name: 33000 + index for index, name in
                           enumerate(('owner', 'lifecycle', 'verifier', 'issuer', 'gate'))}}


class SQLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiled = database_plan(PRODUCT / 'payload', passwords())

    def test_quoted_semicolon_is_not_a_statement_boundary(self):
        self.assertEqual(statements("SELECT 'a;b'; SELECT `x;y`;"), ["SELECT 'a;b'", 'SELECT `x;y`'])

    def test_comments_and_escaped_quotes(self):
        self.assertEqual(statements("-- skip ;\nSELECT 'a''b'; /* ; */ SELECT 1;"), ["SELECT 'a''b'", 'SELECT 1'])

    def test_unclosed_quote_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SQL_unclosed_quote'):
            statements("SELECT 'unfinished")

    def test_executable_comment_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'SQL_executable_comment'):
            statements('/*! DROP DATABASE x */;')

    def test_definer_grants_precede_views(self):
        steps = self.compiled['steps']
        first = next(index for index, row in enumerate(steps) if row['label'].startswith('view_'))
        self.assertTrue(any("TO 'mailcert_views_v1'" in row.get('sql', '') and 'virtual_users' in row['sql']
                            for row in steps[:first]))

    def test_all_39_existing_objects_have_additive_definitions(self):
        text = (PRODUCT / 'payload/blueprint/schema.sql').read_text(encoding='utf-8')
        self.assertEqual(len(re.findall(r'CREATE TABLE `', text)) + len(re.findall(r' VIEW `', text)), 39)

    def test_schema_contains_no_drop_or_wildcard_grant(self):
        text = '\n'.join(row.get('sql', '') for row in self.compiled['steps'])
        self.assertIsNone(re.search(r'\b(?:DROP|TRUNCATE|GRANT OPTION|ALL PRIVILEGES)\b', text))

    def test_view_definer_is_locked(self):
        row = next(row for row in self.compiled['steps'] if row['label'] == 'account_mailcert_views_v1')
        self.assertTrue(row['sql'].endswith('ACCOUNT LOCK'))

    def test_new_session_and_verifier_principals_are_separate(self):
        self.assertIn('mailcert_session_v1', self.compiled['principals'])
        self.assertIn('mailcert_verify_v1', self.compiled['principals'])
        sql = '\n'.join(row.get('sql', '') for row in self.compiled['steps'])
        self.assertNotRegex(sql, r"GRANT UPDATE .*auth_webauthn_credentials.*mail_management_app")

    def test_missing_credential_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'credentials_incomplete'):
            database_plan(PRODUCT / 'payload', {})

    def test_password_SQL_injection_is_rejected(self):
        values = passwords()
        values['mailreader'] = "' OR 1=1 --"
        with self.assertRaisesRegex(ValueError, 'password_format'):
            database_plan(PRODUCT / 'payload', values)


class AssemblyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.resources = assemble(PRODUCT / 'payload', SITE, facts(), passwords(), native_facts())
        cls.by_path = {item.path: item for item in cls.resources}

    def test_resource_names_are_unique(self):
        self.assertEqual(len(self.resources), len(self.by_path))

    def test_five_actor_primary_groups_use_actual_unit_facts(self):
        for name, group in native_facts()['actor_gids'].items():
            cfg = json.loads(self.by_path['/etc/mail-client-certificates-v1/' + name + '.json'].raw)
            self.assertEqual(cfg['peers'][name]['gid'], group)

    def test_roundcube_peer_is_www_data(self):
        cfg = json.loads(self.by_path['/etc/mail-client-certificates-v1/owner.json'].raw)
        self.assertEqual(cfg['peers']['fpm']['uid'], facts()['www-data.uid'])

    def test_web_peer_gid_matches_owner_unit(self):
        cfg = json.loads(self.by_path['/etc/mail-client-certificates-v1/web.json'].raw)
        self.assertEqual(cfg['owner_gid'], native_facts()['actor_gids']['owner'])

    def test_backend_pins_match_both_generated_files(self):
        cfg = json.loads(self.by_path['/etc/mail-client-certificates-v1/smtpd.json'].raw)
        for name, pin in cfg['pins'].items():
            raw = self.by_path['/etc/mail-client-certificates-v1/postfix/' + name].raw
            self.assertEqual(hashlib.sha256(raw).hexdigest(), pin)

    def test_private_SMTP_has_device_milter_and_antispam_and_DATA_limit(self):
        main = self.by_path['/etc/mail-client-certificates-v1/postfix/main.cf'].raw
        self.assertIn(b'/native/milter.sock, unix:', main)
        self.assertIn(b'/native/rspamd.sock', main)
        self.assertIn(b'check_policy_service unix:/run/mail-send-limits-v1/policy.sock', main)

    def test_all_default_protection_targets_exist(self):
        context = json.loads(self.by_path['/var/lib/mail-protection-admin-v1/context.json'].raw)
        for paths in context['expected'].values():
            for path, pin in paths.items():
                self.assertEqual(hashlib.sha256(self.by_path[path].raw).hexdigest(), pin)

    def test_credential_files_are_not_world_readable(self):
        for item in self.resources:
            if b'S' * 64 in item.raw:
                self.assertEqual(item.mode & 0o007, 0, item.path)

    def test_one_protection_loader(self):
        scripts = [item for item in self.resources if item.path.endswith('.lua') and '/etc/' in item.path]
        self.assertEqual(len(scripts), 1)

    def test_no_live_resource_reads_in_pure_assembly(self):
        self.assertTrue(all(item.path.startswith('/') for item in self.resources))
        self.assertNotIn('/etc/mail-client-certificates-v1/activation-approved.json', self.by_path)

    def test_new_history_is_empty(self):
        cfg = json.loads(self.by_path['/var/lib/mail-feature-runtime-v1/configuration.json'].raw)
        self.assertEqual(cfg['serial'], 0)
        self.assertEqual(cfg['health'], {})

    def test_legacy_specific_timers_excluded(self):
        compiled = host_plan(PRODUCT, SITE)
        self.assertNotIn('mail-pop-account1.timer', compiled['units'])
        self.assertNotIn('mail-residual-pop-v1.timer', compiled['units'])
        self.assertFalse(compiled['host_changes'])

    def test_plan_contains_all_OS_phases(self):
        self.assertEqual(host_plan(PRODUCT, SITE)['phase_order'][-4:],
                         ['native_validation', 'administrator', 'start', 'health'])

    def test_schema_and_assembly_new_secrets_stay_in_memory(self):
        public = host_plan(PRODUCT, SITE)
        self.assertNotIn('S' * 64, json.dumps(public))


if __name__ == '__main__':
    unittest.main()
