"""New configuration/identity regressions. All inputs are synthetic."""
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'framework'))
from configuration_templates import ConfigurationError, describe, encode, references, render, templates
from identity_bindings import bind, rules
from install_preparation import baseline_identities, compile_tree, read_facts

SITE = json.loads((ROOT / 'site.example.json').read_bytes())


def synthetic_inputs():
    refs = set().union(*(references(template.value) for template in templates(SITE)))
    result = {'identities': {}, 'artifacts': {}, 'secrets': {}}
    for index, ref in enumerate(sorted(refs, key=lambda item: (item.section, item.name))):
        if ref.kind is int:
            value = 2100 + index
        elif ref.kind is list:
            value = [3100 + index]
        elif ref.section == 'secrets':
            value = 'SYNTHETIC-ONLY-' + ref.name + '-quote\'\\' + 'x' * 32
        elif ref.name.endswith('_sha256'):
            value = hashlib.sha256(ref.name.encode()).hexdigest()
        else:
            value = '/var/lib/mail-platform-test/' + ref.name + '.pem'
        result[ref.section][ref.name] = value
    # Some guards belong to public code but do not appear in a private template.
    result['identities']['www-data.uid'] = 2301
    result['identities']['www-data.gid'] = 2302
    return result


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.inputs = synthetic_inputs()

    def test_22_unique_templates(self):
        rows = templates(SITE)
        self.assertEqual(len(rows), 22)
        self.assertEqual(len({row.path for row in rows}), 22)

    def test_secrets_are_absent_from_public_plan(self):
        raw = json.dumps(describe(SITE))
        self.assertNotIn('SYNTHETIC-ONLY-', raw)
        self.assertNotIn('sha256', json.dumps([row.get('content') for row in describe(SITE)]))

    def test_no_migration_history_or_activation_marker(self):
        paths = set(render(SITE, self.inputs))
        self.assertNotIn('/etc/mail-client-certificates-v1/activation-approved.json', paths)
        self.assertFalse(any('migration-state' in path or 'retry-bootstrap' in path for path in paths))

    def test_closed_input_sections(self):
        with self.assertRaises(ConfigurationError):
            render(SITE, {**self.inputs, 'private_key': 'unaccepted'})

    def test_missing_secret_is_rejected_without_value(self):
        del self.inputs['secrets']['mail_management_app']
        with self.assertRaisesRegex(ConfigurationError, '^input_type_secrets$'):
            render(SITE, self.inputs)

    def test_boolean_identity_is_rejected(self):
        self.inputs['identities']['postfix.uid'] = True
        with self.assertRaises(ConfigurationError):
            render(SITE, self.inputs)

    def test_root_worker_identity_is_rejected(self):
        self.inputs['identities']['postfix.uid'] = 0
        with self.assertRaisesRegex(ConfigurationError, '^identity_range$'):
            render(SITE, self.inputs)

    def test_groups_require_integer_members(self):
        self.inputs['identities']['_rspamd.groups'] = [False]
        with self.assertRaisesRegex(ConfigurationError, '^supplementary_groups$'):
            render(SITE, self.inputs)

    def test_invalid_digest_is_rejected(self):
        self.inputs['artifacts']['private_main_sha256'] = 'not-a-digest'
        with self.assertRaisesRegex(ConfigurationError, '^artifact_digest$'):
            render(SITE, self.inputs)

    def test_parent_traversal_in_artifact_is_rejected(self):
        self.inputs['artifacts']['root_certificate'] = '/root/../unexpected.pem'
        with self.assertRaisesRegex(ConfigurationError, '^artifact_path$'):
            render(SITE, self.inputs)

    def test_php_literal_roundtrip_with_quotes_slashes_and_code(self):
        value = {'secret': "a'\\b<?php echo 1; ?>", 'array': [True, None, 12]}
        raw = encode(value, 'php').decode('ascii')
        literal = raw.split("json_decode('", 1)[1].rsplit("', true", 1)[0]
        decoded = re.sub(r"\\([\\'])", lambda match: match[1], literal)
        self.assertEqual(json.loads(decoded), value)

    def test_secret_modes_have_no_world_access(self):
        for row in templates(SITE):
            if any(ref.section == 'secrets' for ref in references(row.value)):
                self.assertEqual(row.mode & 0o007, 0)

    def test_new_notification_defaults(self):
        rendered = render(SITE, self.inputs)
        value = json.loads(rendered['/etc/mail-management-alerts-v1/runtime.json']['bytes'])
        self.assertFalse(value['enabled'])
        self.assertEqual(value['channels'], {'email': False, 'discord': False})

    def test_plugin_databases_match_public_contracts(self):
        rendered = render(SITE, self.inputs)
        for filename, schema in [('app-passwords.json', 'mailserver'), ('mail-pop.json', 'mail_management')]:
            value = json.loads(rendered['/etc/roundcube/' + filename]['bytes'])
            self.assertIn(';dbname=' + schema + ';', value['dsn'])
            self.assertEqual(list(value), ['dsn', 'user', 'password'])

    def test_all_guard_anchors_match_real_candidate(self):
        for path, old, _, _, count in rules():
            self.assertEqual((ROOT / 'payload' / path).read_text(encoding='utf-8').count(old), count, path)

    def test_policy_socket_matches_packaged_socket_unit(self):
        configs = render(SITE, self.inputs)
        value = json.loads(configs['/etc/mail-send-limits-v1/runtime.json']['bytes'])
        unit = (ROOT / 'payload/blueprint/systemd/mail-send-limits-v1.socket').read_text(encoding='utf-8')
        listen = re.search(r'^ListenStream=(.*)$', unit, re.M)[1]
        self.assertEqual(value['socket'], listen)

    def test_facts_reject_unknown_sections(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'facts.json'
            path.write_text('{"secrets":{}}')
            with self.assertRaisesRegex(ValueError, '^facts_fields$'):
                read_facts(path)

    def test_full_source_binding_and_secret_isolation(self):
        payload = ROOT / 'payload'
        facts = {key: self.inputs[key] for key in ('identities', 'artifacts')}
        code, configs, report = compile_tree(payload, SITE, facts, self.inputs['secrets'])
        self.assertEqual(len(configs), 22)
        self.assertFalse(report['host_configured'])
        self.assertNotIn('SYNTHETIC-ONLY-', json.dumps(report))
        self.assertNotIn(b'SYNTHETIC-ONLY-', b''.join(code.values()))
        path = 'usr/local/lib/mail-management-log-viewer-v1/collector.py'
        self.assertIn(('GROUP=' + str(facts['identities']['mailadmin.gid'])).encode(), code[path])
        self.assertIn(b'(0,2301)', code[path])
        for name, raw in code.items():
            if name.endswith('.py'):
                compile(raw, name, 'exec')
            if name.startswith('blueprint/systemd/'):
                self.assertIsNone(re.search(rb'^(?:User|Group|SupplementaryGroups)=[0-9]', raw, re.M))


if __name__ == '__main__':
    unittest.main()
