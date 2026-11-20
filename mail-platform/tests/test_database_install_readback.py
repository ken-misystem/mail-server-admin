"""Regression coverage for the fresh MariaDB schema readback."""
import unittest
from unittest.mock import Mock

from test_host_candidate import PRODUCT, database_plan, passwords
from database_install import execute


class DatabaseReadbackTests(unittest.TestCase):
    def setUp(self):
        self.compiled = database_plan(PRODUCT / 'payload', passwords())
        self.tables = set(self.compiled['schema_objects'])

    def readback(self, objects, seed_rows=('2', '2')):
        lines = ['\t'.join(row) for row in sorted(objects, reverse=True)] + list(seed_rows)
        commands = Mock()
        commands.run.side_effect = [b'0\n0\t0\n0\n', ('\n'.join(lines) + '\n').encode()]
        transaction = Mock()
        execute(self.compiled, commands, transaction, '')
        label, _, query = commands.run.call_args.args
        self.assertEqual(label, 'database_schema_readback')
        self.assertIn(b'TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE', query)

    def test_fresh_schema_includes_both_passkey_tables(self):
        self.assertEqual(len(self.tables), 41)
        self.assertEqual(sum(row[2] == 'VIEW' for row in self.tables), 4)
        for name in ('webmail_passkey_sessions', 'webmail_passkey_challenges'):
            self.assertIn(('mailserver', name, 'BASE TABLE'), self.tables)
            self.assertTrue(any(step.get('sql', '').startswith(f'CREATE TABLE mailserver.{name} (')
                                for step in self.compiled['steps']))
        self.readback(self.tables)

    def test_legacy_count_without_passkey_tables_fails(self):
        rows = {row for row in self.tables if not row[1].startswith('webmail_passkey_')}
        with self.assertRaisesRegex(ValueError, '^database_schema_readback$'):
            self.readback(rows)

    def test_unrelated_table_cannot_replace_either_passkey_table(self):
        for name in ('webmail_passkey_sessions', 'webmail_passkey_challenges'):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, '^database_schema_readback$'):
                rows = self.tables - {('mailserver', name, 'BASE TABLE')}
                self.readback(rows | {('mailserver', 'unrelated', 'BASE TABLE')})

    def test_wrong_schema_or_type_is_rejected(self):
        name = 'webmail_passkey_sessions'
        rows = self.tables - {('mailserver', name, 'BASE TABLE')}
        for wrong in (('mail_management', name, 'BASE TABLE'), ('mailserver', name, 'VIEW')):
            with self.subTest(wrong=wrong), self.assertRaisesRegex(ValueError, '^database_schema_readback$'):
                self.readback(rows | {wrong})

    def test_initial_lock_and_limit_counts_are_still_required(self):
        for seed_rows in (('1', '2'), ('2', '1')):
            with self.subTest(seed_rows=seed_rows), self.assertRaisesRegex(ValueError, '^database_schema_readback$'):
                self.readback(self.tables, seed_rows)
