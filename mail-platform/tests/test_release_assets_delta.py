"""New local release-builder and encrypted-signing checks with synthetic resources."""
import json
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PRODUCT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(PRODUCT), str(PRODUCT/'framework')]
import release
import release_assets

OPENSSL = Path('C:/Program Files/Git/usr/bin/openssl.exe')


class AssetCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='mail-signing-synthetic-')
        cls.key_root = Path(cls.temporary.name)
        cls.password = secrets.token_hex(24).encode()
        cls.key, cls.public = cls.key_root/'encrypted.key', cls.key_root/'public.pem'
        for argv in (
            ['genpkey', '-algorithm', 'ED25519', '-aes-256-cbc', '-pass', 'stdin', '-out', str(cls.key)],
            ['pkey', '-in', str(cls.key), '-passin', 'stdin', '-pubout', '-out', str(cls.public)],
        ):
            result = subprocess.run([str(OPENSSL), *argv], input=cls.password+b'\n', capture_output=True, timeout=30)
            if result.returncode:
                raise RuntimeError(json.dumps({'reason': 'synthetic_encrypted_key_fixture_failed',
                    'operation': argv[0], 'exit': result.returncode,
                    'stdout': result.stdout.decode(errors='replace'), 'stderr': result.stderr.decode(errors='replace')}))

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='mail-assets-delta-')
        self.root = Path(self.temporary.name)
        self.output = self.root/'release'
        self.contract = json.loads((PRODUCT/'update-contract.example.json').read_bytes())
        self.contract_path = self.root/'contract.json'
        self.contract_path.write_bytes(release.canonical(self.contract))
        self.source = {'payload/installer.py': b'print("synthetic hook")\n',
                       'payload/usr/local/lib/example.py': b'value = 1\n'}
        self.provenance = {'changed_sources': ['synthetic'], 'source_providers': {'repository': 2}}

    def tearDown(self):
        self.temporary.cleanup()

    def prepare(self):
        with patch.object(release_assets, 'prepare_sources', return_value=(self.source, self.provenance)) as reader:
            record = release_assets.prepare(self.root/'registered-repository', '0.1.1', self.contract_path, self.output)
        reader.assert_called_once_with(self.root/'registered-repository')
        return record

    def test_prepare_uses_registered_sources_and_fixed_assets_with_false_readiness(self):
        record = self.prepare()
        self.assertEqual(record['status'], 'prepared_unsigned')
        self.assertIs(record['install_ready'], False)
        self.assertTrue(record['readiness']['pending'])
        self.assertEqual(record['payload_files'], 3)
        self.assertFalse((self.output/'release.sig').exists())
        self.assertEqual(release_assets.prepared(self.output)[0], record)

    def test_encrypted_candidate_signature_verifies_and_remains_noninstallable(self):
        self.prepare()
        signed = release_assets.sign_prepared(self.output, self.key, self.public, self.password, OPENSSL, candidate=True)
        self.assertEqual(signed['status'], 'signed_candidate')
        self.assertIs(signed['install_ready'], False)
        verified = release_assets.verify(self.output, self.public, OPENSSL)
        self.assertEqual(verified, {'status': 'verified', 'version': '0.1.1', 'install_ready': False, 'files': 4})

    def test_formal_prepare_rejects_pending_validation_before_source_read_or_output(self):
        with patch.object(release_assets, 'prepare_sources') as reader:
            with self.assertRaisesRegex(release.ReleaseError, 'release_validation_pending'):
                release_assets.prepare(self.root, '0.1.1', self.contract_path, self.output, install_ready=True)
        reader.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_formal_sign_rejects_candidate_before_opening_private_key(self):
        self.prepare()
        with self.assertRaisesRegex(release.ReleaseError, 'release_validation_pending'):
            release_assets.sign_prepared(self.output, self.root/'missing.key', self.public, self.password, OPENSSL)
        self.assertFalse((self.output/'release.sig').exists())

    def test_wrong_verification_key_leaves_signature_absent(self):
        self.prepare()
        wrong_key, wrong_public = self.root/'wrong.key', self.root/'wrong.pem'
        release.openssl_run(OPENSSL, ['genpkey', '-algorithm', 'ED25519', '-aes-256-cbc', '-pass', 'stdin', '-out', wrong_key], self.password+b'\n')
        release.openssl_run(OPENSSL, ['pkey', '-in', wrong_key, '-passin', 'stdin', '-pubout', '-out', wrong_public], self.password+b'\n')
        with self.assertRaisesRegex(release.ReleaseError, 'signature_operation_failed'):
            release_assets.sign_prepared(self.output, self.key, wrong_public, self.password, OPENSSL, candidate=True)
        self.assertFalse((self.output/'release.sig').exists())

    def test_archive_drift_rejected_before_private_key_read(self):
        self.prepare()
        archive = self.output/'mail-platform.tar.gz'
        archive.write_bytes(archive.read_bytes()+b'changed')
        with self.assertRaisesRegex(release.ReleaseError, 'prepared_archive_drift'):
            release_assets.sign_prepared(self.output, self.root/'missing.key', self.public, self.password, OPENSSL, candidate=True)

    def test_unencrypted_signing_key_rejected_by_builder(self):
        self.prepare()
        key = self.root/'unencrypted.key'
        key.write_bytes(b'-----BEGIN PRIVATE KEY-----\nsynthetic-invalid-body\n')
        with self.assertRaisesRegex(release.ReleaseError, 'encrypted_signing_key_required'):
            release_assets.sign_prepared(self.output, key, self.public, self.password, OPENSSL, candidate=True)

    def test_wrong_passphrase_keeps_candidate_unsigned(self):
        self.prepare()
        with self.assertRaisesRegex(release.ReleaseError, 'signature_operation_failed') as error:
            release_assets.sign_prepared(self.output, self.key, self.public, b'synthetic-wrong-password', OPENSSL, candidate=True)
        self.assertNotIn(self.password.decode(), str(error.exception))
        self.assertFalse((self.output/'release.sig').exists())

    def test_password_uses_standard_input_and_never_command_argument(self):
        def fake_run(argv, **kwargs):
            self.assertNotIn(self.password.decode(), ' '.join(map(str, argv)))
            self.assertEqual(kwargs['input'], self.password+b'\n')
            self.assertEqual(argv[-2:], ['-passin', 'stdin'])
            Path(argv[argv.index('-out')+1]).write_bytes(b'x'*64)
            return subprocess.CompletedProcess(argv, 0, b'', b'')
        with patch.object(release.subprocess, 'run', side_effect=fake_run):
            signature = release.sign({'synthetic': True}, self.key, OPENSSL, passphrase=self.password)
        self.assertTrue(signature)

    def test_line_break_or_empty_passphrase_rejected_before_process(self):
        for password in (b'', b'a\nb', b'a\rb', b'a\0b'):
            with self.subTest(password_length=len(password)), patch.object(release.subprocess, 'run') as runner:
                with self.assertRaisesRegex(release.ReleaseError, 'signing_passphrase_input'):
                    release.sign({}, self.key, OPENSSL, passphrase=password)
                runner.assert_not_called()

    def test_release_contract_requires_matching_version_lists_and_health(self):
        changes = [{'health': []}, {'to_version': '0.1.2'}, {'stop': []}, {'pause': ['x.timer', 'x.timer']}]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(release.ReleaseError):
                release_assets.update_contract({**self.contract, **change}, '0.1.1')

    def test_existing_output_is_preserved(self):
        self.output.mkdir()
        (self.output/'retained').write_bytes(b'old')
        with self.assertRaisesRegex(release.ReleaseError, 'release_output_exists'):
            release_assets.prepare(self.root, '0.1.1', self.contract_path, self.output)
        self.assertEqual((self.output/'retained').read_bytes(), b'old')

    def test_prepared_inventory_hash_matches_saved_sidecar(self):
        record = self.prepare()
        raw = (self.output/'distribution-inventory.json').read_bytes()
        self.assertEqual(record['distribution_inventory_sha256'], release.sha(raw))
        self.assertEqual(json.loads(raw)['legal_compliance_assessment'], 'not_performed')

    def test_missing_required_readiness_fields_remain_pending(self):
        path = self.root/'partial-readiness.json'
        path.write_bytes(b'{"signed_update_protocol_tested":true}')
        result = release_assets.readiness(path)
        self.assertFalse(result['install_ready'])
        self.assertEqual(set(result['pending']), release_assets.REQUIRED_READINESS)

    def test_legacy_signature_call_preserves_default_unencrypted_interface(self):
        def fake_run(argv, **kwargs):
            self.assertNotIn('-passin', argv)
            self.assertIsNone(kwargs['input'])
            Path(argv[argv.index('-out')+1]).write_bytes(b'x'*64)
            return subprocess.CompletedProcess(argv, 0, b'', b'')
        with patch.object(release.subprocess, 'run', side_effect=fake_run):
            self.assertTrue(release.sign({'synthetic': True}, self.root/'mock-only.key', OPENSSL))


if __name__ == '__main__':
    unittest.main(verbosity=2)
