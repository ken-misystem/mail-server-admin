"""New source-preparation boundary tests; no package/service/mail operations.
Copyright (c) 2026 MI-SYSTEM. MIT license.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('rspamd_source_prepare', HERE / 'prepare.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class PreparationBoundary(unittest.TestCase):
    def test_published_material_hashes(self):
        lock = json.loads((HERE / 'source-lock.json').read_bytes())
        for name, digest in lock['materials'].items():
            self.assertEqual(prepare.sha((HERE/name).read_bytes()), digest)

    def test_wrong_bytes_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / 'source'
            p.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'input_hash_mismatch'):
                prepare.checked(p, prepare.sha(b'expected'))

    def test_directory_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, 'regular_input_required'):
                prepare.checked(Path(temp), prepare.sha(b''))

    def fixture(self, directory):
        here = directory / 'materials'
        here.mkdir()
        cache = directory / 'cache'
        cache.mkdir()
        (cache / 'rspamd_3.12.1-1.dsc').write_bytes(b'fixture')
        (here / 'source-lock.json').write_text(json.dumps({
            'sources': {'rspamd_3.12.1-1.dsc': {'sha256': prepare.sha(b'fixture')}},
            'materials': {}}))
        return here, cache

    def test_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            here, cache = self.fixture(root)
            out = root / 'output'
            out.mkdir()
            (out / 'evidence').write_bytes(b'keep')
            with patch.object(prepare, 'HERE', here), patch.object(prepare.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'new_output_required'):
                    prepare.prepare(cache, out)
                run.assert_not_called()
            self.assertEqual((out / 'evidence').read_bytes(), b'keep')

    def test_invalid_input_before_output_or_command(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            here, cache = self.fixture(root)
            (cache / 'rspamd_3.12.1-1.dsc').write_bytes(b'wrong')
            out = root / 'output'
            with patch.object(prepare, 'HERE', here), patch.object(prepare.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'input_hash_mismatch'):
                    prepare.prepare(cache, out)
                run.assert_not_called()
            self.assertFalse(out.exists())

    def test_command_failure_saved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            here, cache = self.fixture(root)
            out = root / 'output'
            failure = subprocess.CompletedProcess([], 9, b'partial output', b'extract failed')
            with patch.object(prepare, 'HERE', here), patch.object(prepare.subprocess, 'run', return_value=failure):
                with self.assertRaisesRegex(RuntimeError, 'source_preparation_command_failed:0'):
                    prepare.prepare(cache, out)
            result = json.loads((out / 'result.json').read_bytes())
            self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(result['operations'][0]['exit'], 9)
            self.assertEqual((out / '0.stderr').read_bytes(), b'extract failed')
            self.assertEqual((out / '0.stdout').read_bytes(), b'partial output')

    def test_launch_failure_saved(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            here, cache = self.fixture(root)
            out = root / 'output'
            with patch.object(prepare, 'HERE', here), patch.object(prepare.subprocess, 'run', side_effect=FileNotFoundError('missing dpkg-source')):
                with self.assertRaises(FileNotFoundError):
                    prepare.prepare(cache, out)
            result = json.loads((out / 'result.json').read_bytes())
            self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(result['failure']['type'], 'FileNotFoundError')
            self.assertFalse(result['package_installed'])


if __name__ == '__main__':
    unittest.main()
