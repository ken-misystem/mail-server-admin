"""New update lifecycle regressions with modeled services and disposable file state."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

PRODUCT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(PRODUCT/'framework'), str(PRODUCT)]
import code_update
import source_patches
import updater
from host_transaction import UNSPECIFIED_BEFORE


def persist(path, value):
    path = Path(path)
    temporary = path.with_suffix('.new')
    temporary.write_bytes(json.dumps(value).encode())
    temporary.replace(path)


def metadata(raw, mode=0o644):
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'uid': 0, 'gid': 0, 'mode': mode}


class ModeledFiles:
    def __init__(self, root, directory):
        self.root, self.directory = Path(root), Path(directory)
        self.entries = []

    def target(self, name):
        return self.root/name.lstrip('/')

    def write(self, name, raw, mode=0o644, uid=0, gid=0, *, expected_before=UNSPECIFIED_BEFORE):
        path = self.target(name)
        original = path.read_bytes() if path.exists() else None
        if expected_before is not UNSPECIFIED_BEFORE and expected_before != (
                metadata(original, 0o600 if path.name == 'installed-code.json' else 0o644)
                if original is not None else None):
            raise ValueError('resource_expected_CAS_conflict')
        entry = {'path': name, 'phase': 'written', 'after': metadata(raw, mode),
                 'before_bytes': original.hex() if original is not None else None}
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        self.entries.append(entry)
        persist(self.directory/('file-entry-'+str(len(self.entries)).zfill(6)+'.json'), entry)

    def restore(self):
        for entry in reversed(self.entries):
            path = self.target(entry['path'])
            if entry['before_bytes'] is None:
                path.rename(path.with_suffix('.retained'))
            else:
                path.write_bytes(bytes.fromhex(entry['before_bytes']))
        return {'status': 'restored'}


class ModeledCommands:
    def __init__(self):
        self.states = {name: {'ActiveState': 'active', 'SubState': 'running', 'MainPID': '123', 'Job': '0'}
                       for name in ['example.service', 'example.timer']}
        self.operations = []
        self.sequence = 0
        self.fail_health = False

    def run(self, label, argv, **kwargs):
        self.operations.append(argv)
        if argv[1] == 'show':
            return ''.join(key+'='+value+'\n' for key, value in self.states[argv[2]].items()).encode()
        if argv[1] == 'is-active' and self.fail_health:
            raise RuntimeError('injected_health_failure')
        if argv[1] in ('start', 'stop'):
            name = argv[-1]
            active = argv[1] == 'start'
            self.states[name] = {'ActiveState': 'active' if active else 'inactive',
                                 'SubState': 'running' if active else 'dead',
                                 'MainPID': '456' if active else '0', 'Job': '0'}
        return b''


class UpdateCases(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.root = self.directory/'host'
        self.payload = self.directory/'release/payload'
        self.transaction = self.directory/'transaction'
        self.transaction.mkdir()
        self.payload.mkdir(parents=True)
        self.commands = ModeledCommands()
        self.old_code, self.new_code = b'value = 1\n', b'value = 2\n'
        self.code = '/usr/local/lib/example.py'
        self.receipt_name = '/var/lib/mail-platform-update/installed-code.json'
        self.bound = {'usr/local/lib/example.py': self.new_code,
                      'blueprint/systemd/example.service': b'new service',
                      'blueprint/systemd/example.timer': b'old timer'}
        for name, raw in [(self.code, self.old_code), ('/etc/systemd/system/example.service', b'old service'),
                          ('/etc/systemd/system/example.timer', b'old timer')]:
            path = self.root/name.lstrip('/')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.receipt = {'format': 2, 'version': '0.1.0', 'identities': {'mailadmin.gid': 113},
                        'site': {}, 'schemas': {}, 'blueprints': {}, 'code': {self.code: metadata(self.old_code)},
                        'unit_files': {'example.service': metadata(b'old service'), 'example.timer': metadata(b'old timer')}}
        path = self.root/self.receipt_name.lstrip('/')
        path.parent.mkdir(parents=True)
        persist(path, self.receipt)
        self.contract = {'format': 1, 'from_version': '0.1.0', 'to_version': '0.1.1',
                         'pause': ['example.timer'], 'stop': ['example.service'], 'start': ['example.service'],
                         'reload': [], 'health': ['example.service']}
        (self.payload/'blueprint').mkdir()
        persist(self.payload/'blueprint/update-contract.json', self.contract)
        persist(self.payload.parent/'bundle.json', {'version': '0.1.1'})
        self.patches = [patch.object(code_update, 'Files', ModeledFiles),
                        patch.object(code_update, 'regular', self.regular),
                        patch.object(code_update, 'durable_json', persist),
                        patch.object(code_update.os, 'geteuid', return_value=0, create=True),
                        patch.object(code_update, 'render', lambda *args: dict(self.bound))]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def regular(self, path):
        path = Path(path)
        raw = path.read_bytes()
        mode = 0o600 if path.name in ('installed-code.json', 'code-update.json') else 0o644
        return raw, metadata(raw, mode)

    def run_phase(self, phase):
        runner = code_update.CodeUpdate(self.payload, self.transaction, root=self.root, commands=self.commands)
        return getattr(runner, phase)()

    def through_activation(self):
        for phase in ('plan', 'stage', 'activate'):
            self.run_phase(phase)

    def test_separate_process_phases_update_code_units_and_receipt(self):
        self.through_activation()
        self.assertEqual(self.run_phase('health')['version'], '0.1.1')
        self.assertEqual((self.root/self.code.lstrip('/')).read_bytes(), self.new_code)
        self.assertEqual(json.loads((self.root/self.receipt_name.lstrip('/')).read_bytes())['version'], '0.1.1')

    def test_health_failure_restores_code_units_and_old_receipt(self):
        self.through_activation()
        self.commands.fail_health = True
        with self.assertRaisesRegex(RuntimeError, 'injected_health_failure'):
            self.run_phase('health')
        self.run_phase('rollback')
        self.assertEqual((self.root/self.code.lstrip('/')).read_bytes(), self.old_code)
        self.assertEqual(json.loads((self.root/self.receipt_name.lstrip('/')).read_bytes())['version'], '0.1.0')

    def test_receipt_is_restored_after_health_if_parent_commit_fails(self):
        self.through_activation()
        self.run_phase('health')
        self.run_phase('rollback')
        self.assertEqual(json.loads((self.root/self.receipt_name.lstrip('/')).read_bytes()), self.receipt)

    def test_unknown_edit_holds_entire_rollback_before_service_stop(self):
        self.through_activation()
        (self.root/self.code.lstrip('/')).write_bytes(b'other administrator')
        count = len(self.commands.operations)
        with self.assertRaisesRegex(ValueError, 'rollback_held_unknown_file_state'):
            self.run_phase('rollback')
        self.assertEqual(len(self.commands.operations), count)

    def test_installed_file_drift_stops_plan(self):
        (self.root/self.code.lstrip('/')).write_bytes(b'other administrator')
        with self.assertRaisesRegex(ValueError, 'installed_code_drift'):
            self.run_phase('plan')

    def test_changed_unit_requires_declared_operation(self):
        self.contract['stop'] = self.contract['start'] = []
        persist(self.payload/'blueprint/update-contract.json', self.contract)
        with self.assertRaisesRegex(ValueError, 'changed_unit_missing_lifecycle'):
            self.run_phase('plan')

    def test_undeclared_unit_rejected(self):
        self.contract['health'] = ['ssh.service']
        persist(self.payload/'blueprint/update-contract.json', self.contract)
        with self.assertRaisesRegex(ValueError, 'update_unit_scope'):
            self.run_phase('plan')

    def test_release_and_contract_version_must_match(self):
        persist(self.payload.parent/'bundle.json', {'version': '0.1.2'})
        with self.assertRaisesRegex(ValueError, 'release_contract_version_mismatch'):
            self.run_phase('plan')

    def test_new_unit_requires_explicit_migration_hook(self):
        self.bound['blueprint/systemd/new.service'] = b'new service'
        with self.assertRaisesRegex(ValueError, 'release_unit_addition_requires_migration_hook'):
            self.run_phase('plan')
        self.assertFalse(self.commands.operations)

    def test_excluded_migration_timer_stays_uninstalled(self):
        self.bound['blueprint/systemd/mail-residual-pop-v1.timer'] = b'old migration timer'
        self.run_phase('plan')
        record = json.loads((self.transaction/'code-update.json').read_bytes())
        self.assertNotIn('/etc/systemd/system/mail-residual-pop-v1.timer', record['candidates'])


    def test_unfinished_service_operation_holds_recovery(self):
        self.run_phase('plan')
        record = json.loads((self.transaction/'code-update.json').read_bytes())
        record['operation_started'] = {'action': 'stop', 'unit': 'example.service'}
        persist(self.transaction/'code-update.json', record)
        with self.assertRaisesRegex(ValueError, 'unfinished_service_operation'):
            self.run_phase('rollback')

    def test_initially_inactive_timer_stays_inactive(self):
        self.commands.states['example.timer'] = {'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0', 'Job': '0'}
        self.through_activation()
        self.assertFalse(any(argv[1] == 'start' and argv[-1] == 'example.timer' for argv in self.commands.operations))


class SealCases(unittest.TestCase):
    def test_install_receipt_captures_version_code_unit_and_immutable_blueprints(self):
        import host_install
        rows = {}
        bound = {'usr/local/lib/example.py': b'code', 'blueprint/schema.sql': b'schema',
                 'blueprint/config.json': b'config', 'blueprint/systemd/example.service': b'unit',
                 'blueprint/update-contract.json': b'contract'}
        fake = types.SimpleNamespace(
            files=types.SimpleNamespace(entries=[
                {'path': '/usr/local/lib/example.py', 'after': metadata(b'code')},
                {'path': '/etc/systemd/system/example.service', 'after': metadata(b'unit')},
                {'path': '/etc/systemd/system/example.service.d/override.conf', 'after': metadata(b'override')}]),
            bound=bound, product_version='0.2.0', site={'synthetic': True}, ids={'mailadmin.gid': 40000})
        with patch.object(host_install, 'durable_json', side_effect=lambda path, value: rows.update({Path(path).as_posix(): value})):
            host_install.Installer.seal_installation(fake)
        receipt = next(value for name, value in rows.items() if name.endswith('/installed-code.json'))
        self.assertEqual(receipt['format'], 2)
        self.assertEqual(receipt['version'], '0.2.0')
        self.assertEqual(set(receipt['code']), {'/usr/local/lib/example.py'})
        self.assertEqual(set(receipt['unit_files']), {'example.service'})
        self.assertEqual(set(receipt['blueprints']), {'blueprint/schema.sql', 'blueprint/config.json'})
        self.assertEqual(set(receipt['schemas']), {'blueprint/schema.sql'})
        self.assertEqual(next(value for name, value in rows.items() if name.endswith('/installed.json'))['version'], '0.2.0')



class SourcePatchCases(unittest.TestCase):
    def test_recorded_changes_preserve_other_repository_edits(self):
        patches = {'code.py': {'hunks': [{'before': 'before\n', 'after': 'after\n'}]}}
        self.assertEqual(source_patches.apply('code.py', b'new upstream\nbefore\n', patches), b'new upstream\nafter\n')

    def test_already_integrated_change_is_idempotent(self):
        patches = {'code.py': {'hunks': [{'before': 'before\n', 'after': 'after\n'}]}}
        self.assertEqual(source_patches.apply('code.py', b'after\n', patches), b'after\n')

    def test_conflicting_or_duplicate_hunk_stops_build(self):
        patches = {'code.py': {'hunks': [{'before': 'before\n', 'after': 'after\n'}]}}
        for raw in (b'unknown\n', b'before\nbefore\n', b'before\nafter\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                source_patches.apply('code.py', raw, patches)


class HookCases(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root/'payload').mkdir()
        (self.root/'payload/installer.py').write_bytes(b'pass\n')
        self.transaction = self.root/'transaction'
        self.transaction.mkdir()
        self.persist = patch.object(updater, 'save', persist)
        self.persist.start()

    def tearDown(self):
        self.persist.stop()
        self.temporary.cleanup()

    def test_hook_nonzero_keeps_actual_exit_and_original_outputs(self):
        result = subprocess.CompletedProcess([], 7, b'synthetic stdout', b'synthetic stderr')
        with patch.object(updater.subprocess, 'run', return_value=result), self.assertRaises(updater.HookFailure) as caught:
            updater.hook(self.root, 'stage', self.transaction)
        self.assertEqual(caught.exception.record['exit'], 7)
        self.assertEqual(next(self.transaction.glob('*.stderr')).read_bytes(), b'synthetic stderr')
        self.assertFalse(caught.exception.uncertain)

    def test_hook_timeout_keeps_partial_outputs_and_requires_review(self):
        failure = subprocess.TimeoutExpired(['synthetic hook'], 600, output=b'partial stdout', stderr=b'partial stderr')
        with patch.object(updater.subprocess, 'run', side_effect=failure), self.assertRaises(updater.HookFailure) as caught:
            updater.hook(self.root, 'activate', self.transaction)
        self.assertTrue(caught.exception.uncertain)
        self.assertIsNone(caught.exception.record['exit'])
        self.assertEqual(next(self.transaction.glob('*.stdout')).read_bytes(), b'partial stdout')

    def test_hook_spawn_failure_keeps_errno_and_no_fabricated_exit(self):
        with patch.object(updater.subprocess, 'run', side_effect=FileNotFoundError(2, 'fixture')), self.assertRaises(updater.HookFailure) as caught:
            updater.hook(self.root, 'plan', self.transaction)
        self.assertEqual(caught.exception.record['spawn_error']['errno'], 2)
        self.assertIsNone(caught.exception.record['exit'])


class ProtocolCases(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.old = {'version': '0.1.0', 'release': None}
        persist(self.root/'installed.json', self.old)
        persist(self.root/'policy.json', {'revision': 0, 'mode': 'automatic'})
        fcntl = types.SimpleNamespace(flock=lambda *args: None, LOCK_EX=1, LOCK_NB=2)
        def extract(files, destination):
            destination.mkdir()
        self.patches = [patch.object(updater, 'save', persist), patch.dict(sys.modules, {'fcntl': fcntl}),
                        patch.object(updater, 'inspect', return_value=({'version': '0.1.1', 'install_ready': True}, {'payload/installer.py': (b'pass', 0o644)})),
                        patch.object(updater, 'extract_verified', side_effect=extract)]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temporary.cleanup()

    def update(self, hook):
        return updater.run_update(self.root, 'synthetic archive', {'version': '0.1.1'}, 'signature', 'key', hook_fn=hook)

    def test_parent_commit_failure_restores_installed_version(self):
        failed = False
        def save(path, value):
            nonlocal failed
            if Path(path) == self.root/'transaction.json' and value.get('phase') == 'complete' and not failed:
                failed = True
                raise OSError('injected_commit_failure')
            persist(path, value)
        with patch.object(updater, 'save', side_effect=save), self.assertRaisesRegex(updater.ReleaseError, 'update_rolled_back'):
            self.update(lambda stage, action, transaction: {'action': action})
        self.assertEqual(json.loads((self.root/'installed.json').read_bytes()), self.old)
        self.assertEqual(json.loads((self.root/'transaction.json').read_bytes())['phase'], 'rolled_back')

    def test_parent_timeout_holds_without_running_rollback(self):
        actions = []
        def hook(stage, action, transaction):
            actions.append(action)
            if action == 'activate':
                raise updater.HookFailure({'action': action, 'timed_out': True})
            return {'action': action}
        with self.assertRaisesRegex(updater.ReleaseError, 'update_held'):
            self.update(hook)
        self.assertNotIn('rollback', actions)
        self.assertEqual(json.loads((self.root/'installed.json').read_bytes()), self.old)

    def test_parent_unknown_installed_version_is_preserved(self):
        other = {'version': '0.5.0', 'release': 'other administrator'}
        def hook(stage, action, transaction):
            if action == 'health':
                persist(self.root/'installed.json', other)
                raise ValueError('injected_health_failure')
            return {'action': action}
        with self.assertRaisesRegex(updater.ReleaseError, 'update_held'):
            self.update(hook)
        self.assertEqual(json.loads((self.root/'installed.json').read_bytes()), other)


if __name__ == '__main__':
    unittest.main(verbosity=2)
