"""Exercise only Roundcube adoption, link updates and rollback in Linux fixtures."""
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest import TestCase, main
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'framework'))
import code_update
import dkim_readiness
import generation_update
from host_transaction import durable_json, regular
import monitor_binding
import roundcube_update as rc
from adaptive_update import HybridGenerationUpdate
from release import canonical, sha

ENTRIES = {rc.SOURCE+'/'+name+'/'+name+'.php': b'<?php // signed '+name.encode()+b'\n' for name in rc.AUTH}
SOURCE_VERSION = '0.4.7'
NEXT_VERSION = '0.4.8'
RECEIPT = '/var/lib/mail-platform-update/installed-code.json'
FPM = 'php8.4-fpm.service'
ASSET = rc.SOURCE + '/local_auth_gate/next-passkey.js'
LOCALES = list(rc.LOCALES)


class Commands:
    sequence = 0

    def __init__(self):
        self.active = True
        self.events = []

    def run(self, label, argv, **kwargs):
        self.events.append(label)
        if argv[0] == '/usr/bin/systemctl':
            action = argv[1]
            if action == 'show':
                return ('ActiveState=active\nSubState=running\nMainPID=11\nJob=0\n' if self.active else
                        'ActiveState=inactive\nSubState=dead\nMainPID=0\nJob=0\n').encode()
            if action in ('stop','start'):
                self.active = action == 'start'
        return b''


class RoundcubeUpdate(TestCase):
    def setUp(self):
        workspace = self.enterContext(tempfile.TemporaryDirectory(prefix='mail-roundcube-update-'))
        self.host = Path(workspace)/'host'
        self.transaction = Path(workspace)/'transaction'
        self.payload = Path(workspace)/'release/payload'
        self.transaction.mkdir()
        (self.payload/'blueprint').mkdir(parents=True)
        self.bound = {path.lstrip('/'):raw for path,raw in ENTRIES.items()}
        self.commands = Commands()
        self.write('/var/lib/dpkg/status', b'')
        self.path('/var/lib/dpkg/info').mkdir()
        self.path(rc.WEB).mkdir(parents=True)
        for path, raw in ENTRIES.items():
            self.write(path, raw)
        self.receipt = {'format':2,'version':SOURCE_VERSION,'site':{},'identities':{},
                        'code':{p:regular(self.path(p))[1] for p in ENTRIES},'unit_files':{}}
        self.save_receipt()
        durable_json(self.payload.parent/'bundle.json', {'version':NEXT_VERSION})
        self.contract = {'format':1,'from_version':[SOURCE_VERSION],'to_version':NEXT_VERSION,
                         'pause':[],'stop':[FPM],'start':[FPM],'reload':[],'health':[FPM]}
        durable_json(self.payload/'blueprint/update-contract.json', self.contract)
        self.enterContext(patch.object(code_update.CodeUpdate,'render',lambda *args:dict(self.bound)))
        self.enterContext(patch.object(monitor_binding,'update',return_value={}))
        self.enterContext(patch.object(dkim_readiness,'update_apply',return_value=None))
        self.enterContext(patch.object(dkim_readiness,'update_rollback',return_value=None))

    def path(self, path):
        return self.host/path.lstrip('/')

    def write(self, path, raw, mode=0o644):
        target = self.path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        target.chmod(mode)

    def save_receipt(self):
        self.path(RECEIPT).parent.mkdir(parents=True, exist_ok=True)
        durable_json(self.path(RECEIPT), self.receipt)

    def run_phase(self, phase, engine=code_update.CodeUpdate):
        return getattr(engine(self.payload,self.transaction,root=self.host,commands=self.commands),phase)()

    def run_update(self, engine=code_update.CodeUpdate):
        for phase in ('plan','stage','activate','health'):
            self.run_phase(phase,engine)

    def install_legacy(self):
        for name in rc.AUTH:
            logical = rc.LEGACY+'/'+name
            self.write(logical+'/'+name+'.php', ENTRIES[rc.SOURCE+'/'+name+'/'+name+'.php'])
            self.path(rc.WEB+'/'+name).symlink_to(logical)

    def install_old_projection(self):
        root = self.path(rc.INITIAL_PROJECTION)
        for name in rc.AUTH:
            relative = name+'/'+name+'.php'
            file = root/relative
            file.parent.mkdir(parents=True, exist_ok=True)
            file.symlink_to(rc.SOURCE+'/'+relative)
            self.path(rc.WEB+'/'+name).symlink_to(rc.INITIAL_PROJECTION+'/'+name)

    def add_candidate(self):
        self.bound[ASSET.lstrip('/')] = b'// newly packaged static file\n'

    def check_new_projection(self):
        targets = [os.readlink(self.path(rc.WEB+'/'+name)).rsplit('/',1)[0] for name in rc.AUTH]
        self.assertEqual(targets[0],targets[1])
        self.assertTrue(targets[0].startswith(rc.PROJECTION_PREFIX))
        projected = self.path(targets[0])/'local_auth_gate/next-passkey.js'
        self.assertEqual(os.readlink(projected),ASSET)
        self.assertNotIn('unregistered.js', [path.name for path in projected.parent.iterdir()])
        self.assertEqual(self.path(ASSET).read_bytes(),self.bound[ASSET.lstrip('/')])

    def test_legacy_translation_replacement_and_exact_adoption_restore(self):
        old = b'<?php // earlier locale\n'
        new = b'<?php // signed locale\n'
        for index, path in enumerate(LOCALES):
            self.write(path, old if index==0 else new)
            self.bound[path.lstrip('/')] = new
        with patch.dict(rc.LOCALES,{LOCALES[0]:sha(old)}):
            self.run_update()
        receipt = json.loads(self.path(RECEIPT).read_bytes())
        self.assertTrue(all(path in receipt['code'] for path in LOCALES))
        self.assertTrue(all(self.path(path).read_bytes()==new for path in LOCALES))
        self.run_phase('rollback')
        self.assertEqual(self.path(LOCALES[0]).read_bytes(),old)
        self.assertEqual(json.loads(self.path(RECEIPT).read_bytes()),self.receipt)

    def test_unknown_locale_is_untouched(self):
        candidate = LOCALES[0]
        self.bound[candidate.lstrip('/')] = b'<?php // signed'
        self.write(candidate,b'<?php // locally changed')
        with self.assertRaisesRegex(ValueError,'new_code_collision'):
            self.run_phase('plan')
        self.assertFalse(self.commands.events)

    def test_dpkg_owned_locale_is_not_adopted(self):
        candidate = LOCALES[0]
        self.bound[candidate.lstrip('/')] = b'<?php // signed'
        self.write(candidate,self.bound[candidate.lstrip('/')])
        self.write('/var/lib/dpkg/status',b'Package: fixture\nStatus: install ok installed\nArchitecture: all\nVersion: 1\nDescription: fixture\n')
        self.write('/var/lib/dpkg/info/fixture.list',(candidate+'\n').encode())
        with self.assertRaisesRegex(ValueError,'new_code_collision'):
            self.run_phase('plan')

    def test_legacy_links_activate_registered_files_and_roll_back(self):
        self.install_legacy()
        self.add_candidate()
        self.write(rc.SOURCE+'/local_auth_gate/unregistered.js',b'legacy unregistered')
        self.run_update()
        self.check_new_projection()
        self.assertLess(self.commands.events.index('stop_php8_4_fpm_service'),
                        self.commands.events.index('start_php8_4_fpm_service'))
        self.run_phase('rollback')
        self.run_phase('rollback')
        for name in rc.AUTH:
            self.assertEqual(os.readlink(self.path(rc.WEB+'/'+name)),rc.LEGACY+'/'+name)
        self.assertFalse(self.path(ASSET).exists())

    def test_current_047_projection_picks_up_new_file(self):
        self.install_old_projection()
        self.add_candidate()
        self.run_update()
        self.check_new_projection()
        self.assertTrue(self.path(rc.INITIAL_PROJECTION).is_dir())
        self.assertFalse(rc.AuthLinks(self.host,self.transaction/'next.json').plan(
            self.bound,json.loads(self.path(RECEIPT).read_bytes()))['change'])

    def test_canonical_links_stay_direct(self):
        for name in rc.AUTH:
            self.path(rc.WEB+'/'+name).symlink_to(rc.SOURCE+'/'+name)
        self.add_candidate()
        self.run_update()
        self.assertTrue(self.path(ASSET).is_file())
        self.assertFalse((self.transaction/'roundcube-auth-links.json').exists())

    def test_unplanned_link_change_stops_health_even_on_canonical_site(self):
        for name in rc.AUTH:
            self.path(rc.WEB+'/'+name).symlink_to(rc.SOURCE+'/'+name)
        self.add_candidate()
        for phase in ('plan','stage','activate'):
            self.run_phase(phase)
        link = self.path(rc.WEB+'/local_auth')
        link.unlink()
        link.symlink_to('/other/local_auth')
        with self.assertRaisesRegex(ValueError,'roundcube_update_link_health'):
            self.run_phase('health')
        self.assertEqual(json.loads(self.path(RECEIPT).read_bytes()),self.receipt)

    def test_unknown_link_is_untouched(self):
        self.install_legacy()
        self.path(rc.WEB+'/local_auth').unlink()
        self.path(rc.WEB+'/local_auth').symlink_to('/somewhere/local_auth')
        with self.assertRaisesRegex(ValueError,'roundcube_update_unknown_link'):
            self.run_phase('plan')
        self.assertFalse(self.commands.events)

    def test_rollback_holds_if_link_was_edited(self):
        self.install_old_projection()
        self.add_candidate()
        self.run_update()
        link = self.path(rc.WEB+'/local_auth')
        link.unlink()
        link.symlink_to('/other/local_auth')
        count = len(self.commands.events)
        with self.assertRaisesRegex(ValueError,'roundcube_update_link_rollback_held'):
            self.run_phase('rollback')
        self.assertEqual(len(self.commands.events),count)
        self.assertTrue(self.path(ASSET).is_file())

    def test_partial_binding_failure_restores_already_published_link(self):
        self.install_old_projection()
        self.add_candidate()
        self.run_phase('plan')
        self.run_phase('stage')
        replace = rc.AuthLinks.replace

        def interrupt(self, path, *args):
            if path.name == 'local_auth_gate':
                raise RuntimeError('test_interruption')
            return replace(self,path,*args)

        with patch.object(rc.AuthLinks,'replace',interrupt), self.assertRaisesRegex(RuntimeError,'test_interruption'):
            self.run_phase('activate')
        self.run_phase('rollback')
        for name in rc.AUTH:
            self.assertEqual(os.readlink(self.path(rc.WEB+'/'+name)),rc.INITIAL_PROJECTION+'/'+name)
        self.assertTrue(self.commands.active)

    def test_hybrid_static_delta_updates_projection_and_rolls_back(self):
        self.install_old_projection()
        self.add_candidate()
        config = {'format':1,'generation_root':'/unused','components':{'other':{
            'kind':'reader','roots':['/opt/unrelated'],'route':'/etc/mail-platform/other.json',
            'control':'/run/mail-test/other.sock','runtime':'/run/mail-test',
            'unit':'mail-platform-other@.service','template':None,'drain_seconds':3,
            'health':{'kind':'http','request':'GET /','reply':'ready'}}}}
        self.write('/etc/mail-platform/availability.json',canonical(config),0o600)
        self.write('/etc/systemd/system/mail-platform-other@.service',b'fixture unit')
        self.run_update(HybridGenerationUpdate)
        self.check_new_projection()
        self.run_phase('rollback',HybridGenerationUpdate)
        self.assertEqual(os.readlink(self.path(rc.WEB+'/local_auth_gate')),rc.INITIAL_PROJECTION+'/local_auth_gate')
        self.assertFalse(self.path(ASSET).exists())

    def test_generation_admits_only_registered_auth_addition(self):
        engine = generation_update.GenerationUpdate(self.payload,self.transaction,root=self.host,commands=self.commands)
        registered = {'components':{'web':{'roots':[rc.SOURCE+'/local_auth_gate','/opt/other']}}}
        self.assertTrue(engine.new_path_allowed(ASSET,registered))
        self.assertFalse(engine.new_path_allowed('/opt/other/unrelated.py',registered))
        self.assertFalse(engine.new_path_allowed(rc.SOURCE+'/local_auth/new.js',registered))


if __name__ == '__main__':
    main()
