"""Journaled first-adoption file transaction. No SQL, account or service operations.

Component quiescence and health belong to a separately reviewed host adapter.
This engine never runs the fresh installer and never invents a previous version.
"""
import fcntl
import json
import os
from pathlib import Path
import stat

from adoption_plan import compare_current, validate
from host_transaction import Files, durable_json, regular
from release import canonical, sha
from native_requirements import validate as validate_native
from sieve_lock import MODULE as SIEVE_MODULE

REGISTRATION = '/var/lib/mail-platform-update/'
RECEIPTS = ('installed-code.json','installed.json','native-components.json','policy.json')
CODE_PREFIXES = ('/usr/local/lib/', '/usr/local/sbin/', '/opt/mail-management/',
                 '/opt/roundcube-auth/', '/opt/mail-antivirus-v1/',
                 '/usr/share/roundcube/plugins/', '/etc/mail-legacy-smtp-v1/', '/integration/')

class InitialAdoption:
    def __init__(self, root, evidence):
        self.root=Path(root).resolve(strict=True)
        self.evidence=Path(evidence)
        if self.evidence.is_symlink():raise ValueError('adoption_evidence_link')
        self.files=Files(self.root,self.evidence)
        self.record=None
        self.aliases={}

    def current(self,name):
        from code_aliases import check, assert_physical
        check(self.root,self.aliases);assert_physical([name],self.aliases)
        path=self.files.target(name)
        return regular(path)[1] if os.path.lexists(path) else None

    def locked(self):
        # The caller supplies the already provisioned, root-only transaction parent.
        parent=self.evidence.parent
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o700:
            raise ValueError('adoption_parent_trust')
        lock=parent/'initial-adoption.lock'
        fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:
            os.close(fd);raise ValueError('adoption_lock_trust')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BaseException:os.close(fd);raise
        return os.fdopen(fd,'r+b')

    def save(self):durable_json(self.evidence/'transaction.json',self.record)

    @staticmethod
    def checked(value):
        if not isinstance(value,dict) or value.get('status')!='PASS':
            raise ValueError('adoption_adapter_did_not_pass')
        return value

    def load(self, expected):
        raw,metadata=regular(self.evidence/'transaction.json')
        if metadata['uid']!=0 or metadata['mode']!=0o600:raise ValueError('adoption_journal_trust')
        self.record=json.loads(raw)
        self.aliases=self.record.get('code_aliases',{})
        from code_aliases import check
        if self.record['plan_sha256']!=expected:raise ValueError('adoption_recovery_plan_pin')
        check(self.root,self.aliases)
        self.files.entries=[]
        for path in sorted(self.evidence.glob('file-entry-*.json')):
            raw,metadata=regular(path)
            if metadata['uid']!=0 or metadata['mode']!=0o600:raise ValueError('adoption_entry_trust')
            entry=json.loads(raw)
            expected_row=self.record['changes'].get(entry['path'])
            if not expected_row or any(entry[k]!=expected_row[k] for k in ('before','after')):
                raise ValueError('adoption_entry_contract')
            if entry['sequence']!=len(self.files.entries):raise ValueError('adoption_entry_sequence')
            if any(previous['path']==entry['path'] for previous in self.files.entries):
                raise ValueError('adoption_duplicate_journal_path')
            self.files.entries.append(entry)

    def apply(self,plan,content,expected,adapter):
        if os.geteuid()!=0:raise ValueError('adoption_requires_root')
        if sha(canonical(plan))!=expected:raise ValueError('adoption_plan_pin')
        if validate(plan)['status']!='READY_FOR_REVIEW':raise ValueError('adoption_not_ready')
        changes={row['path']:row for row in plan['changes']}
        if set(content)!=set(changes):raise ValueError('adoption_payload_inventory')
        for name,row in changes.items():
            if sha(content[name])!=row['after']['sha256']:raise ValueError('adoption_payload_pin')
        # Registration must be an explicit, create-only last stage, never old-version fakery.
        for name in RECEIPTS:
            row=changes.get(REGISTRATION+name)
            if not row or row['before'] is not None or row['after']['mode']!=0o600 or row['after']['uid']!=0 or row['after']['gid']!=0:
                raise ValueError('adoption_registration_contract')
        installed=json.loads(content[REGISTRATION+'installed.json'])
        owned=json.loads(content[REGISTRATION+'installed-code.json'])
        from code_aliases import check, assert_physical
        self.aliases=plan.get('code_aliases',{})
        if owned.get('code_aliases',{})!=self.aliases:raise ValueError('adoption_alias_receipt_mismatch')
        check(self.root,self.aliases);assert_physical(owned['code'],self.aliases)
        policy=json.loads(content[REGISTRATION+'policy.json'])
        validate_native(json.loads(content[REGISTRATION+'native-components.json']))
        if installed!={'version':plan['target']['version'],'release':plan['target']['release_sha256']} or owned.get('version')!=installed['version'] or owned.get('format')!=2:
            raise ValueError('adoption_target_registration')
        if policy!={'revision':0,'mode':'manual'}:raise ValueError('adoption_initial_policy')
        required={'format','version','site','identities','code','schemas','unit_files','blueprints'}
        if not required<=set(owned) or not owned['code']:raise ValueError('adoption_ownership_receipt')
        if any(name.startswith(REGISTRATION) for name in owned['code']):raise ValueError('adoption_recursive_receipt')
        if any(not name.startswith(CODE_PREFIXES) and name != SIEVE_MODULE for name in owned['code']):raise ValueError('adoption_code_scope')
        if any(name==p or name.startswith(p+'/') for name in owned['code'] for p in plan['preserve']):
            raise ValueError('adoption_ownership_of_preserved_state')
        # All code ownership must be proved against the actual host before sealing.
        with self.locked():
            if self.evidence.exists():raise ValueError('adoption_existing_transaction_use_recovery')
            observed={name:self.current(name) for name in changes}
            compare_current(plan,observed)
            for name in RECEIPTS:
                if self.current(REGISTRATION+name) is not None:raise ValueError('adoption_already_registered')
            self.evidence.mkdir(mode=0o700)
            self.record={'format':1,'phase':'preflight','plan_sha256':expected,'changes':changes,
                         'target':plan['target'],'registration_started':False}
            if self.aliases:self.record['code_aliases']=self.aliases
            self.save()
            try:
                # The adapter verifies signed release, binds site/native invariants, and controls
                # the maintenance barrier. No packet-defined shell commands are accepted here.
                self.record['preflight']=self.checked(adapter.preflight(plan,content))
                self.record['phase']='barrier_requested';self.save()
                self.record['barrier']=self.checked(adapter.quiesce());self.record['phase']='barrier_acquired';self.save()
                compare_current(plan,{name:self.current(name) for name in changes})
                for name,row in changes.items():
                    if name in {REGISTRATION+x for x in RECEIPTS}:continue
                    if self.current(name)!=row['before']:raise ValueError('adoption_write_CAS')
                    self.files.write(name,content[name],expected_before=row['before'],**{k:row['after'][k] for k in ('mode','uid','gid')})
                self.record['phase']='candidate_written';self.save()
                self.record['health']=self.checked(adapter.health())
                for name,metadata in owned['code'].items():
                    if self.current(name)!=metadata:raise ValueError('adoption_owned_code_readback')
                for name,metadata in owned['unit_files'].items():
                    if '/' in name or self.current('/etc/systemd/system/'+name)!=metadata:raise ValueError('adoption_owned_unit_readback')
                self.record['registration_started']=True;self.record['phase']='registration_started';self.save()
                for filename in RECEIPTS:
                    name=REGISTRATION+filename;row=changes[name]
                    if self.current(name) is not None:raise ValueError('adoption_registration_race')
                    self.files.write(name,content[name],0o600,0,0,expected_before=None)
                self.record['phase']='resume_requested';self.save()
                self.record['resume']=self.checked(adapter.resume())
                self.record['verification']=self.checked(adapter.verify())
                for name,row in changes.items():
                    if self.current(name)!=row['after']:raise ValueError('adoption_final_readback')
                self.record['phase']='complete';self.save()
                return self.record
            except BaseException as error:
                self.record['failure']={'type':type(error).__name__,
                    'reason':str(error) if isinstance(error,ValueError) else 'adoption_step_failed',
                    'errno':getattr(error,'errno',None),'phase':self.record['phase']}
                # A resume request may have published settings or consumed queue. Never undo it blindly.
                if self.record['phase'] in ('resume_requested','complete'):
                    self.record['phase']='held';self.save()
                else:
                    self.save();self.recover_locked(expected,adapter)
                raise

    def recover_locked(self,expected,adapter):
        self.load(expected)
        if self.record['phase'] in ('resume_requested','restore_resume_requested','complete','held'):
            raise ValueError('adoption_recovery_requires_review')
        if self.record['phase']=='restored':return self.record
        if self.record['phase']=='preflight' and not self.files.entries:
            # No maintenance barrier was requested. Do not start or stop any service.
            self.record['phase']='restored';self.record['restore']={'status':'restored','operations':0};self.save()
            return self.record
        unknown=[]
        journaled={entry['path'] for entry in self.files.entries}
        for name,row in self.record['changes'].items():
            try:
                current=self.current(name)
                if current not in (row['before'],row['after']) or (current!=row['before'] and name not in journaled):
                    unknown.append(name)
            except (OSError,ValueError):unknown.append(name)
        if unknown:
            self.record['phase']='held';self.record['unknown_paths']=unknown;self.save()
            return self.record
        self.checked(adapter.recovery_preflight(self.record))
        restored=self.files.restore()
        self.record['restore']=restored
        if restored['status']=='held':
            self.record['phase']='held';self.save();return self.record
        if any(self.current(name)!=row['before'] for name,row in self.record['changes'].items()):
            self.record['phase']='held';self.record['restore_readback']='mismatch';self.save();return self.record
        # Original services are resumed only after all code has been restored.
        self.record['phase']='restore_resume_requested';self.save()
        try:
            self.record['restore_resume']=self.checked(adapter.restore_resume())
            self.record['phase']='restored';self.save()
        except BaseException:
            self.record['phase']='held';self.save();raise
        return self.record

    def recover(self,expected,adapter):
        with self.locked():return self.recover_locked(expected,adapter)
