"""Offline, signed Rspamd package migration with an independent durable journal.

No APT update/download, config rewrite, cache deletion, or SMTP request occurs.
The previous package and corresponding sources travel with the signed release.
"""
import json
import os
from pathlib import Path
import stat
import time

from host_transaction import Commands, Files, durable_json, regular
from release import canonical, sha
from native_requirements import LIBRARY, RECEIPT

DESCRIPTOR='blueprint/migrations/rspamd-package-v1/manifest.json'
POLICY='/usr/sbin/policy-rc.d'
STATE='/var/lib/mail-platform-update/'+RECEIPT


def require(value, message):
    if not value:raise ValueError(message)


def asset(path):
    path=Path(path);before=path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink==1,'native_asset_type')
    raw=path.read_bytes();after=path.lstat()
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    require(identity(before)==identity(after) and len(raw)==before.st_size,'native_asset_changed')
    return raw


def add_assets(files, root):
    root=Path(root);value=descriptor(root);base=Path(DESCRIPTOR).parent
    expected={DESCRIPTOR,*(str(base/row['archive']).replace('\\','/') for row in (value['baseline'],value['candidate'])),
              *(str(base/name).replace('\\','/') for name in value['sources'])}
    found={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() or p.is_symlink()}
    require(found==expected,'native_asset_inventory')
    for name in sorted(expected):
        require('payload/'+name not in files,'native_duplicate_asset')
        files['payload/'+name]=asset(root/name)
    from distribution_inventory import inventory
    review=inventory(files,json.loads(files['distribution-policy.json']))
    review['signed_native_packages']={key:value[key] for key in ('package','architecture','baseline','candidate','sources')}
    raw=(json.dumps(review,sort_keys=True,indent=2)+'\n').encode()
    files['distribution-inventory.json']=raw
    files['payload/usr/local/lib/mail-platform-update/licenses/distribution-inventory.json']=raw
    return value


def descriptor(payload):
    value=json.loads(asset(Path(payload)/DESCRIPTOR))
    require(set(value)=={'format','package','architecture','baseline','candidate','sources'} and
            value['format']==1 and value['package']=='rspamd' and value['architecture']=='amd64','native_migration_descriptor')
    for key in ('baseline','candidate'):
        row=value[key]
        require(set(row)=={'version','archive','sha256','runtime_files'},'native_migration_package_fields')
        require(type(row['archive']) is str and Path(row['archive']).name==row['archive'] and row['archive'].endswith('.deb'),'native_migration_archive_name')
        raw=asset(Path(payload)/Path(DESCRIPTOR).parent/row['archive'])
        require(sha(raw)==row['sha256'],'native_migration_archive_hash')
        require(type(row['runtime_files']) is dict and LIBRARY in row['runtime_files'] and row['runtime_files'],'native_runtime_inventory')
        require(all(n.startswith(('/usr/bin/rspam','/usr/lib/rspamd/')) and '..' not in n.split('/') for n in row['runtime_files']),'native_runtime_scope')
    require(value['baseline']['version']=='3.12.1-1' and value['candidate']['version']=='3.12.1-1+0misystem1','native_migration_version_pair')
    require(type(value['sources']) is dict and value['sources'],'native_corresponding_sources_missing')
    for name,digest in value['sources'].items():
        require(type(name) is str and name.startswith('source/') and '..' not in name.split('/') and '\\' not in name,'native_source_path')
        require(sha(asset(Path(payload)/Path(DESCRIPTOR).parent/name))==digest,'native_source_digest')
    return value


class NativePackage:
    def __init__(self,payload,directory,root='/',commands=None):
        self.payload=Path(payload);self.directory=Path(directory);self.root=Path(root)
        self.directory.mkdir(parents=True,exist_ok=True,mode=0o700)
        self.path=self.directory/'native-package.json';self.files=Files(self.root,self.directory)
        self.commands=commands or Commands(self.directory)
        self.commands.sequence=len(list(self.directory.glob('[0-9][0-9][0-9][0-9]-*.json')))
        self.offer=descriptor(payload)

    def target(self,name):return self.root/name.lstrip('/')
    def live(self,name):return regular(self.target(name))
    def save(self):durable_json(self.path,self.record)
    def load(self):
        raw,meta=regular(self.path);require(meta['uid']==0 and meta['mode']==0o600,'native_journal_trust')
        self.record=json.loads(raw)
        self.files.entries=[json.loads(p.read_bytes()) for p in sorted(self.directory.glob('file-entry-*.json'))]
    def run(self,label,args,timeout=60):return self.commands.run(label,args,timeout=timeout)
    def version(self):
        raw=self.run('native_version',['/usr/bin/dpkg-query','-W','-f=${db:Status-Status}\t${Version}\t${Architecture}','rspamd']).decode()
        fields=raw.split('\t');require(len(fields)==3 and fields[0]=='installed' and fields[2]=='amd64','native_package_state')
        return fields[1]
    def unit(self):
        raw=self.run('native_unit',['/usr/bin/systemctl','show','rspamd.service','-p','ActiveState,SubState,MainPID,Job']).decode()
        row=dict(line.split('=',1) for line in raw.splitlines());require(row.get('Job') in ('','0'),'native_service_job')
        return row
    def configurations(self):
        base=self.target('/etc/rspamd');result={}
        require(base.is_dir() and not base.is_symlink(),'native_config_root')
        for p in sorted(base.rglob('*')):
            name=p.relative_to(self.root).as_posix()
            if p.is_symlink():result[name]={'link':os.readlink(p)}
            elif p.is_file():result[name]=regular(p)[1]
        return result
    def configurations_after_common_hooks(self):
        """Accept only the current transaction's exact, reversible DKIM dedup."""
        expected=dict(self.record['configs'])
        directory=self.directory.parent/'dkim'
        from dkim_readiness import CONFIG, deduplicate
        for path in sorted(directory.glob('file-entry-*.json')):
            raw,trust=regular(path)
            require(trust['uid']==0 and trust['mode']==0o600,'native_DKIM_journal_trust')
            entry=json.loads(raw)
            require(entry['path']==CONFIG and expected.get(CONFIG.lstrip('/'))==entry['before'],'native_DKIM_baseline')
            if entry['phase']=='restored':continue
            require(entry['phase']=='written','native_DKIM_change_unknown')
            # Backup location is produced by Files; restrict it to this journal.
            name=entry['backup']
            require(type(name)is str and Path(name).name==name and name.startswith('original-'),'native_DKIM_backup_scope')
            backup=directory/name
            require(not backup.is_symlink(),'native_DKIM_backup_scope')
            before=regular(backup)[0];require(sha(before)==entry['before']['sha256'],'native_DKIM_backup_hash')
            normalized,count=deduplicate(before)
            after=dict(entry['before'],sha256=sha(normalized))
            require(count>0 and entry['after']==after,'native_DKIM_only_duplicate_removal')
            expected[CONFIG.lstrip('/')]=after
        return expected
    def runtime(self,kind):
        for path,digest in self.offer[kind]['runtime_files'].items():
            raw,meta=self.live(path)
            require(meta['uid']==0 and meta['gid']==0 and not meta['mode']&0o022 and sha(raw)==digest,'native_runtime_drift:'+path)
    def archive(self,kind):return self.payload/Path(DESCRIPTOR).parent/self.offer[kind]['archive']
    def receipt(self):
        row=self.offer['candidate']
        return {'format':1,'components':{'rspamd':{'version':row['version'],'architecture':'amd64',
            'files':{LIBRARY:row['runtime_files'][LIBRARY]},'fix':'symcache-single-fd-persistence-v1'}}}

    def plan(self):
        require(not self.path.exists(),'native_migration_already_planned')
        version=self.version();kind=next((k for k in ('baseline','candidate') if self.offer[k]['version']==version),None)
        require(kind is not None,'native_unreviewed_version');self.runtime(kind)
        meta=[]
        for k in ('baseline','candidate'):
            raw=self.run('native_deb_metadata',['/usr/bin/dpkg-deb','-f',str(self.archive(k)),'Package','Version','Architecture','Depends'])
            values=dict(line.split(': ',1) for line in raw.decode().splitlines())
            require(values['Package']=='rspamd' and values['Version']==self.offer[k]['version'] and values['Architecture']=='amd64','native_deb_metadata')
            meta.append(values)
        require(meta[0]['Depends']==meta[1]['Depends'],'native_dependency_change')
        require(not self.run('native_dpkg_audit',['/usr/bin/dpkg','--audit']),'native_dpkg_audit')
        unit=self.unit();require(unit['ActiveState'] in ('active','inactive') and (unit['ActiveState']=='active' or unit['MainPID']=='0'),'native_service_not_settled')
        previous=None
        if os.path.lexists(self.target(STATE)):
            raw,attributes=self.live(STATE);require(attributes['uid']==0 and attributes['gid']==0 and attributes['mode']==0o600,'native_receipt_trust')
            require(kind=='candidate' and json.loads(raw)==self.receipt(),'native_receipt_drift');previous=attributes
        policy=None
        if os.path.lexists(self.target(POLICY)):
            raw,policy=self.live(POLICY);require(policy['uid']==0 and not policy['mode']&0o022,'native_policy_trust')
        self.record={'phase':'planned','kind':kind,'before_unit':unit,'configs':self.configurations(),
            'receipt_before':previous,'policy_before':policy,'changed_package':False,'request':None}
        self.save();return {'phase':'planned','package_change':kind=='baseline','dependencies_added':0}

    def stage(self):
        self.load();require(self.record['phase']=='planned','native_stage_order')
        self.runtime(self.record['kind']);require(self.configurations()==self.record['configs'],'native_config_drift')
        self.record['phase']='staged';self.save();return {'phase':'staged'}

    def package(self,kind):
        current=self.live(POLICY)[1] if os.path.lexists(self.target(POLICY)) else None
        require(current==self.record['policy_before'],'native_policy_CAS')
        backup=self.directory/'original-policy'
        if current:
            raw,_=self.live(POLICY)
            if not backup.exists():backup.write_bytes(raw);backup.chmod(0o700)
            require(sha(backup.read_bytes())==current['sha256'],'native_original_policy_drift')
        suffix=('exec '+str(backup)+' "$@"\n') if current else 'exit 0\n'
        # Transaction paths are controlled by updater; never interpolate an arbitrary shell path.
        import re
        require(re.fullmatch(r'/[A-Za-z0-9_./-]+',str(backup)) is not None,'native_policy_backup_path')
        raw=b'#!/bin/sh\ncase "$1" in rspamd|rspamd.service) exit 101;; esac\n'+suffix.encode()
        self.files.write(POLICY,raw,0o755,expected_before=current)
        self.record['request']='dpkg-'+kind;self.save()
        try:self.run('native_install_'+kind,['/usr/bin/dpkg','--force-confold','-i',str(self.archive(kind))],timeout=180)
        finally:
            restored=self.files.restore({POLICY});require(restored['status']=='restored','native_policy_restore_held')
            # Files.restore retains a newly created policy under an inactive name.
        self.record['request']=None;self.record['changed_package']=kind=='candidate';self.save()
        require(self.version()==self.offer[kind]['version'],'native_package_version_after')
        self.runtime(kind);require(self.configurations()==self.record['configs'],'native_configs_changed')

    def process(self,pid):
        proc=Path('/proc')/str(pid);first=(proc/'stat').read_text();status=(proc/'status').read_text()
        children=(proc/'task'/str(pid)/'children').read_text().split();last=(proc/'stat').read_text()
        ticks=lambda s:int(s.rsplit(')',1)[1].split()[19])
        require(ticks(first)==ticks(last),'native_master_changed')
        values=dict(line.split(':',1) for line in status.splitlines() if ':' in line)
        ready=bool(int(values['SigCgt'].strip(),16)&1) and not bool(int(values['SigBlk'].strip(),16)&1) and bool(children)
        library=self.target(LIBRARY).stat();matches=[]
        for line in (proc/'maps').read_text().splitlines():
            row=line.split(None,5)
            if len(row)==6 and row[5] in (LIBRARY,LIBRARY+' (deleted)'):
                require(row[5]==LIBRARY and int(row[4])==library.st_ino and tuple(int(v,16) for v in row[3].split(':'))==(os.major(library.st_dev),os.minor(library.st_dev)),'native_mapping_drift')
                matches.append(row)
        require(any('x' in row[1] for row in matches),'native_library_not_loaded')
        return {'pid':pid,'ticks':ticks(first),'ready':ready}

    def ready(self):
        deadline=time.monotonic()+60;last=None;stable=0
        while stable<2:
            unit=self.unit();require(unit['ActiveState']=='active' and int(unit['MainPID'])>1,'native_not_active')
            observed=self.process(int(unit['MainPID']));identity=(observed['pid'],observed['ticks'])
            self.record.setdefault('readiness',[]).append(observed);self.save()
            stable=(stable+1 if last==identity else 1) if observed['ready'] else 0;last=identity
            require(time.monotonic()<deadline,'native_readiness_timeout')
            if stable<2:time.sleep(.5)
        return identity

    def cache_identity(self):
        p=self.target('/var/lib/rspamd/symbols.cache')
        if not os.path.lexists(p):return None
        s=p.lstat();require(stat.S_ISREG(s.st_mode),'native_cache_type');return (s.st_dev,s.st_ino)
    def save_cache(self):
        before=self.cache_identity();identity=self.ready()
        self.record['request']='cache-reload';self.save()
        self.run('native_cache_reload',['/usr/bin/systemctl','reload','rspamd.service'])
        deadline=time.monotonic()+30
        while True:
            unit=self.unit();require(int(unit['MainPID'])==identity[0],'native_master_replaced')
            state=self.process(identity[0]);require((state['pid'],state['ticks'])==identity,'native_master_identity')
            after=self.cache_identity()
            if after and before!=after:break
            require(time.monotonic()<deadline,'native_cache_not_replaced');time.sleep(.5)
        raw,meta=self.live('/var/lib/rspamd/symbols.cache')
        import pwd
        owner=pwd.getpwnam('_rspamd')
        require(meta['uid']==owner.pw_uid and meta['gid']==owner.pw_gid and not meta['mode']&0o022,'native_cache_owner')
        require(raw[:8]==bytes.fromhex('7273630200000000') and type(json.loads(raw[204:])) is dict,'native_cache_format')
        self.record['request']=None;self.record['cache']={'before':before,'after':after,'sha256':sha(raw)};self.save()

    def activate(self):
        self.load();require(self.record['phase']=='staged','native_activation_order')
        self.runtime(self.record['kind']);require(self.configurations()==self.record['configs'],'native_config_drift')
        require(self.unit()==self.record['before_unit'],'native_unit_changed')
        if self.record['kind']=='baseline':
            self.record['phase']='installing';self.save();self.package('candidate')
            self.record['phase']='installed';self.save()
            self.run('native_configtest',['/usr/bin/rspamadm','configtest'])
            if self.record['before_unit']['ActiveState']=='active':
                self.record['request']='restart';self.save()
                self.run('native_restart',['/usr/bin/systemctl','restart','rspamd.service'],timeout=120)
                self.record['request']=None;self.save();self.save_cache()
        else:
            if self.record['before_unit']['ActiveState']=='active':self.ready()
        require(self.configurations()==self.record['configs'],'native_config_drift')
        if self.record['receipt_before'] is None:
            self.files.write(STATE,canonical(self.receipt()),0o600,expected_before=None)
        self.record['phase']='applied';self.save();return {'phase':'applied','package_changed':self.record['changed_package']}

    def health(self):
        self.load();require(self.record['phase']=='applied','native_health_order')
        require(self.version()==self.offer['candidate']['version'],'native_health_version');self.runtime('candidate')
        require(self.configurations()==self.configurations_after_common_hooks(),'native_health_config')
        require(json.loads(self.live(STATE)[0])==self.receipt(),'native_health_receipt')
        if self.record['before_unit']['ActiveState']=='active':self.ready()
        else:require(self.unit()['ActiveState']=='inactive','native_closed_service_started')
        return {'phase':'healthy','package':self.offer['candidate']['version']}

    def rollback_ready(self):
        if not self.path.exists():return
        self.load();require(self.record['request'] is None,'native_outcome_unknown')
        if self.record['phase']=='rolled_back':return
        require(self.configurations()==self.configurations_after_common_hooks(),'native_rollback_config_drift')
        expected='candidate' if self.record['changed_package'] else self.record['kind']
        require(self.version()==self.offer[expected]['version'],'native_rollback_version');self.runtime(expected)
        for entry in self.files.entries:
            if entry['path']!=STATE or entry['phase']=='restored':continue
            if self.files.mark_unapplied(entry):continue
            require(entry['phase']=='written' and self.live(STATE)[1]==entry['after'],'native_rollback_receipt_drift')

    def rollback(self):
        if not self.path.exists():return {'phase':'rolled_back','operations':0}
        self.rollback_ready()
        if self.record['phase']=='rolled_back':return {'phase':'rolled_back','operations':0}
        if self.record['changed_package']:
            require(self.version()==self.offer['candidate']['version'],'native_rollback_version');self.runtime('candidate')
            self.package('baseline')
            if self.record['before_unit']['ActiveState']=='active':
                self.record['request']='rollback-restart';self.save()
                self.run('native_rollback_restart',['/usr/bin/systemctl','restart','rspamd.service'],timeout=120)
                self.record['request']=None;self.save();self.ready()
        result=self.files.restore({STATE});require(result['status']=='restored','native_receipt_restore_held')
        self.record['phase']='rolled_back';self.save();return {'phase':'rolled_back','cache_preserved':True}


def wrap(base):
    class WithNative:
        def __init__(self,payload,directory,root='/',commands=None):
            self.engine=base(payload,directory,root,commands)
            self.native=NativePackage(payload,Path(directory)/'native-package',root,commands)
        def plan(self):
            native=self.native.plan();return dict(self.engine.plan(),native=native)
        def stage(self):self.native.stage();return self.engine.stage()
        def activate(self):self.native.activate();return self.engine.activate()
        def health(self):
            self.native.health();return self.engine.health()
        def retire(self):return self.engine.retire()
        def rollback(self):
            self.native.rollback_ready()
            result=self.engine.rollback();return dict(result,native=self.native.rollback())
    return WithNative
