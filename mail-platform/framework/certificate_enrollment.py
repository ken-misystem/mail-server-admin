"""Prepare a gate-only certificate runtime view and conditionally adopt its unit."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath

from host_transaction import Files, durable_json, regular
from availability_plan import path as absolute_path
from generation_front import control, read_route

RELEASE='/usr/local/lib/mail-client-certificates-v1'
CONFIG='/etc/mail-client-certificates-v1/gate.json'
GATE_UNIT='/etc/systemd/system/mail-client-cert-gate.service'
MODULES=('client-certificates/adapters-v1/transport.py',
         'client-certificates/runtime-completion-v1/gate_runtime.py',
         'client-certificates/runtime-completion-v1/backend_fronts.py')
NATIVE_UNITS=frozenset(('mail-client-cert-postfix-backend.service','mail-client-cert-dovecot-backend.service'))

def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()

def trusted(path, limit=2097152):
    for parent in Path(path).parents:
        info=parent.lstat()
        if parent.is_symlink() or info.st_uid!=0 or info.st_mode&0o022:
            raise ValueError('enrollment_parent_trust')
    raw,attributes=regular(path,limit)
    if attributes['uid']!=0 or attributes['mode']&0o022:
        raise ValueError('enrollment_source_trust')
    return raw,attributes

def member(name):
    if not isinstance(name,str) or name.startswith('/') or '..' in name.split('/') or str(PurePosixPath(name))!=name or '\\' in name:
        raise ValueError('enrollment_member')
    return name

def publish_new(path,raw,mode=0o644,gid=0):
    path=Path(path)
    for directory in reversed(path.parent.parents):
        if directory.is_symlink():
            raise ValueError('enrollment_stage_link')
    for directory in reversed([path.parent,*path.parent.parents]):
        if not directory.exists():
            directory.mkdir(mode=0o755)
            os.chmod(directory,0o755)
        if directory.is_symlink() or directory.stat().st_uid!=0 or directory.stat().st_mode&0o022:
            raise ValueError('enrollment_stage_parent')
    descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(descriptor,'wb') as stream:
        stream.write(raw);os.fchmod(stream.fileno(),mode);os.fchown(stream.fileno(),0,gid)
        stream.flush();os.fsync(stream.fileno())
    descriptor=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(descriptor)
    finally:os.close(descriptor)

def stage(release,config,payload,destination,expected):
    """Copy only pinned public files, keeping the original live view untouched."""
    release=Path(release);payload=Path(payload);destination=Path(destination)
    if destination.exists():raise ValueError('enrollment_stage_exists')
    for parent in destination.parents:
        if parent.is_symlink() or (parent.exists() and (parent.stat().st_uid!=0 or parent.stat().st_mode&0o022)):
            raise ValueError('enrollment_destination_trust')
    raw,attributes=trusted(release/'runtime-manifest.json')
    config_raw,config_attributes=trusted(config)
    if attributes!=expected['manifest'] or config_attributes!=expected['config']:
        raise ValueError('enrollment_baseline_CAS')
    manifest=json.loads(raw);configuration=json.loads(config_raw)
    if configuration['actor']!='gate' or configuration['release']!=str(release) or configuration['manifest_sha256']!=attributes['sha256']:
        raise ValueError('enrollment_configuration_binding')
    if configuration.get('backend_fronts') is not None:
        raise ValueError('enrollment_already_adopted')
    updates={name:trusted(payload/name)[0] for name in MODULES}
    source_files={}
    for name,digest in manifest['pins'].items():
        member(name)
        data,metadata=trusted(release/name,16777216)
        if metadata['sha256']!=digest:raise ValueError('enrollment_pin_drift:'+name)
        source_files[name]=(data,metadata)
    # The native guard is checked outside the public source pin list by existing consumers.
    if 'guard.so' not in source_files:
        data,metadata=trusted(release/'guard.so')
        if metadata['sha256']!=manifest['guard_pin']:raise ValueError('enrollment_guard_pin')
        source_files['guard.so']=(data,metadata)
    for name in MODULES:
        if name in source_files:
            if expected['modules'].get(name)!=source_files[name][1]:
                raise ValueError('enrollment_module_CAS:'+name)
        elif name in expected['modules']:
            raise ValueError('enrollment_missing_baseline')
        compile(updates[name],name,'exec')
    destination.mkdir(mode=0o755,parents=True)
    os.chmod(destination,0o755)
    certificate=destination/'certificate'
    certificate.mkdir(mode=0o755)
    for name,(data,metadata) in source_files.items():
        publish_new(certificate/name,updates.get(name,data),metadata['mode'],metadata['gid'])
    for name,data in updates.items():
        if name not in source_files:publish_new(certificate/name,data)
        manifest['pins'][name]=hashlib.sha256(data).hexdigest()
    manifest_raw=encoded(manifest)
    if len(manifest['pins'])>180:raise ValueError('enrollment_runtime_pin_limit')
    publish_new(certificate/'runtime-manifest.json',manifest_raw)
    configuration['manifest_sha256']=hashlib.sha256(manifest_raw).hexdigest()
    configuration['backend_fronts']={name:{'path':'/run/mail-platform-'+name+'/listen.sock','uid':0}
                                    for name in ('submission','imaps','pop3s')}
    configuration_path=destination/'gate.json'
    publish_new(configuration_path,encoded(configuration),config_attributes['mode'],config_attributes['gid'])
    if trusted(release/'runtime-manifest.json')[1]!=expected['manifest'] or trusted(config)[1]!=expected['config']:
        raise ValueError('enrollment_source_changed_during_stage')
    receipt={'format':1,'phase':'staged','certificate':str(certificate),'configuration':str(configuration_path),
             'original_release':str(release),'original_configuration':str(config),
             'original_manifest':expected['manifest'],'original_config':expected['config'],
             'new_manifest_sha256':configuration['manifest_sha256'],
             'staged_config':trusted(configuration_path)[1],
             'inventory':{name:trusted(certificate/name,16777216)[1] for name in source_files.keys()|updates.keys()}}
    durable_json(destination/'enrollment.json',receipt)
    return receipt

def verify_stage(directory):
    directory=Path(directory)
    record=json.loads(trusted(directory/'enrollment.json')[0])
    if record['certificate']!=str(directory/'certificate') or record['configuration']!=str(directory/'gate.json'):
        raise ValueError('enrollment_stage_binding')
    for name,expected in record['inventory'].items():
        if trusted(directory/'certificate'/member(name),16777216)[1]!=expected:
            raise ValueError('enrollment_stage_drift:'+name)
    raw,_=trusted(directory/'certificate/runtime-manifest.json')
    if hashlib.sha256(raw).hexdigest()!=record['new_manifest_sha256']:
        raise ValueError('enrollment_staged_manifest')
    if trusted(directory/'gate.json')[1]!=record['staged_config']:
        raise ValueError('enrollment_staged_configuration')
    return record

def gate_unit(raw,release,configuration,stage_directory):
    """Remove native dependencies in the complete unit, preserving other directives."""
    if b'\\\n' in raw:
        raise ValueError('enrollment_unit_continuation_review')
    for value in (release,configuration,stage_directory):absolute_path(str(value))
    result=[];removed=set();section=''
    for line in raw.decode().splitlines():
        if line.startswith('['):section=line
        key,separator,value=line.partition('=')
        if section=='[Unit]' and separator and key.strip()=='Requires':
            names=value.split();removed.update(set(names)&NATIVE_UNITS)
            line=key+'='+' '.join(name for name in names if name not in NATIVE_UNITS)
        result.append(line)
    if removed!=NATIVE_UNITS:raise ValueError('enrollment_native_dependencies')
    result+=['','[Unit]','Wants='+' '.join('mail-platform-'+name+'-front.service' for name in ('submission','imaps','pop3s')),
             'After='+' '.join('mail-platform-'+name+'-front.service' for name in ('submission','imaps','pop3s')),
             '[Service]',
             'BindReadOnlyPaths='+str(Path(stage_directory)/'certificate')+':'+str(release),
             'BindReadOnlyPaths='+str(Path(stage_directory)/'gate.json')+':'+str(configuration)]
    return ('\n'.join(result)+'\n').encode()

def retirement_status(fronts,generation):
    """Shared native instances retire only after every route and old session moved."""
    active={};routes={}
    for name,item in fronts.items():
        routes[name]=read_route(item['route'])['generation']
        active[name]=control(item['control'],'status')['active'].get(generation,0)
    return {'ready':all(value!=generation for value in routes.values()) and not any(active.values()),
            'active':active,'routes':routes}

class Adoption:
    """An existing Files journal guards unit adoption and recovery across process restarts."""
    def __init__(self,root,directory):
        self.directory=Path(directory)
        for parent in [self.directory,*self.directory.parents]:
            if parent.is_symlink() or (parent.exists() and (parent.stat().st_uid!=0 or parent.stat().st_mode&0o022)):
                raise ValueError('enrollment_transaction_trust')
        self.directory.mkdir(mode=0o700,parents=True,exist_ok=True)
        self.files=Files(root,self.directory)
        self.path=self.directory/'adoption.json'
        self.record=json.loads(trusted(self.path)[0]) if self.path.exists() else {'phase':'new','operation':None}
        self.files.entries=[json.loads(trusted(path)[0]) for path in sorted(self.directory.glob('file-entry-*.json'))]
    def save(self):durable_json(self.path,self.record)
    def adopt(self,target,raw,expected):
        if target!=GATE_UNIT or self.record['phase']!='new':raise ValueError('enrollment_adoption_scope')
        if trusted(self.files.target(target))[1]!=expected:raise ValueError('enrollment_unit_CAS')
        self.record.update(phase='adopting',target=target,baseline=expected);self.save()
        self.files.write(target,raw,expected['mode'],0,expected['gid'])
        self.record['phase']='adopted';self.save()
    def operation_started(self,name):
        if name not in ('daemon_reload','gate_restart'):raise ValueError('enrollment_operation')
        self.record['operation']=name;self.save()
    def operation_finished(self):
        self.record['operation']=None;self.save()
    def recover(self):
        if self.record['phase']=='restored':
            return {'status':'already_restored','data_and_credentials_preserved':True}
        if self.record['operation']:
            self.record['phase']='held';self.save()
            return {'status':'held','reason':'unit_operation_unknown'}
        result=self.files.restore()
        self.record['phase']=result['status'];self.save()
        return result
