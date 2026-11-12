"""Fixed root no-swap TLS bundle/renewal and public-only certificate health."""
from datetime import datetime,timezone
from hashlib import sha256
import ctypes
import fcntl
import json
import os
from pathlib import Path
import re
import resource
import ssl
import stat
import subprocess
import sys
import time
import traceback
import uuid
sys.dont_write_bytecode=True
sys.path.append('/usr/lib/python3/dist-packages')
STATE=Path('/var/lib/mail-client-cert-public-v1')
CONFIG=Path('/etc/mail-client-certificates-v1/health.json')
MARKER=Path('/etc/mail-client-certificates-v1/activation-approved.json')
GATE=Path('/run/mail-client-certificates-v1/gate/health.json')
SERVICES=tuple('mail-client-cert-'+v+'.service'for v in ('network','milter','coordination','postfix-backend','dovecot-backend','issuer','lifecycle','verifier','gate','owner'))+('mail-client-cert-gate.socket',)
CODES=('private_unit_not_active','gate_observation_missing','gate_observation_stale','gate_threads_failed','crl_expiring','crl_expired','tls_expiring','tls_expired',
    'root_ca_expiring','root_ca_expired','issuer_ca_expiring','issuer_ca_expired','tls_reload_unverified','tls_source_invalid','tls_refresh_failed','health_collection_failed','health_snapshot_stale')

class Stop(RuntimeError):
    def __init__(self,code):self.code=code;super().__init__(code)
def need(value,code):
    if value is not True:raise Stop(code)
def read(path,maximum=131072,owner=0):
    path=Path(path);need(path.is_absolute()and '..'not in path.parts,'health_absolute_path')
    descriptors=[];parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);descriptors.append(parent)
    try:
        for part in path.parts[1:-1]:
            parent=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);descriptors.append(parent)
            s=os.fstat(parent);need(s.st_uid in(0,owner)and s.st_mode&0o022==0,'health_parent_permissions')
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent);descriptors.append(fd)
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_uid==owner and a.st_nlink==1 and a.st_mode&0o022==0 and 0<a.st_size<=maximum,'health_file_metadata')
        raw=os.pread(fd,a.st_size+1,0);b=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
        need(len(raw)==a.st_size and(a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns),'health_file_drift');return raw
    finally:
        for fd in reversed(descriptors):os.close(fd)
def write_new(path,raw,mode=0o600):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
    try:os.fchmod(fd,mode);need(os.write(fd,raw)==len(raw),'health_short_write');os.fsync(fd)
    finally:os.close(fd)
def atomic(path,value):
    path=Path(path);raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode();temp=path.with_name('.'+path.name+'-'+uuid.uuid4().hex)
    write_new(temp,raw);os.replace(temp,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)
def native(argv):
    d=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=40,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'})
    if d.returncode or d.stderr or len(d.stdout)>65536:
        e=Stop('health_native_command_failed');e.native_exit=d.returncode;e.stderr_bytes=len(d.stderr);raise e
    return d.stdout
def harden(selfcheck=False):
    need(os.geteuid()==0,'health_root_identity');resource.setrlimit(resource.RLIMIT_CORE,(0,0));libc=ctypes.CDLL(None,use_errno=True)
    need(libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0 and libc.prctl(39,0,0,0,0)==1,'health_dump_and_nnp')
    status=Path('/proc/self/status').read_bytes();cap=next(v.split(b':',1)[1].strip()for v in status.splitlines()if v.startswith(b'CapEff:'))
    need(int(cap,16)==0,'health_capabilities_empty')
    name='mail-client-cert-health-validation-v1.service'if selfcheck else'mail-client-cert-health.service';cgroup='/system.slice/'+name
    need(Path('/proc/self/cgroup').read_text()=='0::'+cgroup+'\n'and Path('/sys/fs/cgroup'+cgroup+'/memory.swap.max').read_text().strip()=='0','health_exact_no_swap_unit')
    return {'dumpable':0,'core_limit':0,'cap_eff':0,'no_new_privileges':1,'swap_disabled':True}
def certificate(raw,now):
    from cryptography import x509
    cert=x509.load_pem_x509_certificate(raw)
    need(cert.not_valid_before_utc.timestamp()<=now<cert.not_valid_after_utc.timestamp(),'tls_source_certificate_validity')
    names=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    need('mx.mi-sys.jp'in names,'tls_source_mail_hostname');return cert.not_valid_after_utc.timestamp()
def sealed(raw):
    fd=os.memfd_create('mail-server-tls-input',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    need(os.write(fd,raw)==len(raw),'tls_memfd_write');fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL);return fd
def checked_pair(cert,key):
    need(b'ENCRYPTED'not in key and len(key)<=65536,'server_tls_key_must_not_prompt')
    left=right=None
    try:
        left=sealed(cert);right=sealed(key);context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain('/proc/self/fd/'+str(left),'/proc/self/fd/'+str(right),password=lambda:None)
    finally:
        for fd in (left,right):
            if fd is not None:os.close(fd)
def publish_bundle(directory,cert,key,expires):
    directory=Path(directory);directory.mkdir(mode=0o700,exist_ok=True)
    name='generation-'+uuid.uuid4().hex;version=directory/name;version.mkdir(mode=0o700)
    write_new(version/'certificate.pem',cert);write_new(version/'key.pem',key)
    meta={'version':1,'certificate_sha256':sha256(cert).hexdigest(),'expires':expires};write_new(version/'public.json',(json.dumps(meta,sort_keys=True)+'\n').encode())
    temp=directory/('.current-'+uuid.uuid4().hex);os.symlink(name,temp);os.replace(temp,directory/'current')
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)
    return meta
def source_file(path):
    p=Path(path);real=p.resolve(strict=True)
    need(str(p).startswith('/etc/letsencrypt/live/')and str(real).startswith('/etc/letsencrypt/archive/'),'fixed_acme_source_roots')
    raw=read(real);need(p.resolve(strict=True)==real,'acme_source_resolution_drift');return raw,real
def evaluate(rows,observation,expiry,now,bundle_pin):
    findings=[]
    def add(code):
        if code not in findings:findings.append(code)
    if len(rows)!=len(SERVICES)or any(v.get('ActiveState')!='active'for v in rows.values()):add('private_unit_not_active')
    if observation is None:add('gate_observation_missing')
    else:
        need(set(observation)=={'version','observed_at','crl_number','crl_expires','tls_certificate_sha256','tls_expires','threads_healthy'}and observation['version']==1,'gate_health_schema')
        need(type(observation['crl_number'])is int and observation['crl_number']>=0,'gate_health_crl_number')
        if not(0<=now-observation['observed_at']<=20):add('gate_observation_stale')
        if observation['threads_healthy']is not True:add('gate_threads_failed')
        if observation['tls_certificate_sha256']!=bundle_pin:add('tls_reload_unverified')
        expiry['crl']=observation['crl_expires'];expiry['server_tls']=min(expiry['server_tls'],observation['tls_expires'])
    for name,days,prefix in (('server_tls',21,'tls'),('issuer_ca',30,'issuer_ca'),('root_ca',180,'root_ca'),('crl',1/3,'crl')):
        if name not in expiry:continue
        if expiry[name]<=now:add(prefix+'_expired')
        elif expiry[name]-now<=days*86400:add(prefix+'_expiring')
    return findings
def safe_error(error):
    rows=traceback.extract_tb(error.__traceback__)[-6:];value={'class':type(error).__name__,'code':getattr(error,'code',None),'errno':getattr(error,'errno',None),
        'frames':[{'source':Path(v.filename).name,'function':v.name,'line':v.lineno}for v in rows],'raw_error_saved':False}
    for name in ('reason','verify_code','native_exit','stderr_bytes'):
        v=getattr(error,name,None)
        if type(v)is int or(type(v)is str and re.fullmatch('[A-Z0-9_]{1,100}',v)):value[name]=v
    return value
"""Bounded observation wait only; never starts/restarts a unit or retrieves mail."""


def initial_observation(read_one,now,monotonic,sleep,pin):
    deadline=monotonic()+15
    while True:
        try:value=read_one()
        except FileNotFoundError:value=None
        if value is not None and value.get('tls_certificate_sha256')==pin and 0<=now()-value.get('observed_at',0)<=20:return value
        if monotonic()>=deadline:return value
        sleep(min(.25,max(0,deadline-monotonic())))


def check():
    protection=harden();config=json.loads(read(CONFIG,16384));need(set(config)=={'version','certificate_source','key_source','gate_uid','root_certificate','issuer_certificate'},'health_config_fields')
    now=time.time();report={'version':1,'observed_at':int(now),'status':'failed','finding_codes':[],'seconds_remaining':{'server_tls':0,'root_ca':0,'issuer_ca':0,'crl':0},'renewal_action':'none','protection':protection}
    try:
        current_raw,current_path=source_file(config['certificate_source']);expiry={'server_tls':certificate(current_raw,now)};pin=sha256(current_raw).hexdigest()
        try:
            target=os.readlink(STATE/'tls/current');need(re.fullmatch('generation-[0-9a-f]{32}',target)is not None,'tls_bundle_current_target')
            bundle=json.loads(read(STATE/'tls'/target/'public.json',8192))
        except FileNotFoundError:bundle=None
        changed=bundle is None or bundle['certificate_sha256']!=pin
        if changed:
            key,key_path=source_file(config['key_source']);checked_pair(current_raw,key)
            need(Path(config['certificate_source']).resolve(strict=True)==current_path and Path(config['key_source']).resolve(strict=True)==key_path,'tls_pair_sources_changed')
            bundle=publish_bundle(STATE/'tls',current_raw,key,expiry['server_tls']);key=None;report['renewal_action']='prepared'
        if not MARKER.exists():report['status']='ok';report['phase']='tls_prepared_before_public_activation';atomic(STATE/'status.json',report);print(json.dumps(report));return 0
        if changed:
            token=STATE/('restart-'+pin+'.intent.json');need(not token.exists(),'tls_restart_once_per_generation')
            write_new(token,(json.dumps({'certificate_sha256':pin,'status':'started','automatic_retry':False})+'\n').encode())
            native(['/usr/bin/systemctl','try-restart','mail-client-cert-gate.service']);report['renewal_action']='gate_restarted'
            deadline=time.monotonic()+25
            while time.monotonic()<deadline:
                try:
                    observed=json.loads(read(GATE,8192,config['gate_uid']))
                    if observed.get('tls_certificate_sha256')==pin and 0<=time.time()-observed.get('observed_at',0)<=20:break
                except FileNotFoundError:pass
                time.sleep(1)
        raw=native(['/usr/bin/systemctl','show',*SERVICES,'--property=Id,ActiveState,SubState,Result'])
        rows={}
        for section in raw.decode().strip().split('\n\n'):
            r=dict(line.split('=',1)for line in section.splitlines()if '='in line);need(r['Id']in SERVICES and r['Id']not in rows,'health_unit_inventory');rows[r['Id']]=r
        from cryptography import x509
        for name,keyname in (('root_ca','root_certificate'),('issuer_ca','issuer_certificate')):expiry[name]=x509.load_pem_x509_certificate(read(config[keyname])).not_valid_after_utc.timestamp()
        observation=initial_observation(lambda:json.loads(read(GATE,8192,config['gate_uid'])),time.time,time.monotonic,time.sleep,bundle['certificate_sha256'])
        report['finding_codes']=evaluate(rows,observation,expiry,time.time(),bundle['certificate_sha256'])
        report['seconds_remaining']={name:int(expiry.get(name,0)-time.time())for name in report['seconds_remaining']}
        report['status']='ok'if not report['finding_codes']else'failed'if any(v.endswith('_expired')or v in {'private_unit_not_active','gate_observation_missing','gate_observation_stale','gate_threads_failed','tls_reload_unverified'}for v in report['finding_codes'])else'warning'
    except BaseException as error:
        report['failure']=safe_error(error)
        code=getattr(error,'code','')
        report['finding_codes']=['tls_source_invalid'if isinstance(error,ssl.SSLError)or code.startswith(('tls_source','server_tls','acme_'))else'tls_refresh_failed'if report['renewal_action']!='none'else'health_collection_failed'];report['status']='failed'
    atomic(STATE/'status.json',report);print(json.dumps(report,sort_keys=True));return 0 if report['status']=='ok'else 2 if report['status']=='warning'else 1
def selfcheck():
    protection=harden(True);directory=Path('/run/mail-client-cert-health-validation-v1')
    value={'selfcheck':True,'secret_material':False};atomic(directory/'value.json',value);need(json.loads(read(directory/'value.json',8192))==value,'health_atomic_selfcheck')
    raw=b'public-dummy';version=directory/'generation-fixture';version.mkdir(mode=0o700);write_new(version/'public.json',raw)
    os.symlink('generation-fixture',directory/'current');need(read(directory/os.readlink(directory/'current')/'public.json',8192)==raw,'health_symlink_public_selfcheck')
    print(json.dumps({'status':'ok','protection':protection,'root_capabilities_required':False,'real_key_read':False,'private_only':True}));return 0
if __name__=='__main__':
    try:
        need(sys.argv[1:]in (['--check'],['--self-check']),'fixed_health_command');raise SystemExit(selfcheck()if sys.argv[1]=='--self-check'else check())
    except Exception as error:print(json.dumps({'status':'fail','failure':safe_error(error)}));raise SystemExit(1)
