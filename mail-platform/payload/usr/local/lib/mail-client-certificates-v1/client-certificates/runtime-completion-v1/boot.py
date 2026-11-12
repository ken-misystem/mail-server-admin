"""Immutable release and configured actor startup; no discovery or host fallback."""
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import sys
from safety import need,held,unique

ROLES={'owner':('identity_reader','orchestrator','gateway_reader','session_reader'),
    'lifecycle':('lifecycle_provisioner',),'verifier':('webauthn_verifier',),
    'issuer':('issuer_journal','issuer_certificate','issuer_key','issuer_password'),
    'gate':('gateway_reader','server_certificate','server_key')}
def load(actor,config_path):
    need(actor in ROLES and all(getattr(sys.flags,k)==1 for k in('isolated','ignore_environment','no_user_site','no_site','dont_write_bytecode','safe_path')),'startup_isolated_flags')
    raw=held(config_path);config=json.loads(raw,object_pairs_hook=unique)
    need(config.get('version')==1 and config.get('actor')==actor and config.get('profile')in {'production','private-validation'},'startup_config_profile')
    release=Path(__file__).resolve().parents[2];need(str(release)==config['release'],'startup_release_binding')
    if config['profile']=='production':need(str(release)=='/usr/local/lib/mail-client-certificates-v1'and config_path=='/etc/mail-client-certificates-v1/'+actor+'.json','startup_production_paths')
    else:need(str(release).startswith('/run/mail-cert-complete-public-')and config_path.startswith(str(release)+'/configs/'),'startup_private_validation_paths')
    manifest=held(str(release/'runtime-manifest.json'),1048576);need(sha256(manifest).hexdigest()==config['manifest_sha256'],'startup_manifest_pin')
    values=json.loads(manifest);need(set(values)=={'pins','wheel','guard_pin','python_pin','openssl_pin','php_pin'},'startup_manifest_fields')
    need(len(values['pins'])<=180,'startup_release_file_count')
    for name,pin in values['pins'].items():
        need(type(name)is str and not name.startswith('/')and all(v not in ('','.','..')for v in name.split('/'))and '\\'not in name,'startup_release_file_name')
        data=held(str(release/name),2097152);need(sha256(data).hexdigest()==pin,'startup_public_source_drift')
    need(values['pins'][values['wheel']]=='14f1c68e2ed859243ae5ca41ffbe677027fc46bc136a9f0be8a4e928e5e7415a','startup_driver_pin')
    sys.path[:0]=[str(release/'client-certificates'/name)for name in ('owner-lifecycle-v1','runtime-completion-v1','final-integration-v1','production-runtime-v1',
        'integration-v1','activation-stack-v1','wiring-v1','session-broker-v1','live-transport-v1','enforcement-integration-v1',
        'adapters-v1','identity-security-v1','runtime-boundaries-v1','candidate-v1')]+[str(release/values['wheel']),'/usr/lib/python3/dist-packages']
    need('pymysql'not in sys.modules,'startup_driver_preloaded');import pymysql
    need(str(pymysql.__file__).startswith(str(release/values['wheel'])+'/pymysql/'),'startup_driver_origin')
    import cryptography
    need(str(cryptography.__file__).startswith('/usr/lib/python3/dist-packages/cryptography/'),'startup_crypto_origin')
    from native import LinuxRuntime
    own=config['peers'][actor];need(os.geteuid()==own['uid']and os.getegid()==own['gid'],'startup_actor_identity')
    current=Path('/proc/self/cgroup').read_text();need(current=='0::'+own['cgroup']+'\n','startup_actor_cgroup')
    runtime=LinuxRuntime(own['uid']);runtime.harden_self();return config,release,values,runtime

class Credentials:
    def __init__(self,actor,runtime,directory):self.actor,self.runtime,self.directory,self.fds,self.stage=actor,runtime,directory,{},None
    def open(self):
        self.runtime.require_armed();directory=os.environ.get('CREDENTIALS_DIRECTORY')
        need(type(directory)is str and directory.startswith('/run/credentials/')and '..'not in directory.split('/'),'startup_credentials_directory')
        parent=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            from credential_stage import Stage
            self.stage=Stage(self.directory,self.runtime)
            info=os.fstat(parent);need(info.st_uid in(0,os.geteuid())and info.st_mode&0o022==0,'startup_credentials_parent')
            for name in ROLES[self.actor]:
                fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent)
                try:self.fds[name]=self.stage.add(fd)
                finally:os.close(fd)
            identities={(os.fstat(fd).st_dev,os.fstat(fd).st_ino)for fd in self.fds.values()};need(len(identities)==len(self.fds),'startup_credential_alias')
            return dict(self.fds)
        except BaseException:self.close();raise
        finally:os.close(parent)
    def close(self):
        if self.stage is not None:self.stage.close();self.stage=None
        self.fds.clear()

def notify(message):
    path=os.environ.get('NOTIFY_SOCKET');need(type(path)is str and path[:1]in('/','@')and len(path)<=108,'startup_notify_socket')
    with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)as channel:channel.connect('\0'+path[1:]if path.startswith('@')else path);channel.sendall(message.encode())

def public(config,name):
    item=config['ca'][name];raw=held(item['path'],131072);need(sha256(raw).hexdigest()==item['sha256'],'startup_public_ca_pin');return raw

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);result=importlib.util.module_from_spec(spec);sys.modules[name]=result;spec.loader.exec_module(result);return result
