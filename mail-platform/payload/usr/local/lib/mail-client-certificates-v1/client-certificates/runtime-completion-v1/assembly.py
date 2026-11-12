"""Concrete actor factories; only entrypoint calls them after manifest/FD guards."""
import json
import os
from pathlib import Path
import socket
import stat
import threading
import time
from safety import need,held
from boot import Credentials,public,module
from peer import CgroupPeer
from rpc import Factory,Client,Listener,Endpoint,HeldHandler

class Context:
    def __init__(self,config,release,manifest,runtime,audit):
        self.config,self.release,self.manifest,self.runtime,self.audit=config,release,manifest,runtime,audit
        self.credentials=Credentials(config['actor'],runtime,config['runtime_directory']);self.fds=self.credentials.open();self.public_fds=[];self.listeners=[];self.threads=[]
    def peer(self,actor):
        value=self.config['peers'][actor];return CgroupPeer(value['uid'],value['gid'],value['cgroup'])
    def factory(self,actor,socket_name):
        path=self.config['sockets'][socket_name];uid=self.config['peers'][actor]['uid']
        def guard():
            parent=Path(path).parent
            # Parent is an actor runtime directory, created by root/systemd.
            fd=os.open(str(parent),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                entry=os.fstat(fd);need(entry.st_uid==uid and entry.st_mode&0o022==0,'actor_socket_parent')
                leaf=os.stat(Path(path).name,dir_fd=fd,follow_symlinks=False)
                need(stat.S_ISSOCK(leaf.st_mode)and leaf.st_uid==uid and leaf.st_nlink==1 and stat.S_IMODE(leaf.st_mode)==0o660,'actor_socket_metadata')
            finally:os.close(fd)
        return Factory(path,self.peer(actor),guard,self.runtime)
    def listen(self,name,handler):
        path=self.config['sockets'][name];group=self.config['socket_groups'][name]
        listener=Listener(path,group,handler);thread=threading.Thread(target=listener.loop,daemon=True);thread.start()
        self.listeners.append(listener);self.threads.append(thread);return listener
    def public_fd(self,path,pin):
        from guarded_php import checked_public_fd
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);self.public_fds.append(fd);checked_public_fd(fd,pin);return fd
    def role(self,name,database='mail_management'):
        if database=='roundcube':api=module('completion_session_connector',self.release/'client-certificates/production-preflight-v1/session_connector.py')
        else:import connector as api
        return api.RoleConnector(self.fds[name],self.runtime,api.Endpoint(self.config['sql_socket'],self.config['principals'][name],database))
    def task(self,regions):
        from guarded_task import Task
        paths=self.config['executables'];manifest=self.manifest
        return Task(self.runtime,regions,self.public_fd(paths['python'],manifest['python_pin']),manifest['python_pin'],
            self.public_fd(str(self.release/'guard.so'),manifest['guard_pin']),manifest['guard_pin'],
            self.public_fd(str(self.release/'secret_worker.py'),manifest['pins']['secret_worker.py']),manifest['pins']['secret_worker.py'])
    def close(self):
        for listener in self.listeners:listener.close()
        for thread in self.threads:thread.join(3)
        self.credentials.close()
        for fd in self.public_fds:os.close(fd)

def owner(context):
    from native import LinuxRegions
    from runtime_factory import RPCClient,ThreadBrokerChannel
    from role_startup import RoleFDs
    from owner_assembly import owner_application
    from frozen_runtime import IdentitySnapshot
    from session_store import ReferenceScope,DbSessionRecords
    from broker_link import Client as BrokerClient
    from owner_link import Application,Connection
    from actuation import Publisher
    from readiness import Readiness
    c=context;refs=ReferenceScope();session=c.role('session_reader','roundcube')
    records=DbSessionRecords(c.runtime,session,refs,600,time.time,Readiness(c.config['readiness']),'changed_v1')
    box={};broker=ThreadBrokerChannel(lambda:BrokerClient(c.runtime,c.factory('issuer','broker'),lambda:box['scope'].owner(),time.monotonic))
    cleanup=BrokerClient(c.runtime,c.factory('issuer','broker'),lambda:None,time.monotonic)
    publisher=Publisher(Client(c.factory('gate','gate_control')),Client(c.factory('issuer','crl_owner')),c.audit)
    fdset=RoleFDs('orchestrator',{k:c.fds[k]for k in ('identity_reader','orchestrator','gateway_reader')},c.runtime,os.geteuid())
    built=owner_application(fd_set=fdset,principals={k:c.config['principals'][k]for k in fdset.fds},sql_socket=c.config['sql_socket'],
        session_connector=session,records=records,references=refs,lifecycle_wire=RPCClient(c.factory('lifecycle','lifecycle'),time.monotonic),
        verifier_wire=RPCClient(c.factory('verifier','verifier'),time.monotonic),broker_channel=broker,enforcement=publisher,audit=c.audit,
        wallclock=lambda:int(time.time()),freshclock=time.time)
    box['scope']=built['scope'];application=Application(built['session_application'],IdentitySnapshot(c.role('identity_reader')),built['registry'])
    c.listen('owner',Connection(c.runtime,c.peer('fpm'),application,broker,cleanup,c.audit,time.monotonic).one)
    from mail_owner_lifecycle_v1.runtime import cleanup_tick
    return {'application':application,'publisher':publisher,'broker':broker,'cleanup':cleanup,'scope':box['scope'],
        'owner_lifecycle_tick':cleanup_tick(c,publisher)}

def lifecycle(context):
    from runtime_factory import FixedRPC,lifecycle_application,lifecycle_handler
    from transport_frozen import kernel_peer
    c=context;service=lifecycle_application(c.runtime,c.role('lifecycle_provisioner'));peer=c.peer('owner')
    handler=FixedRPC(c.runtime,lambda ch:kernel_peer(ch,peer.uid,peer.gid),lifecycle_handler(service),time.monotonic,c.audit)
    c.listen('lifecycle',HeldHandler(peer,handler.one,c.audit));return {'service':service}

def verifier(context):
    from runtime_factory import FixedRPC,verifier_handler
    from transport_frozen import kernel_peer
    from native import LinuxRegions
    from guarded_php import GuardedPHP
    from verifier import VerifierService
    c=context;m=c.manifest;exe=c.public_fd(c.config['executables']['php'],m['php_pin']);guard=c.public_fd(str(c.release/'guard.so'),m['guard_pin'])
    source=c.public_fd(str(c.release/'crypto_worker.php'),m['pins']['crypto_worker.php'])
    crypto=GuardedPHP(c.runtime,LinuxRegions(c.runtime),exe,m['php_pin'],guard,m['guard_pin'],source,m['pins']['crypto_worker.php'],tuple(c.config['php_extensions']))
    service=VerifierService(c.runtime,c.role('webauthn_verifier','roundcube'),crypto,time.time);peer=c.peer('owner')
    from mail_owner_lifecycle_v1.backend import verifier_handler as shared_verifier_handler
    handler=FixedRPC(c.runtime,lambda ch:kernel_peer(ch,peer.uid,peer.gid),shared_verifier_handler(service,verifier_handler(service)),time.monotonic,c.audit)
    c.listen('verifier',HeldHandler(peer,handler.one,c.audit));return {'service':service}

def issuer(context):
    from native import LinuxRegions
    from child import GuardedOpenSSL
    from guarded_php import GuardedPHP
    from custody import online_issuer,KeyChecker
    from pc_custody import validate
    from broker_link import Provider,Server
    from broker_wire import BrokerWireServer
    from broker import IssuerBroker
    from authority import BrokerAuthority
    from frozen_runtime import BoundRepository,LiveRegistry
    from inspect_certificate import CertificateInspector
    from issue_clock import CurrentInspector
    from crl import Authority,Sequence
    c=context;m=c.manifest;regions=LinuxRegions(c.runtime)
    custody=json.loads(public(c.config,'custody'));receipt=json.loads(public(c.config,'restoration'));statement=json.loads(public(c.config,'custody_statement'))
    validate(custody,receipt,statement)
    guard=c.public_fd(str(c.release/'guard.so'),m['guard_pin']);php=c.public_fd(c.config['executables']['php'],m['php_pin'])
    source=c.public_fd(str(c.release/'keypair_worker.php'),m['pins']['keypair_worker.php'])
    checker=KeyChecker(c.runtime,GuardedPHP(c.runtime,regions,php,m['php_pin'],guard,m['guard_pin'],source,m['pins']['keypair_worker.php'],()))
    material=online_issuer(c.runtime,regions,{k:c.fds[k]for k in ('issuer_certificate','issuer_key','issuer_password')},custody,public(c.config,'root'),checker,time.time)
    need(public(c.config,'issuer')==os.pread(material.certificate_fd,65536,0),'issuer_public_configuration_binding')
    provider=Provider();connection=c.role('issuer_journal');registry=LiveRegistry(connection)
    runner=GuardedOpenSSL(c.public_fd(c.config['executables']['openssl'],m['openssl_pin']),m['openssl_pin'],guard,m['guard_pin'],c.runtime)
    broker=IssuerBroker(BrokerAuthority(BoundRepository(connection,provider.owner),registry),regions,runner,
        CurrentInspector(CertificateInspector(),lambda:int(time.time())),material,time.monotonic,c.audit)
    peer=c.peer('owner');delegate=BrokerWireServer(c.runtime,peer.uid,peer.gid,broker,registry.device_active,c.audit,time.monotonic,time.time)
    handler=Server(c.runtime,peer.uid,peer.gid,provider,delegate,c.audit,time.monotonic)
    c.listen('broker',HeldHandler(peer,handler.one,c.audit))
    prefix=public(c.config,'root')+public(c.config,'issuer')+public(c.config,'root_crl')
    authority=Authority(c.runtime,connection,material,c.task(regions),Sequence(c.config['state_directory'],material.id),prefix)
    def crl_handler(operation,data):need(operation=='crl'and not data,'issuer_crl_operation');return authority.bundle()
    c.listen('crl',Endpoint(c.runtime,c.peer('gate'),crl_handler,c.audit).one)
    # Owner is also allowed to request this public CRL, on a distinct peer-checked socket.
    from mail_owner_lifecycle_v1.runtime import issuer_retirement
    c.listen('crl_owner',Endpoint(c.runtime,c.peer('owner'),issuer_retirement(connection,broker,crl_handler),c.audit).one)
    return {'broker':broker,'authority':authority}
