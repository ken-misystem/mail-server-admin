"""Adopt exact host listeners/namespace FD and run real gate/policy/control loops."""
import base64
import fcntl
import os
from pathlib import Path
import socket
import stat
import threading
import time
from safety import need
from boot import public
from rpc import Client,Endpoint

def activation(inventory,runtime,host_pin):
    from network_guard import namespace_identity,NamespaceScope
    count=len(inventory.entries)+1
    need(os.environ.get('LISTEN_PID')==str(os.getpid())and os.environ.get('LISTEN_FDS')==str(count),'gate_activation_descriptor_count')
    names=os.environ.get('LISTEN_FDNAMES','').split(':');need(len(names)==count and names.count('host-net')==1,'gate_activation_namespace_name')
    held=[];tcp=[];host=None
    try:
        for fd,name in zip(range(3,3+count),names):
            duplicate=fcntl.fcntl(fd,fcntl.F_DUPFD_CLOEXEC,300);held.append(duplicate)
            if stat.S_ISSOCK(os.fstat(fd).st_mode):need(name!='host-net','gate_namespace_socket_alias');tcp.append(duplicate)
            else:
                need(name=='host-net'and host is None and namespace_identity(duplicate)==tuple(host_pin),'gate_host_namespace_pin');host=duplicate
        need(host is not None and len(tcp)==len(inventory.entries),'gate_activation_inventory')
        for fd in range(3,3+count):os.close(fd)
        for index,fd in enumerate(tcp):os.dup2(fd,3+index,inheritable=False)
        for fd in tcp:os.close(fd);held.remove(fd)
        env={'LISTEN_PID':str(os.getpid()),'LISTEN_FDS':str(len(tcp))}
        listeners=inventory.acquire(runtime,env)
        private=os.open('/proc/thread-self/ns/net',os.O_RDONLY|os.O_CLOEXEC)
        scope=NamespaceScope(host,private,runtime);scope.verify();held.remove(host)
        for key in ('LISTEN_PID','LISTEN_FDS','LISTEN_FDNAMES'):os.environ.pop(key,None)
        return listeners,scope
    except BaseException:
        for fd in held:os.close(fd)
        raise

class Runtime:
    def __init__(self,c):
        from topology import Inventory,Listener
        from entrance import Entrance
        from tls_gate import Identity
        from transport import relay
        from frozen_runtime import LiveRegistry
        from crl import RotatingContexts
        from readiness import Readiness
        from actuation import Gate
        self.c=c;self.stop=threading.Event();self.threads=[];self.workers=[];self.slots=threading.BoundedSemaphore(128)
        entries=tuple(Listener(v['name'],v['protocol'],tuple(v['address']))for v in c.config['listeners']);inventory=Inventory(entries)
        if c.config['profile']=='production':inventory.require_production(frozenset(c.config['public_addresses']))
        self.listeners,self.scope=activation(inventory,c.runtime,c.config['host_namespace'])
        self.contexts=RotatingContexts(c.fds['server_certificate'],c.fds['server_key'],public(c.config,'root'),public(c.config,'issuer'),public(c.config,'root_crl'),c.runtime,time.time)
        self.crl=Client(c.factory('issuer','crl'));self.contexts.install(self.crl.call('crl',{}))
        readiness=Readiness(c.config['readiness'],self.scope);registry=LiveRegistry(c.role('gateway_reader'))
        class Current:
            def __getattr__(_,name):return getattr(registry,name)
            def require_active(_,identity):
                readiness.require_current('external_certificate_routes')
                need(time.time()<self.contexts.expires,'gate_crl_expired');return registry.require_active(identity)
        self.entrance=Entrance(runtime=c.runtime,readiness=readiness,scope=self.scope,inventory=inventory,backends=c.config['backends'],
            policy_endpoint=tuple(c.config['policy_endpoint']),contexts=self.contexts,registry=Current(),relay=relay,clock=time.monotonic,audit=c.audit)
        self.entrance.listeners=self.listeners
        self.actuation=Gate(c.runtime,c.role('gateway_reader'),self.entrance.sessions,self.contexts,readiness)
        c.listen('gate_control',Endpoint(c.runtime,c.peer('owner'),self.actuation.call,c.audit).one)
        self.policy=socket.socket(socket.AF_INET,socket.SOCK_STREAM);self.policy.bind(tuple(c.config['policy_endpoint']));self.policy.listen(32);self.policy.settimeout(.25)
        for name,channel in self.listeners.items():self.start(lambda n=name,s=channel:self.accept(s,lambda conn:self.entrance.accepted(n,conn)))
        self.start(lambda:self.accept(self.policy,self.entrance.policy));self.start(self.refresh)
        from gate_health import Publisher
        self.health=Publisher(c.config['runtime_directory'],c.fds['server_certificate'])
    def start(self,work):
        thread=threading.Thread(target=work,daemon=True);self.threads.append(thread);thread.start()
    def accept(self,listener,handler):
        listener.settimeout(.25)
        while not self.stop.is_set():
            try:channel,_=listener.accept()
            except socket.timeout:continue
            except OSError:
                if self.stop.is_set():break
                raise
            if not self.slots.acquire(False):channel.close();continue
            def run(ch):
                try:handler(ch)
                except Exception as e:self.c.audit.failure(e,'tls_or_policy')
                finally:ch.close();self.slots.release()
            thread=threading.Thread(target=run,args=(channel,),daemon=True);self.workers=[t for t in self.workers if t.is_alive()];self.workers.append(thread);thread.start()
    def refresh(self):
        # Refresh long before the 24-hour CRL expires; failures retain only a still
        # valid CRL. New and existing connections fail closed at its expiry.
        while not self.stop.wait(21600):
            try:self.contexts.install(self.crl.call('crl',{}))
            except Exception as e:self.c.audit.failure(e,'periodic_crl_refresh')
    def require_healthy(self):
        self.c.runtime.require_armed()
        need(all(t.is_alive()for t in self.threads),'gate_runtime_thread_failed')
        need(time.time()<self.contexts.expires,'gate_crl_expired')
    def publish_health(self):
        with self.contexts.lock:self.health.publish(self.contexts.number,self.contexts.expires,all(t.is_alive()for t in self.threads))
    def close(self):
        self.stop.set()
        with self.entrance.sessions.lock:
            for _,close in list(self.entrance.sessions.sessions.values()):close()
        for channel in (*self.listeners.values(),self.policy):channel.close()
        for thread in self.threads+self.workers:thread.join(6)
        os.close(self.scope.host_fd);os.close(self.scope.private_fd)
