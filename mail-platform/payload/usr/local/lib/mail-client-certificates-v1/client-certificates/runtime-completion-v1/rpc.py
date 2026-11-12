"""Actor-owned Unix listeners: peer PIDFD+cgroup before greeting/request bytes."""
import json
import os
import socket
import stat
import struct
import threading
import time
from safety import need,unique
from peer import CgroupPeer,GreetedFactory
from transport_frozen import receive

LIMIT=524288
def read(channel,deadline,clock=time.monotonic):
    value=json.loads(receive(channel,clock,deadline,maximum=LIMIT),object_pairs_hook=unique)
    need(type(value)is dict,'actor_rpc_object');return value
def send(channel,value,deadline,clock=time.monotonic):
    raw=json.dumps(value,separators=(',',':'),allow_nan=False).encode();need(0<len(raw)<=LIMIT,'actor_rpc_size')
    need(clock()<deadline,'actor_rpc_deadline');channel.settimeout(deadline-clock());channel.sendall(struct.pack('!I',len(raw))+raw)

class PinnedChannel:
    def __init__(self,channel,context,alive):self.channel,self.context,self.alive,self.closed=channel,context,alive,False
    def __getattr__(self,name):return getattr(self.channel,name)
    def sendall(self,*args):self.alive();return self.channel.sendall(*args)
    def send(self,*args):self.alive();return self.channel.send(*args)
    def recvmsg(self,*args):self.alive();return self.channel.recvmsg(*args)
    def recv(self,*args):self.alive();return self.channel.recv(*args)
    def close(self):
        if self.closed:return
        self.closed=True
        try:
            try:self.context.__exit__(None,None,None)
            except ValueError as e:
                if e.args!=('fpm_peer_exited',):raise
        finally:self.channel.close()

class HeldHandler:
    def __init__(self,peer,delegate,audit):self.peer,self.delegate,self.audit=peer,delegate,audit
    def __call__(self,channel):
        context=self.peer.hold(channel)
        try:alive=context.__enter__()
        except Exception as e:self.audit.failure(e,'actor_peer');channel.close();return False
        return self.delegate(PinnedChannel(channel,context,alive))

class Factory(GreetedFactory):
    def __init__(self,path,peer,parent_guard,runtime):
        need(type(peer)is CgroupPeer,'actor_peer_contract');super().__init__(path,peer.uid,peer.gid,parent_guard,runtime);self.peer=peer
    def open(self):
        channel=super().open();context=self.peer.hold(channel)
        try:alive=context.__enter__();return PinnedChannel(channel,context,alive)
        except BaseException:channel.close();raise

class Client:
    def __init__(self,factory):self.factory=factory
    def call(self,operation,data):
        channel=self.factory.open()
        try:
            send(channel,{'operation':operation,'input':data},time.monotonic()+5)
            result=read(channel,time.monotonic()+220)
            need(set(result)=={'ok','result'}and result['ok']is True,'actor_rpc_remote_failure')
            return result['result']
        finally:channel.close()

class Endpoint:
    def __init__(self,runtime,peer,handler,audit):self.runtime,self.peer,self.handler,self.audit=runtime,peer,handler,audit
    def one(self,channel):
        phase='actor_peer'
        try:
            self.runtime.require_armed()
            with self.peer.hold(channel)as alive:
                need(channel.send(b'P')==1,'actor_greeting')
                phase='actor_read';value=read(channel,time.monotonic()+5)
                need(set(value)=={'operation','input'}and type(value['operation'])is str and type(value['input'])is dict,'actor_request_fields')
                phase='actor_operation';result=self.handler(value['operation'],value['input']);alive()
                send(channel,{'ok':True,'result':result},time.monotonic()+5)
            return True
        except Exception as e:self.audit.failure(e,phase);return False
        finally:channel.close()

from server import Listener
