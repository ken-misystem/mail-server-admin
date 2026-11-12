"""Peer-authenticated owner envelope around the verified broker/P12 protocol."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict,fields
import json
import re
import struct
from peer import need
from frozen_runtime import Owner,domain,require
from broker_wire import BrokerWireClient,object_read
from transport_frozen import kernel_peer

def owner(value):
    need(type(value)is dict and set(value)=={v.name for v in fields(Owner)},'broker_owner_fields')
    need(all(type(value[k])is int and value[k]>0 for k in ('owner_id','roundcube_id','identity_version'))
        and type(value['epoch'])is int and 0<=value['epoch']<2**64 and value['active']is True
        and type(value['session_hash'])is str and re.fullmatch('[0-9a-f]{64}',value['session_hash'])is not None,'broker_owner_shape')
    return Owner(**value)
class Wrapped:
    def __init__(self,channel):self.channel=channel
    def __getattr__(self,key):return getattr(self.channel,key)
class OwnerEnvelope(Wrapped):
    def __init__(self,channel,current):super().__init__(channel);self.current,self.first=current,True
    def sendall(self,raw):
        if self.first:
            need(type(raw)is bytes and 4<len(raw)<=65540 and struct.unpack('!I',raw[:4])[0]==len(raw)-4,'broker_envelope_frame')
            value=json.loads(raw[4:]);need(type(value)is dict and 'owner'not in value,'broker_envelope_fields')
            current=self.current();need(type(current)is Owner,'broker_current_owner_type');value['owner']=asdict(current)
            payload=json.dumps(value,separators=(',',':')).encode();raw=struct.pack('!I',len(payload))+payload;self.first=False
        self.channel.sendall(raw)
class Client(BrokerWireClient):
    def __init__(self,runtime,factory,current,clock):
        super().__init__(runtime,factory,factory.uid,factory.gid,clock);self.current=current;self.cleanup=ContextVar('broker_cleanup_owner',default=None)
    def open(self):
        self.require_peer();return OwnerEnvelope(self.factory.open(),lambda:self.cleanup.get()or self.current())
    def retire_as(self,identity,device_id):
        need(type(identity)is Owner and self.active is None,'retire_separate_connection')
        token=self.cleanup.set(identity)
        try:return self.retire(device_id)
        finally:self.cleanup.reset(token)
class BufferedRequest(Wrapped):
    def __init__(self,channel,request):
        super().__init__(channel);raw=json.dumps(request,separators=(',',':')).encode();self.pending=bytearray(struct.pack('!I',len(raw))+raw)
    def recv(self,count,*args):
        if self.pending:
            raw=bytes(self.pending[:count]);del self.pending[:count];return raw
        return self.channel.recv(count,*args)
    def recvmsg(self,count,ancbufsize=0,flags=0):
        if self.pending:
            # The pinned framed receiver uses recvmsg to reject SCM_RIGHTS.
            # This frame was already received and ancillary-checked by it.
            need(flags & getattr(__import__('socket'),'MSG_PEEK',0)==0,'buffered_request_peek_denied')
            return self.recv(count),[],0,None
        return self.channel.recvmsg(count,ancbufsize,flags)
class Provider:
    def __init__(self):self.frame=ContextVar('issuer_authenticated_owner',default=None)
    def owner(self):
        value=self.frame.get();need(type(value)is Owner,'issuer_owner_missing');return value
    @contextmanager
    def bind(self,value):
        need(type(value)is Owner and self.frame.get()is None,'issuer_owner_scope');token=self.frame.set(value)
        try:yield
        finally:self.frame.reset(token)
class Server:
    def __init__(self,runtime,uid,gid,provider,delegate,audit,clock):self.runtime,self.uid,self.gid,self.provider,self.delegate,self.audit,self.clock=runtime,uid,gid,provider,delegate,audit,clock
    def one(self,channel):
        try:
            self.runtime.require_armed();kernel_peer(channel,self.uid,self.gid)
            need(channel.send(b'P')==1,'broker_actor_greeting')
            request=object_read(channel,self.clock,self.clock()+5)
            need(type(request)is dict and 'owner'in request,'broker_envelope_missing');identity=owner(request.pop('owner'))
            with self.provider.bind(identity):return self.delegate.one(BufferedRequest(channel,request))
        except Exception as error:self.audit.failure(error,'broker_owner_envelope');channel.close();return False
