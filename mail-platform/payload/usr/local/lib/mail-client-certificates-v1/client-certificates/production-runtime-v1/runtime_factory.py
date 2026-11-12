"""Explicit owner/session/lifecycle/verifier/broker construction, never activation.

Inputs are held role descriptors and reviewed kernel-authenticated channels.
No default actor, database path, credential file, startup arming or CA generation.
"""
from dataclasses import asdict
import threading
from actions_store import ActionStore
from lifecycle import BootstrapReader,FirstUseSession,LifecycleService
from peer import need
from session_connection import SessionApplication
from verifier import ExistingWebauthnClient


def owner_application(*,fd_set,principals,sql_socket,session_connector,records,
        references,lifecycle_wire,verifier_wire,broker_channel,enforcement,audit,clock):
    from role_startup import orchestrator
    from frozen_runtime import actions,IdentitySnapshot,SessionContext
    from sessions import EpochBoundSession
    need(set(fd_set.fds)=={'identity_reader','orchestrator','gateway_reader'},'owner_role_inventory')
    connections=fd_set.connectors(principals,sql_socket)
    raw=BootstrapReader(connections['identity_reader'],SessionContext)
    class Provisioner:
        def ensure(self,context):return lifecycle_wire.call('ensure',{'context':asdict(context)})
    identity=IdentitySnapshot(connections['identity_reader'])
    gate=EpochBoundSession(fd_set.runtime,records,identity,clock)
    live=FirstUseSession(gate,raw,Provisioner(),gate)
    box={}
    uv=ExistingWebauthnClient(verifier_wire,lambda:box['scope'].owner())
    store=ActionStore(clock,actions.BoundAction)
    built=orchestrator(fd_set,principals,sql_socket,live,broker_channel,enforcement,audit,store,uv,clock)
    box['scope']=built['scope']
    # The connector is separately held, never one of the mail_management FDs.
    need(records.connector is session_connector,'session_role_connector_binding')
    built['session_application']=SessionApplication(references,records,gate,raw,live,built['dispatcher'])
    return built


def lifecycle_application(runtime,connector):
    from identity import SessionContext
    from provision import prepare_binding
    return LifecycleService(runtime,BootstrapReader(connector,SessionContext),connector,prepare_binding)


class ThreadBrokerChannel:
    """Existing stream client has mutable state: allocate one per request thread."""
    def __init__(self,create):self.create,self.local=create,threading.local()
    def client(self):
        if not hasattr(self.local,'client'):self.local.client=self.create()
        return self.local.client
    def require_peer(self):return self.client().require_peer()
    def prepare(self,*args):return self.client().prepare(*args)
    def stream(self,*args):return self.client().stream(*args)
    def retire(self,*args):return self.client().retire(*args)


class FixedRPC:
    def __init__(self,runtime,peer,handler,clock,audit):self.runtime,self.peer,self.handler,self.clock,self.audit=runtime,peer,handler,clock,audit
    def one(self,channel):
        from broker_wire import object_read
        from pull_stream import control
        try:
            self.runtime.require_armed();self.peer(channel)
            need(channel.send(b'P')==1,'rpc_greeting')
            value=object_read(channel,self.clock,self.clock()+5,131072)
            need(set(value)=={'operation','input'}and type(value['input'])is dict,'rpc_fields')
            result=self.handler(value['operation'],value['input']);control(channel,result,self.clock,self.clock()+5);return True
        except Exception as error:self.audit.failure(error,'fixed_actor_rpc');return False
        finally:channel.close()


class RPCClient:
    def __init__(self,factory,clock):self.factory,self.clock=factory,clock
    def call(self,operation,data):
        from broker_wire import object_read
        from pull_stream import control
        channel=self.factory.open()
        try:
            control(channel,{'operation':operation,'input':data},self.clock,self.clock()+5)
            return object_read(channel,self.clock,self.clock()+60,65536)
        finally:channel.close()


def verifier_handler(service):
    def call(operation,data):
        if operation=='begin':
            need(set(data)=={'uid','binding'},'verifier_begin_fields');ceremony,options=service.begin(data['uid'],data['binding'])
            return {'ceremony_id':ceremony,'publicKey':options}
        need(operation=='finish'and set(data)=={'uid','binding','ceremony','response'},'verifier_finish_fields')
        service.finish(data['uid'],data['binding'],data['ceremony'],data['response']);return {'verified':True}
    return call


def lifecycle_handler(service):
    def call(operation,data):
        from identity import SessionContext
        need(operation=='ensure'and set(data)=={'context'}and type(data['context'])is dict
            and set(data['context'])=={'roundcube_id','username','mail_host','binding_hash'},'lifecycle_rpc_fields')
        return service.ensure(SessionContext(**data['context']))
    return call
