"""Fresh session/owner/registry checks during EVERY P12 pull, including cleanup."""
from contextlib import contextmanager
from hashlib import sha256
from peer import need
from pull_stream import serve_stream,control
from broker_wire import object_read
from frozen_runtime import OwnerIdentity

class Application:
    def __init__(self,previous,identity_reader,registry):self.previous,self.identity_reader,self.registry=previous,identity_reader,registry
    @contextmanager
    def reference(self,value):
        refs=self.previous.references;binding=sha256(b'mail-device-v1\0'+value.encode('ascii')).hexdigest()
        if refs.slot.get()is None:
            with refs.bind(value):yield binding
        else:
            need(refs.current(binding)==value,'download_reference_changed');yield binding
    def resolve(self,reference):
        with self.reference(reference)as binding:
            record=self.previous.records.current(binding);context=record.context
            self.previous.first_use.current(context)
            class Session:
                def authenticated(_,key):need(key is context,'download_server_context');return context
            identity=OwnerIdentity(Session(),self.identity_reader).resolve(context)
            after=self.previous.records_gate.record(context)
            need(record.auth_epoch==after.auth_epoch==identity.epoch,'download_epoch_changed');return identity
    def run(self,request,writer=None):return self.previous.run(request,writer)
    def require_current(self,request,expected):
        need(self.resolve(request['session_ref'])==expected,'download_session_changed')
        current=self.registry.device_active(request['input']['device_id'])
        need((current.owner_id,current.epoch,current.identity_version)==(expected.owner_id,expected.epoch,expected.identity_version),'download_registry_changed')
class Connection:
    def __init__(self,runtime,peer,application,active_broker,cleanup_client,audit,clock):
        self.runtime,self.peer,self.application,self.active_broker,self.cleanup_client,self.audit,self.clock=runtime,peer,application,active_broker,cleanup_client,audit,clock
    def one(self,channel):
        phase='owner_peer'
        try:
            self.runtime.require_armed()
            with self.peer.hold(channel)as alive:
                need(channel.send(b'P')==1,'owner_greeting');phase='owner_request'
                request=object_read(channel,self.clock,self.clock()+5,131072)
                if request.get('operation')!='download':
                    result=self.application.run(request);alive();control(channel,result,self.clock,self.clock()+5);phase='response_sent'
                else:
                    need(set(request)=={'operation','input','session_ref'}and type(request['input'])is dict
                        and set(request['input'])=={'device_id','download_handle'},'owner_download_fields')
                    from frozen_runtime import domain
                    domain.identifier(request['input']['device_id']);identity=self.application.resolve(request['session_ref'])
                    def current():alive();self.application.require_current(request,identity)
                    def retire():
                        # The issuer holds its stream lock. Cancel over that
                        # SAME active stream before opening any cleanup RPC.
                        client=self.active_broker.client();device=request['input']['device_id']
                        if client.active is not None:
                            need(client.active['device_id']==device,'cleanup_active_device_mismatch');client.retire(device)
                        else:self.cleanup_client.retire_as(identity,device)
                    phase='owner_p12_pull'
                    serve_stream(channel,lambda writer:self.application.run(request,writer),self.runtime,current,retire,self.clock)
                    phase='response_sent'
            return True
        except Exception as error:
            if phase=='response_sent'and type(error)is ValueError and error.args==('fpm_peer_exited',):return True
            self.audit.failure(error,phase);return False
        finally:channel.close()
