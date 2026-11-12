"""Fresh server-side session resolution; HTTP cannot assert owner or UV success."""
from hashlib import sha256
from peer import need


class SessionApplication:
    def __init__(self,references,records,records_gate,bootstrap,first_use,dispatcher):
        self.references,self.records,self.records_gate=references,records,records_gate
        self.bootstrap,self.first_use,self.dispatcher=bootstrap,first_use,dispatcher

    def run(self,request,writer=None):
        need(type(request)is dict and set(request)=={'operation','input','session_ref'}
            and type(request['input'])is dict,'session_request_fields')
        operation=request['operation'];need(type(operation)is str and operation in
            {'current','list','issue_options','issue_finish','revoke_options','revoke_finish','download','verification_status','verification_options','verification_finish','verification_authorize','verification_consume','verification_invalidate'},'session_operation')
        reference=request['session_ref']
        with self.references.bind(reference):
            binding=sha256(b'mail-device-v1\0'+reference.encode('ascii')).hexdigest()
            record=self.records.current(binding);context=record.context
            checked=self.records_gate.record(context)
            need(checked.context==context and checked.auth_epoch==record.auth_epoch,'session_record_changed')
            if operation=='current':
                need(not request['input'],'current_no_client_identity')
                owner,_=self.bootstrap.current(context);need(owner.epoch==checked.auth_epoch,'session_current_epoch')
                return {'roundcube_id':context.roundcube_id,'username':context.username,'epoch':owner.epoch,'active':owner.active}
            self.first_use.current(context)
            if operation=='download':
                need(writer is not None,'download_writer_required')
                return self.dispatcher.download(context,request['input'],writer)
            return self.dispatcher.dispatch(operation,context,request['input'])


class SessionConnection:
    def __init__(self,runtime,peer,application,audit,clock,stream):
        self.runtime,self.peer,self.application,self.audit,self.clock,self.stream=runtime,peer,application,audit,clock,stream
    def one(self,channel):
        from broker_wire import object_read
        from pull_stream import control
        phase='fpm_kernel_peer'
        try:
            self.runtime.require_armed()
            with self.peer.hold(channel)as alive:
                need(channel.send(b'P')==1,'session_public_greeting')
                phase='fresh_session_dispatch';request=object_read(channel,self.clock,self.clock()+5,131072)
                if request.get('operation')=='download':
                    # stream is the already-validated pull/retirement adapter.
                    self.stream(channel,lambda writer:self.application.run(request,writer),alive)
                else:
                    result=self.application.run(request);alive();control(channel,result,self.clock,self.clock()+5)
            return True
        except Exception as error:self.audit.failure(error,phase);return False
        finally:channel.close()
