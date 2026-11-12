"""Fixed broker RPC and cancellable stream proxy. No listener or signing here."""
from dataclasses import asdict, fields
import json
from transport_frozen import require, domain, kernel_peer, receive, unique
from pull_stream import control, send, RemoteRegion, serve_stream


def object_read(channel,clock,deadline,maximum=65536):
    value=json.loads(receive(channel,clock,deadline,maximum=maximum),object_pairs_hook=unique)
    require(type(value)is dict,'broker_response_object','broker_wire');return value


class BrokerWireClient:
    def __init__(self,runtime,factory,uid,gid,clock):
        self.runtime,self.factory,self.uid,self.gid,self.clock=runtime,factory,uid,gid,clock
        # One client per request scope; no shared mutable per-owner/session singleton.
        self.active=None
    def require_peer(self):
        self.runtime.require_armed();self.factory.require_current()
    def open(self):
        self.require_peer();channel=self.factory.open()
        try:kernel_peer(channel,self.uid,self.gid);return channel
        except BaseException:channel.close();raise
    def prepare(self,device,password,now):
        require(type(device)is domain.Device,'broker_wire_device','broker_wire')
        channel=self.open();deadline=self.clock()+10
        try:
            control(channel,{'operation':'prepare','device':asdict(device),'password':password},self.clock,deadline)
            value=object_read(channel,self.clock,self.clock()+200)
            require(set(value)=={'receipt'} and type(value['receipt'])is dict
                    and set(value['receipt'])=={f.name for f in fields(domain.Receipt)},'broker_receipt_shape','broker_wire')
            return domain.Receipt(**value['receipt'])
        finally:channel.close()
    def stream(self,device_id,destination):
        require(self.active is None,'broker_wire_reentry','broker_wire')
        channel=self.open();deadline=self.clock()+15;state={'device_id':device_id,'channel':channel,
            'deadline':deadline,'retired':False,'position':0}
        self.active=state
        try:
            control(channel,{'operation':'stream','device_id':device_id},self.clock,deadline)
            value=object_read(channel,self.clock,deadline)
            require(set(value)=={'p12_length'} and type(value['p12_length'])is int
                    and 0<value['p12_length']<=131072,'broker_stream_length','broker_wire')
            def reader(offset,count):
                require(not state['retired'] and offset==state['position'] and type(count)is int
                        and 0<count<=8192,'broker_stream_offset','broker_wire')
                control(channel,{'read':count},self.clock,deadline)
                block=receive(channel,self.clock,deadline,maximum=count+1)
                require(block[:1]==b'B' and len(block)==count+1,'broker_stream_bytes','broker_wire')
                state['position']+=count;return block[1:]
            destination.send_region(RemoteRegion(value['p12_length'],reader),deadline)
            require(state['position']==value['p12_length'] and not state['retired'],
                    'broker_stream_incomplete','broker_wire')
            control(channel,{'complete':True},self.clock,deadline)
            require(object_read(channel,self.clock,deadline)=={'complete':True,'retired':True},
                    'broker_stream_ack','broker_wire');state['retired']=True
        finally:
            try:
                if not state['retired']:self.retire(device_id)
            finally:self.active=None;channel.close()
    def retire(self,device_id):
        state=self.active
        if state is not None:
            require(state['device_id']==device_id,'broker_retire_device','broker_wire')
            if state['retired']:return
            control(state['channel'],{'retire':True},self.clock,state['deadline'])
            require(object_read(state['channel'],self.clock,state['deadline'])=={'retired':True},
                    'broker_retire_ack','broker_wire');state['retired']=True;return
        channel=self.open();deadline=self.clock()+5
        try:
            control(channel,{'operation':'retire','device_id':device_id},self.clock,deadline)
            require(object_read(channel,self.clock,deadline)=={'retired':True},'broker_retire_ack','broker_wire')
        finally:channel.close()


class BrokerWireServer:
    def __init__(self,runtime,uid,gid,broker,current,audit,clock,wallclock):
        self.runtime,self.uid,self.gid,self.broker,self.current,self.audit,self.clock,self.wallclock=(
            runtime,uid,gid,broker,current,audit,clock,wallclock)
    def one(self,channel):
        phase='broker_peer'
        try:
            self.runtime.require_armed();kernel_peer(channel,self.uid,self.gid)
            phase='broker_request';deadline=self.clock()+5
            value=object_read(channel,self.clock,deadline)
            operation=value.get('operation')
            if operation=='prepare':
                require(set(value)=={'operation','device','password'} and type(value['device'])is dict
                        and set(value['device'])=={f.name for f in fields(domain.Device)},'broker_prepare_scope','broker_wire')
                value['device']['pending_components']=tuple(value['device']['pending_components'])
                phase='broker_prepare'
                receipt=self.broker.prepare(domain.Device(**value['device']),value['password'],int(self.wallclock()))
                control(channel,{'receipt':asdict(receipt)},self.clock,self.clock()+5)
            else:
                require(operation in {'stream','retire'} and set(value)=={'operation','device_id'},
                        'broker_operation_scope','broker_wire')
                device=value['device_id'];domain.identifier(device)
                if operation=='retire':
                    self.broker.retire(device);control(channel,{'retired':True},self.clock,self.clock()+5)
                else:
                    phase='broker_stream'
                    serve_stream(channel,lambda writer:self.broker.stream(device,writer),self.runtime,
                        lambda:self.current(device),lambda:self.broker.retire(device),self.clock)
            return True
        except Exception as error:self.audit.failure(error,phase);return False
        finally:channel.close()
