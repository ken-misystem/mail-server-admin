"""DB-verified exact-generation deny/drain/CRL RPC; no optimistic acknowledgements."""
from hashlib import sha256
import json
import threading
import uuid
from safety import need
from frozen_runtime import domain
from control import request

def row(connector,device):
    domain.identifier(device);connection=connector()
    try:
        cursor=connection.cursor();cursor.execute('START TRANSACTION READ ONLY')
        cursor.execute('SELECT owner_id,owner_epoch,owner_identity_version,revocation_generation,state,serial,issuer_id FROM mail_client_devices WHERE id=%s LIMIT 2',(uuid.UUID(device).bytes,))
        rows=cursor.fetchmany(3);connection.rollback();need(len(rows)==1 and len(rows[0])==7,'actuation_device_missing')
        return rows[0]
    finally:connection.close()
def payload(device):
    return {'device_id':device.id,'generation':device.generation,'owner_epoch':device.epoch,'owner_identity_version':device.identity_version}

class Gate:
    def __init__(self,runtime,connector,sessions,contexts,readiness):
        self.runtime,self.connector,self.sessions,self.contexts,self.readiness=runtime,connector,sessions,contexts,readiness
        self.lock=threading.RLock();self.pending={}
    def verify(self,value,states):
        need(type(value)is dict and set(value)=={'device_id','generation','owner_epoch','owner_identity_version'},'actuation_request_fields')
        # Activation generation may be zero. Revocation must be positive.
        domain.identifier(value['device_id']);need(all(type(value[k])is int for k in ('generation','owner_epoch','owner_identity_version')),'actuation_integer_fields')
        current=row(self.connector,value['device_id'])
        need(current[1:4]==(value['owner_epoch'],value['owner_identity_version'],value['generation'])and current[4]in states,'actuation_database_binding')
        return current
    def call(self,operation,data):
        self.runtime.require_armed()
        with self.lock:
            if operation=='activate':
                self.verify(data,{'pending'});self.readiness.require_current('external_certificate_routes');self.contexts.fresh()
                return {'components':sorted(domain.ACTIVATION),'binding_sha256':sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest()}
            if operation=='deny':
                self.verify(data,{'revoke_pending','revoked'});need(data['generation']>0,'actuation_positive_generation')
                _,binding=request(data['device_id'],data['generation'],data['owner_epoch'],data['owner_identity_version'])
                drained=self.sessions.revoke(data['device_id'],data['generation'])
                need(drained['generation']==data['generation']and drained['remaining']==0,'actuation_drain_unverified')
                self.pending[data['device_id']]=(data['generation'],binding)
                return {'binding_sha256':binding,'components':['existing_sessions','imaps','pop3s','resumption','submission'],'closed':drained['closed']}
            need(operation=='install_crl'and set(data)=={'request','crl'},'actuation_operation')
            current=self.verify(data['request'],{'revoke_pending','revoked'});value=data['request']
            _,binding=request(value['device_id'],value['generation'],value['owner_epoch'],value['owner_identity_version'])
            need(self.pending.get(value['device_id'])==(value['generation'],binding)and type(current[5])is bytes and bool(current[5]),'actuation_crl_before_deny')
            need(str(uuid.UUID(bytes=current[6]))==data['crl']['issuer_id'],'actuation_issuer_binding')
            installed=self.contexts.install(data['crl'],int.from_bytes(current[5],'big'))
            return {'binding_sha256':binding,'component':'crl','installed':installed}

class Publisher:
    def __init__(self,gate,issuer,audit):self.gate,self.issuer,self.audit=gate,issuer,audit
    def activate(self,device):
        data=payload(device);value=self.gate.call('activate',data)
        expected=sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        need(type(value)is dict and set(value)=={'components','binding_sha256'}and value['binding_sha256']==expected
            and type(value['components'])is list and len(value['components'])==4 and frozenset(value['components'])==domain.ACTIVATION,'actuation_activation_ack')
        return domain.ACTIVATION
    def revoke(self,device):
        data=payload(device);_,binding=request(device.id,device.generation,device.epoch,device.identity_version);acks=set()
        try:
            value=self.gate.call('deny',data)
            need(set(value)=={'binding_sha256','components','closed'}and value['binding_sha256']==binding
                and set(value['components'])=={'imaps','pop3s','submission','resumption','existing_sessions'}
                and len(value['components'])==5 and type(value['closed'])is int and value['closed']>=0,'actuation_deny_ack')
            acks.update(value['components'])
            crl=self.issuer.call('crl',{})
            value=self.gate.call('install_crl',{'request':data,'crl':crl})
            need(set(value)=={'binding_sha256','component','installed'}and value['binding_sha256']==binding and value['component']=='crl'
                and value['installed']=={'number':crl['number'],'sha256':crl['sha256']},'actuation_crl_ack')
            acks.add('crl')
        except Exception as e:self.audit.failure(e,'revocation_publication')
        return device.generation,frozenset(acks)
