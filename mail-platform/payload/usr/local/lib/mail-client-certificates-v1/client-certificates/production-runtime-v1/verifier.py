"""Dedicated Passkey verifier logic. Existing cryptographic validator is reused.

    Only the orchestrator's kernel-authenticated RPC can call this service.
    FPM cannot supply a verification-success flag. PHP signature work executes
    in a pinned, guarded child with no SQL/network or credential descriptors.
"""
import base64
from dataclasses import dataclass
import json
import re
import secrets
import threading


def need(value,code):
    if value is not True:raise ValueError(code)


def binary(value):
    need(type(value)in (bytes,bytearray),'verifier_binary_type');return bytes(value)


@dataclass(frozen=True)
class Ceremony:
    uid:int
    binding:str
    handle:bytes
    options:str
    expires:float


class VerifierService:
    def __init__(self,runtime,connector,crypto,clock):
        self.runtime,self.connector,self.crypto,self.clock=runtime,connector,crypto,clock
        self.pending={};self.lock=threading.RLock()

    def begin(self,uid,binding):
        self.runtime.require_armed();need(type(uid)is int and uid>0 and type(binding)is str and re.fullmatch('[0-9a-f]{64}',binding)is not None,'verifier_owner_binding')
        with self.lock:
            now=self.clock();self.pending={k:v for k,v in self.pending.items()if v.expires>now}
            need(len(self.pending)<512 and sum(v.uid==uid for v in self.pending.values())<2,'verifier_pending_limit')
            connection=self.connector()
            try:
                cursor=connection.cursor();cursor.execute('SELECT user_handle FROM roundcube.auth_webauthn_users WHERE user_id=%s LIMIT 2',(uid,));rows=cursor.fetchmany(3)
                need(len(rows)==1 and len(rows[0])==1,'verifier_user_handle');handle=binary(rows[0][0]);need(len(handle)==32,'verifier_handle_size')
                cursor.execute('SELECT credential_id,transports_json FROM roundcube.auth_webauthn_credentials WHERE user_id=%s AND enabled=1 ORDER BY id LIMIT 129',(uid,))
                rows=cursor.fetchmany(130);need(0<len(rows)<=128,'verifier_credential_count');descriptors=[]
                for credential,transports in rows:
                    credential=binary(credential);need(0<len(credential)<=1023,'verifier_credential_id')
                    values=json.loads(transports);need(type(values)is list,'verifier_transport_shape')
                    descriptors.append({'id':base64.b64encode(credential).decode(),'transports':[v for v in values if type(v)is str]})
            finally:connection.close()
            options=self.crypto.options(descriptors)
            need(type(options)is str and 0<len(options.encode())<=65536 and json.loads(options).get('userVerification')=='required','verifier_uv_required')
            identifier=secrets.token_urlsafe(32);self.pending[identifier]=Ceremony(uid,binding,handle,options,now+300)
            return identifier,json.loads(options)

    def finish(self,uid,binding,ceremony,response):
        self.runtime.require_armed()
        need(type(uid)is int and uid>0 and type(binding)is str and re.fullmatch('[0-9a-f]{64}',binding)is not None
            and type(ceremony)is str and 16<=len(ceremony)<=128,'verifier_finish_binding')
        with self.lock:state=self.pending.pop(ceremony,None)
        need(type(state)is Ceremony and state.uid==uid and state.binding==binding and self.clock()<state.expires,'verifier_ceremony_consumed_or_scope')
        need(type(response)is dict,'verifier_response_object');encoded=response.get('rawId')
        need(type(encoded)is str and 2<=len(encoded)<=1364 and re.fullmatch('[A-Za-z0-9_-]+',encoded)is not None,'verifier_credential_encoding')
        credential=base64.urlsafe_b64decode(encoded+'='*((-len(encoded))%4));need(0<len(credential)<=1023,'verifier_credential_size')
        need(base64.urlsafe_b64encode(credential).decode().rstrip('=')==encoded,'verifier_credential_noncanonical')
        raw=json.dumps(response,separators=(',',':'),ensure_ascii=True);need(len(raw)<=65536,'verifier_response_bound')
        connection=self.connector();committing=False
        try:
            connection.autocommit(False);connection.begin();cursor=connection.cursor()
            cursor.execute('SELECT credential_id,user_handle,credential_record_json FROM roundcube.auth_webauthn_credentials WHERE user_id=%s AND credential_id=%s AND enabled=1 LIMIT 2 FOR UPDATE',(uid,credential));rows=cursor.fetchmany(3)
            need(len(rows)==1 and len(rows[0])==3,'verifier_enabled_credential')
            current,handle,record=rows[0];current,handle=binary(current),binary(handle)
            need(current==credential and handle==state.handle and type(record)is str and 0<len(record.encode())<=131072,'verifier_stored_binding')
            validated=self.crypto.verify(raw,state.options,current,handle,record,state.handle)
            need(type(validated)is dict and set(validated)=={'credential_id','user_handle','record','sign_count'}
                and binary(validated['credential_id'])==current and binary(validated['user_handle'])==handle
                and type(validated['record'])is str and 0<len(validated['record'].encode())<=131072
                and type(validated['sign_count'])is int and validated['sign_count']>=0,'verifier_signature_result')
            cursor.execute('UPDATE roundcube.auth_webauthn_credentials SET credential_record_json=%s,sign_count=%s,last_used_at=CURRENT_TIMESTAMP WHERE user_id=%s AND credential_id=%s AND enabled=1 AND credential_record_json=%s',
                (validated['record'],validated['sign_count'],uid,current,record))
            need(cursor.rowcount in (0,1),'verifier_update_rowcount')
            cursor.execute('SELECT credential_record_json,sign_count,enabled FROM roundcube.auth_webauthn_credentials WHERE user_id=%s AND credential_id=%s LIMIT 2',(uid,current));rows=cursor.fetchmany(3)
            need(rows==((validated['record'],validated['sign_count'],1),)or rows==[(validated['record'],validated['sign_count'],1)],'verifier_update_readback')
            committing=True;connection.commit()
        except BaseException:
            try:connection.rollback()
            finally:connection.close()
            if committing:raise ValueError('verifier_commit_unknown')from None
            raise
        else:connection.close()


class ExistingWebauthnClient:
    def __init__(self,wire,owner):self.wire,self.owner=wire,owner
    def begin(self,uid):
        owner=self.owner();need(owner.roundcube_id==uid,'verifier_client_owner')
        result=self.wire.call('begin',{'uid':uid,'binding':owner.session_hash})
        need(type(result)is dict and set(result)=={'ceremony_id','publicKey'},'verifier_options_reply')
        return result['ceremony_id'],result['publicKey']
    def verify_uv(self,uid,ceremony,response):
        owner=self.owner();need(owner.roundcube_id==uid,'verifier_client_owner')
        result=self.wire.call('finish',{'uid':uid,'binding':owner.session_hash,'ceremony':ceremony,'response':response})
        need(result=={'verified':True},'verifier_finish_reply')
