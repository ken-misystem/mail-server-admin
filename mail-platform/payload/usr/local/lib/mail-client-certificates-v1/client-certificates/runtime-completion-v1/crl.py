"""Issuer-only CRL snapshot and gate-side independent validation/rotation."""
import base64
from datetime import datetime,timezone
from hashlib import sha256
import json
import os
import ssl
import stat
import threading
import uuid
from safety import need,unchanged
MAX_REVOKED=1024
def snapshot(connector,issuer_id):
    need(str(uuid.UUID(issuer_id))==issuer_id,'crl_issuer_identity')
    connection=connector()
    try:
        cursor=connection.cursor();cursor.execute("SET SESSION time_zone='+00:00'")
        cursor.execute('SET SESSION max_statement_time=3');cursor.execute('START TRANSACTION READ ONLY')
        cursor.execute("SELECT j.serial FROM mail_client_issuer_journal j JOIN mail_client_devices d ON d.id=j.device_id "
            "WHERE j.issuer_id=%s AND d.state IN ('revoke_pending','revoked','issuance_unknown') "
            "AND COALESCE(j.expires_at,DATE_ADD(d.created_at,INTERVAL 90 DAY))>UTC_TIMESTAMP() "
            "ORDER BY j.serial LIMIT 1025",(uuid.UUID(issuer_id).bytes,))
        rows=cursor.fetchmany(MAX_REVOKED+1);connection.rollback()
        need(len(rows)<=MAX_REVOKED,'crl_capacity_rotation_required');values=[]
        for row in rows:
            need(len(row)==1 and type(row[0])is bytes and 0<len(row[0])<=20,'crl_serial_shape')
            value=int.from_bytes(row[0],'big');need(0<value<2**159,'crl_serial_range');values.append(value)
        need(len(values)==len(set(values)),'crl_duplicate_serial');return values
    finally:connection.close()

class Sequence:
    """One issuer process, durable reservation BEFORE CRL signing; gaps allowed."""
    def __init__(self,directory,issuer):self.directory,self.issuer,self.lock=directory,issuer,threading.Lock()
    def next(self):
        with self.lock:
            parent=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                info=os.fstat(parent);need(info.st_uid==os.geteuid()and info.st_mode&0o077==0,'crl_sequence_directory')
                try:fd=os.open('sequence.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                except FileNotFoundError:value={'issuer_id':self.issuer,'number':0}
                else:
                    try:
                        info=os.fstat(fd);need(stat.S_ISREG(info.st_mode)and info.st_uid==os.geteuid()and info.st_nlink==1 and info.st_mode&0o077==0 and 0<info.st_size<=1024,'crl_sequence_file')
                        value=json.loads(os.pread(fd,1025,0));need(unchanged(info,os.fstat(fd)),'crl_sequence_drift')
                    finally:os.close(fd)
                need(set(value)=={'issuer_id','number'}and value['issuer_id']==self.issuer and type(value['number'])is int and 0<=value['number']<2**63,'crl_sequence_identity')
                value['number']+=1;raw=json.dumps(value,sort_keys=True).encode();temp='sequence-'+uuid.uuid4().hex+'.new'
                fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
                try:need(os.write(fd,raw)==len(raw),'crl_sequence_write');os.fsync(fd)
                finally:os.close(fd)
                os.replace(temp,'sequence.json',src_dir_fd=parent,dst_dir_fd=parent);os.fsync(parent)
                return value['number']
            finally:os.close(parent)

class Authority:
    def __init__(self,runtime,connector,issuer,worker,sequence,public_root_crl):
        self.runtime,self.connector,self.issuer,self.worker,self.sequence,self.prefix=runtime,connector,issuer,worker,sequence,public_root_crl
        self.lock=threading.Lock()
    def bundle(self):
        self.runtime.require_armed()
        with self.lock:
            serials=snapshot(self.connector,self.issuer.id);number=self.sequence.next()
            result=self.worker.run({'operation':'crl','number':number,'serials':serials},self.issuer.certificate_fd,self.issuer.key_fd,self.issuer.password_fd)
            need(set(result)=={'ok','crl','protection'}and result['ok']is True,'crl_worker_reply')
            raw=base64.b64decode(result['crl'],validate=True);need(0<len(raw)<=98304,'crl_worker_bound')
            combined=self.prefix+raw
            return {'bundle':base64.b64encode(combined).decode(),'sha256':sha256(combined).hexdigest(),'issuer_id':self.issuer.id,'number':number,'entries':len(serials)}

class RotatingContexts:
    """Fixed CA chain/root CRL, current issuer CRL; new context per connection."""
    def __init__(self,certificate,key,root,issuer,root_crl,runtime,clock):
        self.certificate,self.key,self.root,self.issuer,self.root_crl,self.runtime,self.clock=certificate,key,root,issuer,root_crl,runtime,clock
        self.lock=threading.RLock();self.number=-1;self.blob=None;self.expires=0
    def install(self,value,required_serial=None):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        self.runtime.require_armed();need(type(value)is dict and set(value)=={'bundle','sha256','issuer_id','number','entries'},'crl_bundle_fields')
        raw=base64.b64decode(value['bundle'],validate=True)
        need(len(raw)<=131072 and sha256(raw).hexdigest()==value['sha256']and type(value['number'])is int and value['number']>=0,'crl_bundle_hash')
        prefix=self.root+self.issuer+self.root_crl;need(raw.startswith(prefix),'crl_fixed_public_chain')
        issuer=x509.load_pem_x509_certificate(self.issuer);root=x509.load_pem_x509_certificate(self.root)
        issuer.verify_directly_issued_by(root)
        tail=raw[len(prefix):];need(tail.count(b'-----BEGIN X509 CRL-----')==1 and tail.strip().endswith(b'-----END X509 CRL-----'),'single_issuer_crl')
        crl=x509.load_pem_x509_crl(tail);root_crl=x509.load_pem_x509_crl(self.root_crl)
        need(crl.issuer==issuer.subject and root_crl.issuer==root.subject and crl.is_signature_valid(issuer.public_key())and root_crl.is_signature_valid(root.public_key()),'crl_signature')
        now=datetime.fromtimestamp(self.clock(),timezone.utc)
        for item in (crl,root_crl):need(item.last_update_utc<=now<item.next_update_utc,'crl_expired_or_future')
        need(crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number==value['number']and len(crl)==value['entries']<=MAX_REVOKED,'crl_number_or_count')
        if required_serial is not None:need(crl.get_revoked_certificate_by_serial_number(required_serial)is not None,'revoked_serial_not_in_crl')
        with self.lock:
            need(value['number']>self.number,'crl_generation_not_new')
            self.blob,self.number,self.expires=raw,value['number'],min(crl.next_update_utc.timestamp(),root_crl.next_update_utc.timestamp())
        # Parsing and actual OpenSSL context creation precede the acknowledgement.
        self.fresh();return {'number':value['number'],'sha256':value['sha256']}
    def fresh(self):
        self.runtime.require_armed()
        with self.lock:need(self.blob is not None and self.clock()<self.expires,'crl_not_ready_or_expired');raw=self.blob
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.maximum_version=ssl.TLSVersion.TLSv1_3
        context.verify_mode=ssl.CERT_REQUIRED;context.post_handshake_auth=False;context.options|=ssl.OP_NO_TICKET|ssl.OP_NO_COMPRESSION;context.num_tickets=0
        context.verify_flags|=ssl.VERIFY_X509_STRICT|ssl.VERIFY_CRL_CHECK_CHAIN
        context.load_cert_chain('/proc/self/fd/'+str(self.certificate),'/proc/self/fd/'+str(self.key))
        # CPython _add_ca_certs(cadata) reads X509 certificates only, not CRLs.
        # Use the native cafile loader on a sealed public-only memfd instead.
        import fcntl
        fd=os.memfd_create('mail-client-public-ca-crl',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        try:
            need(os.write(fd,raw)==len(raw),'crl_context_short_write')
            fcntl.fcntl(fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
            context.load_verify_locations(cafile='/proc/self/fd/'+str(fd))
            stats=context.cert_store_stats();need(stats['crl']==2 and stats['x509_ca']==2,'crl_context_store_incomplete')
        finally:os.close(fd)
        return context
