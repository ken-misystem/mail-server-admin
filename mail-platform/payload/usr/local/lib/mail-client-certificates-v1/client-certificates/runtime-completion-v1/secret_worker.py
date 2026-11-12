"""Fixed guarded process; no SQL, network, subprocess, raw diagnostics or path input."""
import base64
from datetime import datetime,timedelta,timezone
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import resource
import stat
import struct
import sys
import traceback
RELEASE=Path('/usr/local/lib/mail-client-certificates-v1')
sys.path[:0]=[str(RELEASE/'client-certificates/runtime-completion-v1'),str(RELEASE/'client-certificates/final-integration-v1'),
    str(RELEASE/'client-certificates/production-runtime-v1'),'/usr/lib/python3/dist-packages']
def need(v,c):
    if v is not True:raise ValueError(c)
def raw(fd,maximum):
    before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and 0<before.st_size<=maximum,'secret_fd_bound')
    value=os.pread(fd,before.st_size+1,0);after=os.fstat(fd)
    need(len(value)==before.st_size and all(getattr(before,k)==getattr(after,k)for k in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')),'secret_fd_drift')
    return value
def frame(fd):
    value=raw(fd,131072);length=struct.unpack('!I',value[:4])[0];need(0<length<=len(value)-4,'secret_request_frame');return value[4:4+length]
def protection():
    libc=ctypes.CDLL(None,use_errno=True);s=Path('/proc/self/status').read_text();fields=dict(line.split(':',1)for line in s.splitlines()if ':'in line)
    p={'dumpable':libc.prctl(3,0,0,0,0),'seccomp':libc.prctl(21,0,0,0,0),'no_new_privileges':libc.prctl(39,0,0,0,0),
        'cap_eff':int(fields['CapEff'].strip(),16),'locked_kib':int(fields['VmLck'].split()[0])}
    need(p['dumpable']==p['cap_eff']==0 and p['seccomp']==2 and p['no_new_privileges']==1 and p['locked_kib']>0
        and resource.getrlimit(resource.RLIMIT_CORE)==(0,0),'guarded_worker_protection_required');return p
def main():
    result={'ok':False};phase='protection'
    try:
        safe=protection();phase='request';request=json.loads(frame(3));operation=request.get('operation')
        import cryptography
        need(str(cryptography.__file__).startswith('/usr/lib/python3/dist-packages/cryptography/'),'secret_crypto_import_origin')
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization,hashes
        phase=operation
        if operation=='crl':
            need(set(request)=={'operation','number','serials'}and type(request['number'])is int and 0<request['number']<2**63
                and type(request['serials'])is list and len(request['serials'])<=1024 and len(set(request['serials']))==len(request['serials'])
                and all(type(n)is int and 0<n<2**159 for n in request['serials']),'crl_worker_request')
            certificate=x509.load_pem_x509_certificate(raw(4,65536));password=raw(6,1024)
            if password.endswith(b'\n'):password=password[:-1]
            need(password and b'\n'not in password,'crl_worker_password_frame')
            key=serialization.load_pem_private_key(raw(5,65536),password)
            encoded=lambda k:k.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
            need(encoded(key.public_key())==encoded(certificate.public_key())and certificate.extensions.get_extension_for_class(x509.KeyUsage).value.crl_sign,'crl_worker_key_pair')
            now=datetime.now(timezone.utc).replace(microsecond=0)
            builder=x509.CertificateRevocationListBuilder().issuer_name(certificate.subject).last_update(now-timedelta(seconds=30)).next_update(min(now+timedelta(hours=24),certificate.not_valid_after_utc))\
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),False).add_extension(x509.CRLNumber(request['number']),False)
            for serial in sorted(request['serials']):
                revoked=x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(now).add_extension(x509.CRLReason(x509.ReasonFlags.cessation_of_operation),False).build()
                builder=builder.add_revoked_certificate(revoked)
            value=builder.sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM);need(len(value)<=98304,'crl_worker_output_bound')
            result={'ok':True,'crl':base64.b64encode(value).decode(),'protection':safe}
        elif operation in {'ceremony','restore'}:
            # No root key is supplied to the parent or online issuer.
            from custody import ceremony,restore
            class Runtime:
                def require_armed(self):protection()
            class Recovery:capacity=32;length=32;fd=4
            need(os.fstat(4).st_size==32,'recovery_key_exact_size')
            if operation=='ceremony':
                need(request=={'operation':'ceremony'},'ca_ceremony_request');material=ceremony(Runtime(),Recovery(),__import__('time').time)
                decoded,metadata=restore(Runtime(),Recovery(),material.encrypted_backup)
                root=x509.load_pem_x509_certificate(material.root_certificate)
                root_key=serialization.load_der_private_key(decoded['root_key'],None);now=datetime.now(timezone.utc).replace(microsecond=0)
                root_crl=x509.CertificateRevocationListBuilder().issuer_name(root.subject).last_update(now-timedelta(seconds=30)).next_update(now+timedelta(days=365))\
                    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),False).add_extension(x509.CRLNumber(1),False)\
                    .sign(root_key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
                fields={'root_certificate':material.root_certificate,'issuer_certificate':material.issuer_certificate,'issuer_key':material.encrypted_issuer_key,
                    'issuer_password':material.issuer_password,'encrypted_backup':material.encrypted_backup,'root_crl':root_crl}
                result={'ok':True,'issuer_id':material.issuer_id,'files':{k:base64.b64encode(v).decode()for k,v in fields.items()},'restore_verified':True,'protection':safe}
            else:
                need(request=={'operation':'restore'},'ca_restore_request');decoded,metadata=restore(Runtime(),Recovery(),raw(5,98304))
                result={'ok':True,'issuer_id':metadata['issuer_id'],'root_sha256':metadata['root_sha256'],'issuer_sha256':metadata['issuer_sha256'],
                    'backup_sha256':sha256(raw(5,98304)).hexdigest(),'restore_verified':True,'protection':safe}
        else:raise ValueError('secret_worker_operation')
    except BaseException as error:
        failure_frame=traceback.extract_tb(error.__traceback__)[-1]
        allowed={n.value for n in __import__('ast').walk(__import__('ast').parse(Path(__file__).read_bytes()))if isinstance(n,__import__('ast').Constant)and type(n.value)is str}
        reason=error.args[0]if type(error)is ValueError and error.args and error.args[0]in allowed else'unclassified'
        result={'ok':False,'failure':{'phase':phase,'class':type(error).__name__,'reason':reason,
            'source':'secret_worker.py'if failure_frame.filename=='/proc/self/fd/7'else Path(failure_frame.filename).name,
            'function':failure_frame.name,'line':failure_frame.lineno,'errno':getattr(error,'errno',None),'raw_error_saved':False}}
        if isinstance(error,NameError):result['failure']['missing_symbol']=error.name
        if isinstance(error,ModuleNotFoundError):result['failure']['missing_module']=error.name
    encoded=json.dumps(result,sort_keys=True,separators=(',',':')).encode();need(0<len(encoded)<=131072,'secret_worker_result_bound')
    need(os.write(1,encoded)==len(encoded),'secret_worker_short_output');return int(result['ok']is not True)
if __name__=='__main__':raise SystemExit(main())
