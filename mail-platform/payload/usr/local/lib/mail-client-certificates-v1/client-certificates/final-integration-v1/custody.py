"""One-shot CA ceremony/AEAD backup core. Dedicated protected actor only.

Never prints keys or writes plaintext material. Caller's process must terminate
after bootstrap; reference release is not a claim of Python heap zeroization.
Only issuer material may be transferred to the online issuer. The recovery key
must be delivered separately from the encrypted backup and kept offline.
"""
from dataclasses import dataclass
from datetime import datetime,timedelta,timezone
from hashlib import sha256
import base64
import json
import os
import secrets
import uuid
from peer import need
from ca_startup import PublicChain,load_issuer

AAD=b'mail-client-ca-backup-v1\0'
@dataclass(repr=False)
class Material:
    issuer_id:str
    root_certificate:bytes
    issuer_certificate:bytes
    encrypted_issuer_key:bytes
    issuer_password:bytes
    encrypted_backup:bytes

def recovery_key(runtime,region):
    runtime.require_armed();need(region.capacity==32 and region.length==32,'recovery_key_region')
    raw=os.pread(region.fd,32,0);need(len(raw)==32,'recovery_key_size');return raw
def seal(runtime,region,payload,metadata):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key=recovery_key(runtime,region);nonce=secrets.token_bytes(12)
    header=json.dumps(metadata,sort_keys=True,separators=(',',':')).encode()
    need(len(header)<=2048 and type(payload)is bytes and 0<len(payload)<=65536,'ca_backup_payload_bound')
    encrypted=AESGCM(key).encrypt(nonce,payload,AAD+header)
    return json.dumps({'version':1,'metadata':metadata,'nonce':base64.b64encode(nonce).decode(),
        'ciphertext':base64.b64encode(encrypted).decode()},sort_keys=True,separators=(',',':')).encode()
def restore(runtime,region,capsule):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    need(type(capsule)is bytes and 0<len(capsule)<=98304,'ca_backup_capsule_bound')
    value=json.loads(capsule);need(type(value)is dict and set(value)=={'version','metadata','nonce','ciphertext'}and type(value['version'])is int and value['version']==1,'ca_backup_format')
    header=json.dumps(value['metadata'],sort_keys=True,separators=(',',':')).encode();nonce=base64.b64decode(value['nonce'],validate=True)
    need(len(header)<=2048 and len(nonce)==12,'ca_backup_header')
    raw=AESGCM(recovery_key(runtime,region)).decrypt(nonce,base64.b64decode(value['ciphertext'],validate=True),AAD+header)
    payload=json.loads(raw);need(type(payload)is dict and set(payload)=={'root_key','root_certificate','issuer_key','issuer_certificate','issuer_password'},'ca_backup_contents')
    decoded={k:base64.b64decode(v,validate=True)for k,v in payload.items()}
    metadata=value['metadata'];need(type(metadata)is dict and set(metadata)=={'issuer_id','root_sha256','issuer_sha256'},'ca_backup_metadata')
    need(str(uuid.UUID(metadata['issuer_id']))==metadata['issuer_id']and sha256(decoded['root_certificate']).hexdigest()==metadata['root_sha256']
        and sha256(decoded['issuer_certificate']).hexdigest()==metadata['issuer_sha256'],'ca_backup_certificate_binding')
    PublicChain(decoded['root_certificate'],__import__('time').time)(decoded['issuer_certificate'],metadata['root_sha256'])
    root=serialization.load_der_private_key(decoded['root_key'],None)
    issuer=serialization.load_pem_private_key(decoded['issuer_key'],decoded['issuer_password'])
    public=lambda key:key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    need(public(root.public_key())==public(x509.load_pem_x509_certificate(decoded['root_certificate']).public_key())
        and public(issuer.public_key())==public(x509.load_pem_x509_certificate(decoded['issuer_certificate']).public_key()),'restored_ca_key_pair')
    return decoded,metadata
def ceremony(runtime,recovery_region,clock):
    runtime.require_armed()
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization,hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
    now=datetime.fromtimestamp(clock(),timezone.utc).replace(microsecond=0);start=now-timedelta(seconds=60)
    root_key=rsa.generate_private_key(public_exponent=65537,key_size=4096);issuer_key=rsa.generate_private_key(public_exponent=65537,key_size=4096)
    def name(value):return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,value)])
    def certificate(subject,key,issuer,signer,days,pathlen,eku=False):
        builder=x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())\
            .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(start+timedelta(days=days))\
            .add_extension(x509.BasicConstraints(ca=True,path_length=pathlen),True)\
            .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),True)\
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),False)\
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()),False)
        if eku:builder=builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),True)
        return builder.sign(signer,hashes.SHA256())
    identifier=str(uuid.uuid4());root_name=name('Mail Device Offline Root '+identifier);issuer_name=name('Mail Device Issuer '+identifier)
    root=certificate(root_name,root_key,root_name,root_key,3650,1);issuer=certificate(issuer_name,issuer_key,root_name,root_key,730,0,True)
    root_pem=root.public_bytes(serialization.Encoding.PEM);issuer_pem=issuer.public_bytes(serialization.Encoding.PEM)
    password=secrets.token_hex(32).encode();encrypted=issuer_key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.BestAvailableEncryption(password))
    payload={'root_key':root_key.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()),
        'root_certificate':root_pem,'issuer_key':encrypted,'issuer_certificate':issuer_pem,'issuer_password':password}
    capsule=seal(runtime,recovery_region,json.dumps({k:base64.b64encode(v).decode()for k,v in payload.items()},sort_keys=True).encode(),
        {'issuer_id':identifier,'root_sha256':sha256(root_pem).hexdigest(),'issuer_sha256':sha256(issuer_pem).hexdigest()})
    return Material(identifier,root_pem,issuer_pem,encrypted,password,capsule)
def online_issuer(runtime,regions,descriptors,custody,root_pem,key_checker,clock):
    issuer=load_issuer(runtime,descriptors,custody,PublicChain(root_pem,clock))
    key_checker.verify(issuer);return issuer
class KeyChecker:
    """Fixed guarded PHP/OpenSSL API; never broadens the leaf runner's phases."""
    def __init__(self,runtime,php):self.runtime,self.php=runtime,php
    def verify(self,issuer):
        self.runtime.require_armed()
        def read(fd,bound):
            before=os.fstat(fd);need(0<before.st_size<=bound,'issuer_check_fd_bound')
            raw=os.pread(fd,before.st_size+1,0);after=os.fstat(fd)
            fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
            need(len(raw)==before.st_size and all(getattr(before,k)==getattr(after,k)for k in fields),'issuer_check_fd_drift');return raw
        certificate=read(issuer.certificate_fd,65536);encrypted=read(issuer.key_fd,65536);password=read(issuer.password_fd,1024)
        if password.endswith(b'\n'):password=password[:-1]
        need(bool(password)and b'\n'not in password and b'\x00'not in password,'issuer_single_line_passphrase')
        result=self.php.run({'operation':'issuer_key_pair'},certificate.decode('ascii'),encrypted.decode('ascii'),{'password':base64.b64encode(password).decode()})
        need(type(result)is dict and set(result)=={'ok','matched'}and result['ok']is True and result['matched']is True,'issuer_key_certificate_mismatch')
