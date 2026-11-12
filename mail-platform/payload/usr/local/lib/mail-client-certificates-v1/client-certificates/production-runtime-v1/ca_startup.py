"""Issuer-only startup contract. Does not create certificates or read a root key.

Offline custody is an operator acknowledgement plus separately retained restore
evidence; a file hash alone is not a claim that a backup is physically offline.
"""
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import re
import stat
import uuid
from peer import need


@dataclass(frozen=True)
class Issuer:
    id:str
    certificate_fd:int
    key_fd:int
    password_fd:int
    certificate_sha256:str


def load_issuer(runtime,descriptors,custody,inspect_chain):
    runtime.require_armed()
    need(type(descriptors)is dict and set(descriptors)=={'issuer_certificate','issuer_key','issuer_password'},'issuer_only_fd_inventory')
    need(all(type(fd)is int and fd>2 and not os.get_inheritable(fd)for fd in descriptors.values())
        and len(set(descriptors.values()))==3,'issuer_fd_alias_or_inheritance')
    identities=set()
    for role,fd in descriptors.items():
        info=os.fstat(fd);identity=info.st_dev,info.st_ino
        need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and identity not in identities
            and info.st_uid==os.geteuid()and info.st_mode&0o077==0 and 0<info.st_size<=65536,'issuer_fd_metadata')
        identities.add(identity)
    need(type(custody)is dict and set(custody)=={'issuer_id','issuer_certificate_sha256','root_certificate_sha256',
        'encrypted_backup_sha256','restore_evidence_sha256','custody_policy_accepted'}
        and re.fullmatch('[A-Za-z0-9_-]{8,64}',custody['issuer_id'])is not None
        and all(type(custody[k])is str and re.fullmatch('[0-9a-f]{64}',custody[k])is not None
            for k in ('issuer_certificate_sha256','root_certificate_sha256','encrypted_backup_sha256','restore_evidence_sha256'))
        and custody['custody_policy_accepted']is True,'issuer_custody_evidence_missing')
    need(str(uuid.UUID(custody['issuer_id']))==custody['issuer_id'],'issuer_uuid_identity')
    fd=descriptors['issuer_certificate'];before=os.fstat(fd);raw=os.pread(fd,before.st_size+1,0)
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_uid,s.st_mode)
    need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))
        and sha256(raw).hexdigest()==custody['issuer_certificate_sha256'],'issuer_certificate_pin')
    # Concrete checker must verify signature, CA pathLen=0, keyCertSign/cRLSign,
    # clientAuth-only issuance and validity against the pinned public root.
    inspect_chain(raw,custody['root_certificate_sha256'])
    return Issuer(custody['issuer_id'],fd,descriptors['issuer_key'],descriptors['issuer_password'],custody['issuer_certificate_sha256'])


class PublicChain:
    """Concrete public CA validation. Never loads a private root/issuer key."""
    def __init__(self,root_pem,clock):self.root_pem,self.clock=root_pem,clock
    def __call__(self,issuer_pem,root_pin):
        from datetime import datetime,timezone
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID
        need(type(self.root_pem)is bytes and sha256(self.root_pem).hexdigest()==root_pin,'public_root_pin')
        def parse(raw):
            need(type(raw)is bytes and 0<len(raw)<=65536 and raw.count(b'-----BEGIN CERTIFICATE-----')==1
                and raw.count(b'-----END CERTIFICATE-----')==1 and raw.strip().endswith(b'-----END CERTIFICATE-----'),'public_single_ca_certificate')
            return x509.load_pem_x509_certificate(raw)
        root,issuer=parse(self.root_pem),parse(issuer_pem)
        now=datetime.fromtimestamp(self.clock(),timezone.utc)
        for certificate,path_length in ((root,1),(issuer,0)):
            key=certificate.public_key();need(isinstance(key,rsa.RSAPublicKey)and key.key_size>=4096,'ca_rsa_strength')
            constraints=certificate.extensions.get_extension_for_class(x509.BasicConstraints)
            usage=certificate.extensions.get_extension_for_class(x509.KeyUsage)
            need(constraints.critical and constraints.value.ca and constraints.value.path_length==path_length
                and usage.critical and usage.value.key_cert_sign and usage.value.crl_sign
                and not usage.value.key_encipherment and not usage.value.data_encipherment and not usage.value.key_agreement,'ca_constraints_or_usage')
            need(certificate.not_valid_before_utc<=now<certificate.not_valid_after_utc,'ca_expired_or_future')
        need(root.subject==root.issuer and issuer.subject!=root.subject and issuer.issuer==root.subject,'ca_chain_names')
        root.verify_directly_issued_by(root);issuer.verify_directly_issued_by(root)
        eku=issuer.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        need(set(eku.value)=={ExtendedKeyUsageOID.CLIENT_AUTH},'issuer_client_auth_only')
        need(root.not_valid_before_utc<=issuer.not_valid_before_utc<issuer.not_valid_after_utc<=root.not_valid_after_utc,'issuer_validity_outside_root')
        need((root.not_valid_after_utc-root.not_valid_before_utc).total_seconds()<=3650*86400+300
            and(issuer.not_valid_after_utc-issuer.not_valid_before_utc).total_seconds()<=730*86400+300,'ca_validity_limit')


def ceremony_plan():
    return {'root':{'rsa_bits':4096,'valid_days':3650,'path_length':1,'retained_on_server':False},
        'issuer':{'rsa_bits':4096,'valid_days':730,'path_length':0,'encrypted_private_key':True},
        'leaf':{'rsa_bits':3072,'valid_days':90,'extended_key_usage':['clientAuth']},
        'offline_backup':{'encrypted':True,'restore_verification_required':True,'custodian_ack_required':True},
        'root_private_key_fd_allowed':False,'create_or_issue_executed':False}
