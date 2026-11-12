"""Public-only gate observation. No key/session/identity or control operation."""
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import time
import uuid

def need(value,code):
    if value is not True:raise ValueError(code)

class Publisher:
    def __init__(self,directory,certificate_fd):
        self.directory=Path(directory);meta=os.stat(self.directory,follow_symlinks=False)
        need(stat.S_ISDIR(meta.st_mode)and meta.st_uid==os.geteuid()and meta.st_mode&0o022==0,'gate_health_runtime_directory')
        raw=os.pread(certificate_fd,131073,0);need(0<len(raw)<=131072,'gate_health_public_certificate_bound')
        from cryptography import x509
        self.fingerprint=sha256(raw).hexdigest();self.expires=x509.load_pem_x509_certificate(raw).not_valid_after_utc.timestamp()
    def publish(self,number,expires,threads_healthy):
        need(type(number)is int and number>=0 and type(expires)in(int,float)and threads_healthy is True,'gate_health_current_runtime')
        value={'version':1,'observed_at':time.time(),'crl_number':number,'crl_expires':expires,'tls_certificate_sha256':self.fingerprint,
            'tls_expires':self.expires,'threads_healthy':True}
        raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
        parent=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            meta=os.fstat(parent);need(meta.st_uid==os.geteuid()and meta.st_mode&0o022==0,'gate_health_parent_drift')
            name='.health-'+uuid.uuid4().hex;fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o640,dir_fd=parent)
            try:os.fchmod(fd,0o640);need(os.write(fd,raw)==len(raw),'gate_health_short_write');os.fsync(fd)
            finally:os.close(fd)
            os.replace(name,'health.json',src_dir_fd=parent,dst_dir_fd=parent);os.fsync(parent)
        finally:os.close(parent)
        return value
