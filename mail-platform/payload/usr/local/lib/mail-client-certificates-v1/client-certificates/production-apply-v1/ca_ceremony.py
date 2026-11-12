"""One real CA ceremony actor, ONLY a later explicitly approved one-shot unit.

No root key/file output. Recovery stays locked until the root coordinator has
exported it over its private pipe and acknowledges receipt. No automatic retry.
"""
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import socket
import struct
import sys
import time
ROOT=Path('/usr/local/lib/mail-client-certificates-v1')
RUN=Path('/run/mail-client-cert-ca-bootstrap-v1')
sys.dont_write_bytecode=True
sys.path[:0]=[str(ROOT/'client-certificates'/p)for p in('runtime-completion-v1','production-apply-v1','final-integration-v1','production-runtime-v1',
    'integration-v1','activation-stack-v1','wiring-v1','session-broker-v1','live-transport-v1','enforcement-integration-v1','adapters-v1','identity-security-v1')]+['/usr/lib/python3/dist-packages']

def notify():
    value=os.environ.get('NOTIFY_SOCKET');need(type(value)is str and value[:1]in {'/','@'},'ca_notify_socket')
    with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)as s:s.connect('\0'+value[1:]if value.startswith('@')else value);s.sendall(b'READY=1\nSTATUS=protected CA export ready')

def need(value,code):
    if value is not True:raise ValueError(code)

def exact(channel,size):
    chunks=[];left=size
    while left:
        raw=channel.recv(min(left,8192));need(bool(raw),'ca_export_peer_eof');chunks.append(raw);left-=len(raw)
    return b''.join(chunks)

def main():
    phase='startup';fds=[];regions=[];listener=None
    try:
        need(sys.argv[1:]==['--create-once']and os.geteuid()>0,'ca_fixed_actor_command')
        import pwd,grp
        need(os.geteuid()==pwd.getpwnam('mailcert-issuer').pw_uid and os.getegid()==grp.getgrnam('mailcert-owner').gr_gid,'ca_dedicated_issuer_identity')
        need(Path('/proc/self/cgroup').read_text()=='0::/system.slice/mail-client-cert-ca-bootstrap-v1.service\n','ca_fixed_cgroup')
        from safety import held,shape
        manifest=json.loads(held(str(ROOT/'runtime-manifest.json'),1048576))
        for name,pin in manifest['pins'].items():need(sha256(held(str(ROOT/name),2097152)).hexdigest()==pin,'ca_release_source_drift')
        from native import LinuxRuntime,LinuxRegions
        from guarded_task import Task
        from offline import restoration,canonical
        runtime=LinuxRuntime(os.geteuid());runtime.harden_self();pool=LinuxRegions(runtime)
        def public(path,pin):
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);fds.append(fd)
            need(sha256(os.pread(fd,33554433,0)).hexdigest()==pin,'ca_public_executable_pin');return fd
        task=Task(runtime,pool,public(Path('/usr/bin/python3').resolve(),manifest['python_pin']),manifest['python_pin'],
            public(ROOT/'guard.so',manifest['guard_pin']),manifest['guard_pin'],public(ROOT/'secret_worker.py',manifest['pins']['secret_worker.py']),manifest['pins']['secret_worker.py'])
        recovery=pool.allocate(32);regions.append(recovery);recovery.write(__import__('secrets').token_bytes(32))
        dummy1=pool.allocate(32);regions.append(dummy1);dummy1.write(b'unused-one')
        dummy2=pool.allocate(32);regions.append(dummy2);dummy2.write(b'unused-two')
        phase='protected_ceremony';material=task.run({'operation':'ceremony'},recovery.fd,dummy1.fd,dummy2.fd)
        import base64
        capsule=base64.b64decode(material['files']['encrypted_backup'],validate=True)
        # The fixed worker reads st_size, not a region's logical length. Use a
        # sized locked tmpfs file supplied by a narrow local helper below.
        # Ceremony backup is public ciphertext. A sized memfd is not a trusted
        # DB credential; resize its independent FD before sealing/worker use.
        capsule_fd=os.memfd_create('mail-ca-encrypted-backup',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING);fds.append(capsule_fd)
        need(os.write(capsule_fd,capsule)==len(capsule),'ca_capsule_write')
        import fcntl
        fcntl.fcntl(capsule_fd,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
        phase='independent_restore';restored=task.run({'operation':'restore'},recovery.fd,capsule_fd,dummy2.fd);receipt=restoration(restored)
        need(material['issuer_id']==receipt['issuer_id'],'ca_restored_issuer_identity')
        export={'version':1,'issuer_id':material['issuer_id'],'files':material['files'],'receipt':receipt,
            'recovery_key':base64.b64encode(os.pread(recovery.fd,32,0)).decode(),'protection':restored['protection']}
        raw=canonical(export);need(len(raw)<=131072,'ca_export_bound')
        listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);listener.bind(str(RUN/'export.sock'));os.chmod(RUN/'export.sock',0o600);listener.listen(1);listener.settimeout(120)
        phase='root_export';notify();channel,_=listener.accept()
        with channel:
            channel.settimeout(120);pid,uid,gid=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            need(pid>0 and uid==gid==0,'ca_export_root_peer');need(exact(channel,8)==b'EXPORT1\n','ca_export_fixed_request')
            channel.sendall(struct.pack('!I',len(raw))+raw)
            expected=sha256(canonical(receipt)).hexdigest().encode()
            need(exact(channel,65)==expected+b'\n','ca_export_acknowledgement_binding')
        return 0
    except BaseException as error:
        try:
            from safety import shape
            value=shape(error,phase)
        except Exception:
            import traceback
            f=traceback.extract_tb(error.__traceback__)[-1];value={'class':type(error).__name__,'source':Path(f.filename).name,'line':f.lineno,'errno':getattr(error,'errno',None),'raw_error_saved':False}
        print(json.dumps({'component':'mail_client_certificates','failure':value}),flush=True);return 1
    finally:
        if listener is not None:listener.close()
        for region in reversed(regions):region.retire()
        for fd in reversed(fds):os.close(fd)
if __name__=='__main__':raise SystemExit(main())
