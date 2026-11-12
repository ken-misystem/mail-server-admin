"""Fixed root socket-generation watcher. Restarts ONLY new private units on drift."""
from pathlib import Path
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import json
import os
import socket
import stat
import subprocess
import time
from safety import need,held,Audit
RUN=Path('/run/mail-client-certificates-v1')
HOST={'cleanup':'/var/spool/postfix/public/cleanup','rewrite':'/var/spool/postfix/private/rewrite','auth':'/var/spool/postfix/private/auth','milter':str(RUN/'milter/milter.sock')}
DEST={'cleanup':RUN/'postfix/public/cleanup','rewrite':RUN/'postfix/private/rewrite','auth':RUN/'postfix/private/auth','milter':RUN/'native/milter.sock'}
def pin(path):
    s=os.stat(path,follow_symlinks=False);need(stat.S_ISSOCK(s.st_mode)and s.st_nlink==1,'delivery_socket_kind')
    return [s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode)]
def atomic(name,value):
    directory=RUN/'coordination';fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        s=os.fstat(fd);need(s.st_uid==0 and s.st_mode&0o022==0,'coordination_directory')
        temp=name+'-'+__import__('uuid').uuid4().hex+'.new';raw=(json.dumps(value,sort_keys=True)+'\n').encode()
        leaf=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o644,dir_fd=fd)
        try:os.fchmod(leaf,0o644);need(os.write(leaf,raw)==len(raw),'coordination_write');os.fsync(leaf)
        finally:os.close(leaf)
        os.replace(temp,name,src_dir_fd=fd,dst_dir_fd=fd);os.fsync(fd)
    finally:os.close(fd)
def capture():
    sources={k:pin(v)for k,v in HOST.items()};targets={k:pin(v)for k,v in DEST.items()}
    need(sources==targets,'delivery_mounted_socket_drift')
    fd=os.open('/proc/thread-self/ns/net',os.O_RDONLY|os.O_CLOEXEC)
    try:s=os.fstat(fd);namespace=[s.st_dev,s.st_ino]
    finally:os.close(fd)
    atomic('mounted.json',{'version':1,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'sockets':sources,'private_namespace':namespace})
def observe():
    value=json.loads(held(str(RUN/'coordination/mounted.json'),8192));need(set(value)=={'version','boot_id','sockets','private_namespace'}and value['version']==1,'coordination_snapshot_shape')
    now={k:pin(v)for k,v in HOST.items()}
    return value,now==value['sockets']
def watch():
    from boot import notify
    audit=Audit();stop=__import__('threading').Event();__import__('signal').signal(__import__('signal').SIGTERM,lambda *_:stop.set());last=None;notified=False
    while not stop.is_set():
        data={'version':1,'valid':False,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'observed_at':time.time(),'private_namespace':None}
        try:
            snapshot,current=observe();need(snapshot['boot_id']==data['boot_id'],'coordination_previous_boot')
            data.update(valid=current,private_namespace=snapshot['private_namespace'])
            if not current:
                token=json.dumps(snapshot['sockets'],sort_keys=True)
                if last!=token:
                    # Mark invalid BEFORE enqueuing rebind/restart. No mail-service operation.
                    atomic('ready.json',data)
                    done=subprocess.run(['/usr/bin/systemctl','--no-block','try-restart','mail-client-cert-postfix-backend.service','mail-client-cert-gate.service'],capture_output=True,timeout=8)
                    need(done.returncode==0 and not done.stderr,'private_backend_rebind_enqueue');last=token
            else:last=None
        except FileNotFoundError:pass # First startup: no mount receipt yet, no admission.
        except Exception as e:
            audit.failure(e,'delivery_generation');data['valid']=False
        atomic('ready.json',data)
        if not notified:notify('READY=1\nSTATUS=delivery generation watcher running');notified=True
        stop.wait(1)
    atomic('ready.json',dict(data,valid=False,observed_at=time.time()));return 0
def main():
    need(os.geteuid()==0 and sys.argv[1:]in (['--snapshot'],['--watch']),'coordination_fixed_command')
    if sys.argv[1]=='--snapshot':capture();return 0
    return watch()
if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as e:Audit().failure(e,'coordination');raise SystemExit(1)
