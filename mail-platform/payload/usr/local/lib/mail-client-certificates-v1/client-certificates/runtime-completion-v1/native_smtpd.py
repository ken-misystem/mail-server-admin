"""Dedicated mail_owner smtpd -S supervisor; fixed loopback and no queue manager."""
from pathlib import Path
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from hashlib import sha256
import json
import os
import signal
import socket
import subprocess
import threading
from safety import need,held,Audit
from diagnostics import native_failure
def main():
    from boot import notify
    config=json.loads(held('/etc/mail-client-certificates-v1/smtpd.json'));need(os.geteuid()==config['postfix_uid']and os.getegid()==config['postfix_gid'],'smtpd_actor_identity')
    for name,pin in config['pins'].items():need(sha256(held(config['configuration']+'/'+name,262144)).hexdigest()==pin,'smtpd_configuration_drift')
    need(sha256(held('/usr/lib/postfix/sbin/smtpd',2097152)).hexdigest()==config['binary_sha256'],'smtpd_binary_drift')
    from coordination import RUN
    mounted=json.loads(held(str(RUN/'coordination/mounted.json'),8192));fd=os.open('/proc/thread-self/ns/net',os.O_RDONLY|os.O_CLOEXEC)
    try:info=os.fstat(fd);need(mounted['private_namespace']==[info.st_dev,info.st_ino],'smtpd_namespace')
    finally:os.close(fd)
    stop=threading.Event();signal.signal(signal.SIGTERM,lambda *_:stop.set());slots=threading.BoundedSemaphore(64);children=[];lock=threading.Lock();audit=Audit()
    listener=socket.socket();listener.bind(('127.0.0.1',15870));listener.listen(64);listener.settimeout(.25)
    def serve(channel):
        child=None;diagnostic=bytearray();overflow=threading.Event();reader=None
        try:
            # -d means foreground, not verbose; -D/-v/-V are deliberately absent.
            child=subprocess.Popen(['/usr/lib/postfix/sbin/smtpd','-S','-d'],stdin=channel,stdout=channel,stderr=subprocess.PIPE,close_fds=True,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C','MAIL_CONFIG':config['configuration']})
            def drain():
                while True:
                    raw=child.stderr.read(4096)
                    if not raw:break
                    if len(diagnostic)+len(raw)>16384:overflow.set();child.kill();break
                    diagnostic.extend(raw)
            reader=threading.Thread(target=drain,daemon=True);reader.start()
            with lock:children.append(child)
            child.wait()
            reader.join(3)
            if child.returncode or overflow.is_set()or reader.is_alive():
                error=ValueError('private_smtpd_child_failed');error.details=native_failure(bytes(diagnostic),child.returncode)
                error.details['diagnostic_overflow']=overflow.is_set();audit.failure(error,'native_smtpd')
        except Exception as e:audit.failure(e,'native_smtpd')
        finally:
            if child is not None:
                if child.poll()is None:child.kill();child.wait(timeout=5)
                if reader is not None:reader.join(3)
                child.stderr.close()
            channel.close();slots.release()
            with lock:
                if child in children:children.remove(child)
    notify('READY=1\nSTATUS=private standalone smtpd listener ready')
    try:
        while not stop.is_set():
            try:channel,_=listener.accept()
            except socket.timeout:continue
            if not slots.acquire(False):channel.close();continue
            threading.Thread(target=serve,args=(channel,),daemon=True).start()
    finally:
        listener.close()
        with lock:
            for child in children:
                if child.poll()is None:child.terminate()
    return 0
if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as e:Audit().failure(e,'smtpd_startup');raise SystemExit(1)
