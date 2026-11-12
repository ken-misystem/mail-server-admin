"""Fixed Python CA/CRL worker, reused C READY/BOUND barrier, no generic exec RPC."""
import array
from hashlib import sha256
import json
import os
import socket
import struct
import subprocess
import threading
from child import recv_frame,release_after_ready,CONTROL,GUARD,EXECUTABLE
from guarded_php import checked_public_fd
from safety import need
from diagnostics import native_failure

class Task:
    def __init__(self,runtime,regions,exe,exe_pin,guard,guard_pin,source,source_pin):
        self.runtime,self.regions,self.exe,self.exe_pin,self.guard,self.guard_pin,self.source,self.source_pin=runtime,regions,exe,exe_pin,guard,guard_pin,source,source_pin
        self.lock=threading.Lock()
    def run(self,request,first,second,third):
        need(type(request)is dict and request.get('operation')in {'crl','ceremony','restore'},'secret_worker_fixed_operation')
        with self.lock:
            self.runtime.require_armed()
            for fd,pin in ((self.exe,self.exe_pin),(self.guard,self.guard_pin),(self.source,self.source_pin)):checked_public_fd(fd,pin)
            buffers=[];reserved=[];parent=child=process=thread=None;stderr=bytearray();overflow=threading.Event()
            try:
                def region(raw):
                    need(type(raw)is bytes and 0<len(raw)<=131068,'secret_task_frame_size')
                    value=self.regions.allocate(131072);buffers.append(value);value.write(struct.pack('!I',len(raw))+raw);return value
                payload=region(json.dumps(request,separators=(',',':')).encode())
                output=self.regions.allocate(131072);buffers.append(output)
                # Secret FDs are direct and bounded at the worker; no read at exec.
                need(all(type(fd)is int and fd>2 for fd in(first,second,third))and len({first,second,third})==3,'secret_task_input_fds')
                parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);parent.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
                import fcntl
                for n in (CONTROL,GUARD,EXECUTABLE):
                    try:os.fstat(n)
                    except OSError as e:need(e.errno==9,'secret_reserved_fd_check')
                    else:raise ValueError('secret_reserved_fd_busy')
                for fd,n in ((child.fileno(),CONTROL),(self.guard,GUARD),(self.exe,EXECUTABLE)):
                    actual=fcntl.fcntl(fd,fcntl.F_DUPFD_CLOEXEC,n)
                    if actual!=n:os.close(actual);raise ValueError('secret_reserved_fd_race')
                    reserved.append(actual)
                process=subprocess.Popen(['python3','-I','-S','-B','/proc/self/fd/7'],executable='/proc/self/fd/258',pass_fds=(CONTROL,GUARD,EXECUTABLE),
                    stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,close_fds=True,
                    env={'LANG':'C','LC_ALL':'C','OPENSSL_CONF':'/dev/null','LD_PRELOAD':'/proc/self/fd/257'})
                for fd in reserved:os.close(fd)
                reserved=[];child.close()
                def drain():
                    while True:
                        raw=process.stderr.read(4096)
                        if not raw:break
                        if len(stderr)+len(raw)>16384:overflow.set();process.kill();break
                        stderr.extend(raw)
                thread=threading.Thread(target=drain,daemon=True);thread.start();parent.settimeout(8)
                descriptors=(output.fd,payload.fd,first,second,third,self.source);targets=(1,3,4,5,6,7)
                release_after_ready(lambda:recv_frame(parent,process.pid,os.geteuid(),os.getegid()),
                    lambda raw,fds:parent.sendmsg([raw],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',fds))]),
                    self.runtime,descriptors,targets,process.pid,os.geteuid(),os.getegid())
                process.wait(timeout=90);thread.join(2)
                need(not thread.is_alive()and not overflow.is_set(),'secret_worker_diagnostic_bound')
                size=os.lseek(output.fd,0,os.SEEK_CUR)
                if not 0<size<=131072:
                    error=ValueError('secret_worker_output_size');error.details=native_failure(bytes(stderr),process.returncode);raise error
                result=json.loads(os.pread(output.fd,size,0));need(type(result)is dict and type(result.get('ok'))is bool,'secret_worker_output_shape')
                if not result['ok']:
                    e=ValueError('secret_worker_failed');e.details={'native_exit':process.returncode,'failure':result.get('failure'),'stderr_bytes':len(stderr),'stderr_sha256':sha256(stderr).hexdigest()};raise e
                need(process.returncode==0 and not stderr,'secret_worker_exit')
                protection=result.get('protection');need(type(protection)is dict and protection.get('locked_kib',0)>0
                    and protection.get('seccomp')==2 and protection.get('dumpable')==0 and protection.get('cap_eff')==0
                    and protection.get('no_new_privileges')==1,'secret_worker_protection')
                return result
            finally:
                if parent is not None:parent.close()
                if child is not None:child.close()
                for fd in reserved:os.close(fd)
                if process is not None:
                    if process.poll()is None:process.kill();process.wait(timeout=5)
                    if thread is not None:thread.join(2)
                    process.stderr.close()
                for value in reversed(buffers):value.retire()
