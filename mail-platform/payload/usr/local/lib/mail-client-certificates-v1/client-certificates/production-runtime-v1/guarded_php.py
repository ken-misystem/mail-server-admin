"""Fixed PHP verifier child using the already-validated post-exec FD barrier.

    No SQL credentials, secret FD, payload or output region is inherited at
    exec. The original C guard forbids network, fork/exec, UID changes and dump
    re-enabling, and locks all present/future heap pages before FD handoff.
"""
import array
import base64
from hashlib import sha256
import json
import os
import socket
import stat
import struct
import subprocess
import threading
import time
from child import recv_frame,release_after_ready,CONTROL,GUARD,EXECUTABLE


def need(value,code):
    if value is not True:raise ValueError(code)


def checked_public_fd(fd,expected):
    before=os.fstat(fd)
    need(stat.S_ISREG(before.st_mode)and before.st_uid==0 and before.st_nlink==1
        and before.st_mode&0o6022==0 and 0<before.st_size<=33554432,'php_public_metadata')
    digest=sha256();position=0
    while position<before.st_size:
        raw=os.pread(fd,min(65536,before.st_size-position),position);need(bool(raw),'php_public_short_read');position+=len(raw);digest.update(raw)
    identity=lambda info:tuple(getattr(info,k)for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
    need(digest.hexdigest()==expected and identity(os.fstat(fd))==identity(before),'php_public_pin_or_drift')


class GuardedPHP:
    def __init__(self,runtime,regions,executable_fd,executable_pin,guard_fd,guard_pin,source_fd,source_pin,extensions):
        need(type(extensions)is tuple and len(extensions)<=8 and all(type(v)is str and v.startswith('/usr/lib/php/')and v.endswith('.so')and '..'not in v.split('/')for v in extensions),'php_extension_profile')
        self.runtime,self.regions=runtime,regions;self.exe,self.exe_pin=executable_fd,executable_pin
        self.guard,self.guard_pin,self.source,self.source_pin=guard_fd,guard_pin,source_fd,source_pin
        self.extensions,self.lock=extensions,threading.Lock()

    def run(self,request,options='{}',record='{}',metadata=None):
        with self.lock:
            self.runtime.require_armed()
            for fd,pin in ((self.exe,self.exe_pin),(self.guard,self.guard_pin),(self.source,self.source_pin)):checked_public_fd(fd,pin)
            buffers=[];reserved=[];parent=None;child=None;process=None;thread=None;stderr=bytearray();overflow=threading.Event()
            try:
                def region(raw,capacity):
                    need(type(raw)is bytes and 0<len(raw)<=capacity-4,'php_region_input_bound')
                    item=self.regions.allocate(capacity);buffers.append(item);item.write(struct.pack('!I',len(raw))+raw);return item
                request_region=region(json.dumps(request,separators=(',',':'),ensure_ascii=True).encode(),131072)
                options_region=region(options.encode(),131072)
                record_bytes=record.encode();need(0<len(record_bytes)<=131072,'php_record_input_bound')
                record_region=self.regions.allocate(131072);buffers.append(record_region);record_region.write(record_bytes)
                metadata_region=region(json.dumps(dict(metadata or{},record_length=len(record_bytes)),separators=(',',':')).encode(),8192)
                output=self.regions.allocate(131072);buffers.append(output);record_output=self.regions.allocate(131072);buffers.append(record_output)
                parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);parent.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
                import fcntl
                for number in (CONTROL,GUARD,EXECUTABLE):
                    try:os.fstat(number)
                    except OSError as error:need(error.errno==9,'php_reserved_fd_check')
                    else:raise ValueError('php_reserved_fd_busy')
                for fd,number in ((child.fileno(),CONTROL),(self.guard,GUARD),(self.exe,EXECUTABLE)):
                    actual=fcntl.fcntl(fd,fcntl.F_DUPFD_CLOEXEC,number)
                    if actual!=number:os.close(actual);raise ValueError('php_reserved_fd_race')
                    reserved.append(actual)
                arguments=['php','-n','-d','display_errors=stderr','-d','log_errors=Off','-d','ffi.enable=false']
                for extension in self.extensions:arguments+=['-d','extension='+extension]
                arguments+=['/proc/self/fd/7']
                process=subprocess.Popen(arguments,executable='/proc/self/fd/258',pass_fds=(CONTROL,GUARD,EXECUTABLE),
                    close_fds=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,
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
                descriptors=(output.fd,request_region.fd,options_region.fd,record_region.fd,metadata_region.fd,self.source,record_output.fd)
                targets=(1,3,4,5,6,7,8)
                release_after_ready(lambda:recv_frame(parent,process.pid,os.geteuid(),os.getegid()),
                    lambda data,fds:parent.sendmsg([data],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',fds))]),
                    self.runtime,descriptors,targets,process.pid,os.geteuid(),os.getegid())
                process.wait(timeout=45);thread.join(2)
                need(not thread.is_alive()and not overflow.is_set(),'php_child_diagnostic_bound')
                size=os.lseek(output.fd,0,os.SEEK_CUR);need(0<size<=131072,'php_child_output_size')
                result=json.loads(os.pread(output.fd,size,0));need(type(result)is dict and type(result.get('ok'))is bool,'php_child_result_shape')
                if not result['ok']:
                    error=ValueError('php_signature_worker_failed');error.details={'exit':process.returncode,'worker':result,'stderr_bytes':len(stderr)};raise error
                need(process.returncode==0 and not stderr,'php_child_exit_or_stderr')
                if request['operation']=='verify':
                    size=os.lseek(record_output.fd,0,os.SEEK_CUR)
                    need(type(result.get('record_length'))is int and size==result['record_length']and 0<size<=131072,'php_child_record_size')
                    result['record']=os.pread(record_output.fd,size,0).decode('utf-8','strict')
                return result
            finally:
                if parent is not None:parent.close()
                if child is not None:child.close()
                for fd in reserved:os.close(fd)
                if process is not None:
                    if process.poll()is None:process.kill();process.wait(timeout=5)
                    if thread is not None:thread.join(2)
                    process.stderr.close()
                failed=False
                for item in reversed(buffers):
                    try:item.retire()
                    except Exception:failed=True
                if failed:raise ValueError('php_region_retirement_failed')

    def options(self,descriptors):
        result=self.run({'operation':'options','descriptors':descriptors})
        need(set(result)=={'ok','options'}and type(result['options'])is dict,'php_options_result')
        return json.dumps(result['options'],separators=(',',':'),ensure_ascii=True)

    def verify(self,response,options,credential,handle,record,expected):
        result=self.run({'operation':'verify','assertion':json.loads(response)},options,record,
            {'credential_id':base64.b64encode(credential).decode(),'user_handle':base64.b64encode(handle).decode(),'expected_handle':base64.b64encode(expected).decode()})
        need(set(result)=={'ok','credential_id','user_handle','sign_count','record_length','record'},'php_verification_result')
        return {'credential_id':base64.b64decode(result['credential_id'],validate=True),'user_handle':base64.b64decode(result['user_handle'],validate=True),
            'sign_count':result['sign_count'],'record':result['record']}
