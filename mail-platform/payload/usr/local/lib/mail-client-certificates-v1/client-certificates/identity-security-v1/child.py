"""Uninstalled replacement runner: existing OpenSSL plan + post-exec FD barrier.

No native calls on import or local validation. Never pass secrets through exec's
pass_fds, argv, environment, stdin or stdout before guarded SCM_RIGHTS handoff.
Linux compilation/pinned shared dependencies/constructor order/real protections
remain native gates. This candidate has NOT been deployed or used with keys.
"""
import array
from hashlib import sha256
import os
import re
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from identity import require, AdapterError

CONTROL, GUARD, EXECUTABLE = 256, 257, 258
STAGES = {1:"bootstrap_identity",2:"harden_process",3:"lock_memory_seccomp",
          4:"ready_send",5:"fd_receive",6:"fd_install",7:"binding_ack"}


def verify_ready(payload, credentials, pid, uid, gid):
    require(credentials == (pid,uid,gid), "child_credentials", "child_ready")
    if len(payload)==3 and payload[:1]==b"E":
        raise AdapterError("child_guard_failed", phase=STAGES.get(payload[1],"unknown_child_stage"),
                           details={"guard_stage":payload[1],"errno":payload[2],"raw_saved":False})
    require(payload == b"READY1", "child_ready_frame", "child_ready")


def rights_packet(targets):
    require(type(targets) is tuple and 1<=len(targets)<=16 and len(set(targets))==len(targets)
            and all(type(n) is int and (n==1 or 3<=n<200) for n in targets),
            "child_descriptor_scope", "child_handoff")
    return bytes([len(targets)]) + b"".join(struct.pack("!H",n) for n in targets)


def checked_public_fd(fd, expected):
    st=os.fstat(fd)
    require(stat.S_ISREG(st.st_mode) and st.st_uid==0 and st.st_mode&0o6022==0
            and 0<st.st_size<=32*1024*1024, "child_public_metadata", "child_launch")
    digest=sha256(); pos=0
    while pos<st.st_size:
        data=os.pread(fd,min(65536,st.st_size-pos),pos)
        require(bool(data),"child_public_short_read","child_launch")
        digest.update(data);pos+=len(data)
    require(digest.hexdigest()==expected and os.fstat(fd)==st,
            "child_public_pin", "child_launch")
    return st


def recv_frame(endpoint,pid,uid,gid):
    payload, ancillary, flags, _ = endpoint.recvmsg(32,socket.CMSG_SPACE(struct.calcsize("3i")))
    require(flags==0 and len(ancillary)==1 and ancillary[0][:2]==(socket.SOL_SOCKET,socket.SCM_CREDENTIALS)
            and len(ancillary[0][2])==struct.calcsize("3i"), "child_credential_frame", "child_ready")
    credentials=struct.unpack("3i",ancillary[0][2])
    require(credentials==(pid,uid,gid),"child_credentials","child_ready")
    return payload,credentials


def release_after_ready(receive, send_rights, runtime, fds, targets, pid, uid, gid, rewind=os.lseek):
    """No FD release before verified post-exec hardening, including failure paths.

    Transport ports are private runner functions, never request-body callables.
    The narrow seam permits local state-machine tests without Linux syscalls.
    """
    packet=rights_packet(targets)
    require(type(fds) is tuple and len(fds)==len(targets),"child_descriptor_scope","child_handoff")
    payload,credentials=receive()
    verify_ready(payload,credentials,pid,uid,gid)
    runtime.require_armed()
    for fd in fds: rewind(fd,0,os.SEEK_SET)
    require(send_rights(packet,fds)==len(packet),"child_handoff_short_write","child_handoff")
    payload,credentials=receive()
    require(credentials==(pid,uid,gid) and payload==b"BOUND1","child_binding_ack","child_handoff")


class GuardedOpenSSL:
    """Construct with held root-owned pinned FD/binary manifest, never Web input.

    Own broker must supply only unchanged broker.plan Command objects. Do not
    expose this object as an arbitrary command RPC. Child receives a fresh FD for
    every input/output; parent runtime and locked regions remain mandatory.
    """
    def __init__(self, executable_fd, executable_pin, guard_fd, guard_pin, runtime):
        self.exe,self.exe_pin,self.guard,self.guard_pin,self.runtime=(
            executable_fd,executable_pin,guard_fd,guard_pin,runtime)

    def run(self,command,regions):
        require(sys.platform=="linux" and hasattr(socket,"SCM_RIGHTS")
                and hasattr(socket,"SCM_CREDENTIALS"),"linux_child_required","child_launch")
        self.runtime.require_armed()
        from broker import Command
        require(type(command) is Command and command.phase in {"key_generation","csr","sign","p12"}
                and command.argv[0]=="openssl" and all(type(v) is str for v in command.argv),
                "fixed_command_plan_required","child_launch")
        target=next((r for r in regions if r.fd==command.output_fd),None)
        require(target is not None,"output_descriptor","child_launch")
        require(all(type(n) is int and 3<=n<200 for n in command.pass_fds)
                and len(set(command.pass_fds))==len(command.pass_fds)
                and command.output_fd not in command.pass_fds,
                "child_descriptor_scope","child_launch")
        targets=(1,)+command.pass_fds
        packet=rights_packet(targets)
        checked_public_fd(self.exe,self.exe_pin);checked_public_fd(self.guard,self.guard_pin)
        parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        parent.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
        process=None;reserved=[];thread=None
        try:
            import fcntl
            # Reserve exact public/control FDs atomically in a dedicated SINGLE
            # launch owner. Refuse collision; never overwrite an unknown FD.
            for number in (CONTROL,GUARD,EXECUTABLE):
                try: os.fstat(number)
                except OSError as error:
                    require(error.errno==9,"reserved_fd_check","child_launch")
                else: raise AdapterError("reserved_fd_busy",phase="child_launch")
            for source,number in ((child.fileno(),CONTROL),(self.guard,GUARD),(self.exe,EXECUTABLE)):
                actual=fcntl.fcntl(source,fcntl.F_DUPFD_CLOEXEC,number)
                if actual!=number:
                    os.close(actual)
                    raise AdapterError("reserved_fd_race",phase="child_launch")
                reserved.append(actual)
            process=subprocess.Popen(command.argv,executable="/proc/self/fd/258",
                pass_fds=(CONTROL,GUARD,EXECUTABLE),close_fds=True,
                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,
                env={"LANG":"C","LC_ALL":"C","OPENSSL_CONF":"/dev/null",
                     "LD_PRELOAD":"/proc/self/fd/257"})
            for n in reserved: os.close(n)
            reserved.clear();child.close()
            counts={"stderr_bytes":0,"overflow":False,"markers":set(),"codes":set()}
            def drain():
                tail=b""
                while True:
                    chunk=process.stderr.read(4096)
                    if not chunk: return
                    counts["stderr_bytes"]+=len(chunk);window=tail+chunk
                    counts["codes"].update(x.decode().lower() for x in re.findall(rb"error:([0-9A-Fa-f]{8,16}):",window))
                    for name,needle in (("bad_decrypt",b"bad decrypt"),("unsupported",b"unsupported"),
                                        ("permission_denied",b"Permission denied"),("memory",b"memory")):
                        if needle in window: counts["markers"].add(name)
                    tail=window[-128:]
                    if counts["stderr_bytes"]>32768:
                        counts["overflow"]=True;process.kill();return
            thread=threading.Thread(target=drain,daemon=True);thread.start()
            deadline=time.monotonic()+45
            parent.settimeout(5)
            # No key/P12/password/output FD was inherited by the child at exec.
            fds=(command.output_fd,)+command.pass_fds
            release_after_ready(lambda:recv_frame(parent,process.pid,os.geteuid(),os.getegid()),
                lambda data,handles:parent.sendmsg([data],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array("i",handles))]),
                self.runtime,fds,targets,process.pid,os.geteuid(),os.getegid())
            process.wait(timeout=max(0.01,deadline-time.monotonic()))
            thread.join(timeout=2)
            require(not thread.is_alive(),"child_stderr_unverified",command.phase)
            if process.returncode!=0 or counts["overflow"]:
                raise AdapterError("guarded_native_failed",phase=command.phase,native_exit=process.returncode,
                    details={"stderr_bytes":counts["stderr_bytes"],"overflow":counts["overflow"],
                             "openssl_error_codes":sorted(counts["codes"])[:16],
                             "reason_markers":sorted(counts["markers"]),"raw_saved":False})
            target.length=os.lseek(target.fd,0,os.SEEK_CUR)
            require(0<target.length<=target.capacity,"native_output_size",command.phase)
            os.lseek(target.fd,0,os.SEEK_SET)
        except (socket.timeout,subprocess.TimeoutExpired):
            raise AdapterError("guarded_child_timeout",phase=command.phase,
                               native_exit=process.poll() if process else None) from None
        finally:
            parent.close();child.close()
            for n in reserved: os.close(n)
            if process is not None:
                if process.poll() is None: process.kill();process.wait(timeout=5)
                if thread is not None: thread.join(timeout=2)
                process.stderr.close()
