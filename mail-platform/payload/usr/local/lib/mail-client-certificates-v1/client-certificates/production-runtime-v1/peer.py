"""Kernel-bound IPC clients and exact PHP-FPM cgroup admission.

No UID-only session assertion and no long-lived signing secret in FPM. A pidfd
obtained from the connected socket pins the peer through the request. Unsupported
SO_PEERPIDFD is a readiness failure, never a weaker authentication fallback.
"""
from contextlib import contextmanager
import os
import re
import select
import socket
import stat
import struct


def need(value,code):
    if value is not True:raise ValueError(code)


def identity(channel):
    need(channel.family==socket.AF_UNIX and channel.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)==socket.SOCK_STREAM,'unix_peer_profile')
    return struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))


class CgroupPeer:
    def __init__(self,uid,gid,cgroup):
        need(type(uid)is int and uid>0 and type(gid)is int and gid>0 and type(cgroup)is str
            and re.fullmatch(r'/[A-Za-z0-9_.:/@\\-]{1,512}',cgroup)is not None and '..'not in cgroup.split('/'),'fpm_cgroup_contract')
        self.uid,self.gid,self.cgroup=uid,gid,cgroup

    @contextmanager
    def hold(self,channel):
        pid,uid,gid=identity(channel);need(pid>0 and(uid,gid)==(self.uid,self.gid),'fpm_peer_identity')
        # Linux UAPI SO_PEERPIDFD=77 since Linux 6.5. No pidfd_open(pid) race.
        descriptor=channel.getsockopt(socket.SOL_SOCKET,getattr(socket,'SO_PEERPIDFD',77))
        need(type(descriptor)is int and descriptor>=0,'fpm_peer_pidfd')
        os.set_inheritable(descriptor,False)
        held=[]
        try:
            poll=select.poll();poll.register(descriptor,select.POLLIN|select.POLLHUP|select.POLLERR)
            def alive():need(poll.poll(0)==[],'fpm_peer_exited')
            alive()
            info=open('/proc/self/fdinfo/'+str(descriptor),encoding='ascii').read(4097)
            pids=re.findall(r'^Pid:\s*([0-9]+)$',info,re.M);need(len(info)<=4096 and pids==[str(pid)],'fpm_peer_pidfd_identity')
            # Exact root-controlled cgroup, not a prefix or descendant match.
            fd=os.open('/sys/fs/cgroup',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);held.append(fd)
            for name in self.cgroup.strip('/').split('/'):
                fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);held.append(fd)
                entry=os.fstat(fd);need(entry.st_uid==0 and entry.st_mode&0o022==0,'fpm_cgroup_ownership')
            proc=os.open('/proc/'+str(pid),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);held.append(proc)
            source=os.open('cgroup',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=proc);held.append(source)
            raw=os.read(source,8193);need(len(raw)<=8192 and raw==('0::'+self.cgroup+'\n').encode(),'fpm_cgroup_mismatch')
            alive();need(identity(channel)==(pid,uid,gid),'fpm_peer_changed')
            yield alive
            alive()
        finally:
            for fd in reversed(held):os.close(fd)
            os.close(descriptor)


class GreetedFactory:
    """Authenticate the sending actor, including PID-1-created socket listeners."""
    def __init__(self,path,uid,gid,parent_guard,runtime):
        need(type(uid)is int and uid>0 and type(gid)is int and gid>0,'greeted_expected_peer')
        self.path,self.uid,self.gid,self.parent_guard,self.runtime=path,uid,gid,parent_guard,runtime
    def require_current(self):self.runtime.require_armed();self.parent_guard()
    def open(self):
        self.require_current();channel=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            channel.settimeout(5);channel.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1);channel.connect(self.path)
            raw,ancillary,flags,_=channel.recvmsg(1,socket.CMSG_SPACE(12))
            need(raw==b'P' and flags==0 and len(ancillary)==1,'greeted_frame')
            level,kind,payload=ancillary[0];need((level,kind)==(socket.SOL_SOCKET,socket.SCM_CREDENTIALS)and len(payload)==12,'greeted_kernel_credentials')
            pid,uid,gid=struct.unpack('3i',payload);need(pid>0 and(uid,gid)==(self.uid,self.gid),'greeted_actor_identity')
            channel.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,0);self.require_current();return channel
        except BaseException:channel.close();raise


def broker_client(runtime,factory,clock):
    from broker_wire import BrokerWireClient
    class GreetedBrokerClient(BrokerWireClient):
        def open(self):
            self.require_peer();return self.factory.open()
    need(type(factory)is GreetedFactory,'greeted_factory_required')
    return GreetedBrokerClient(runtime,factory,factory.uid,factory.gid,clock)
