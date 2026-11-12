"""Host delivery IPC bind mounts: exact sockets, no host TCP or whole queue mount."""
from dataclasses import dataclass
import os
from pathlib import PurePosixPath
import socket
import stat
import struct


def need(value,code):
    if value is not True:raise ValueError(code)


HOST={'cleanup':'/var/spool/postfix/public/cleanup','rewrite':'/var/spool/postfix/private/rewrite','auth':'/var/spool/postfix/private/auth'}
DEST={'cleanup':'public/cleanup','rewrite':'private/rewrite','auth':'private/auth'}


@dataclass(frozen=True)
class SocketPin:
    device:int
    inode:int
    uid:int
    gid:int
    mode:int


def pin(info):
    need(stat.S_ISSOCK(info.st_mode)and info.st_nlink==1,'ipc_socket_type')
    return SocketPin(info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))


class DeliveryPlan:
    def __init__(self,queue,identities):
        need(type(queue)is str and queue.startswith('/run/mail-client-certificates-v1/')
            and str(PurePosixPath(queue))==queue and '..'not in queue.split('/'),'dedicated_queue_root')
        need(type(identities)is dict and set(identities)=={'postfix_uid','postfix_gid','postdrop_gid'}
            and all(type(v)is int and v>0 for v in identities.values()),'delivery_identities')
        self.queue,self.identities=queue,dict(identities)

    def mounts(self):
        return tuple((HOST[k],self.queue+'/'+DEST[k])for k in ('cleanup','rewrite','auth'))

    def master(self):
        # Dedicated smtpd can run in single-connection (-S) mode. Its rewrite,
        # cleanup and SASL IPC endpoints refer to the existing mail stack.
        return '# No qmgr, pickup, cleanup, local, smtp, lmtp or delivery daemon here.\n'

    def require_metadata(self,observations):
        need(type(observations)is dict and set(observations)==set(HOST),'delivery_socket_inventory')
        for value in observations.values():
            need(type(value)is SocketPin and value.uid==self.identities['postfix_uid']
                and value.gid==self.identities['postfix_gid']and value.mode in {0o660,0o666},'delivery_socket_metadata')


class MountedIPC:
    """Keep an O_PATH inode reference across connect and verify kernel peer.

    The systemd bind mount is established by trusted startup and is read-only.
    Parent directories must be root-owned and not writable by service actors.
    """
    def __init__(self,path,expected,peer,runtime,parent_guard):
        need(type(path)is str and type(expected)is SocketPin and type(peer)is tuple and len(peer)==3
            and all(type(v)is int and v>=0 for v in peer)and peer[0]>0,'mounted_ipc_contract')
        self.path,self.expected,self.peer=path,expected,peer
        self.runtime,self.parent_guard=runtime,parent_guard

    def open(self):
        self.runtime.require_armed();self.parent_guard();descriptor=None;channel=None
        try:
            descriptor=os.open(self.path,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
            need(pin(os.fstat(descriptor))==self.expected,'mounted_ipc_inode')
            channel=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);channel.settimeout(5);channel.connect(self.path)
            need(struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))==self.peer,'mounted_ipc_peer')
            self.parent_guard();need(pin(os.stat(self.path,follow_symlinks=False))==self.expected==pin(os.fstat(descriptor)),'mounted_ipc_drift')
            result=channel;channel=None;return result
        finally:
            if descriptor is not None:os.close(descriptor)
            if channel is not None:channel.close()
