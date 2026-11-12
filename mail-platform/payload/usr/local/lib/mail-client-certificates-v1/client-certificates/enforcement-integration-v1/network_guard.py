"""Explicit private-network backend and inherited host listener adoption.

No listener/bind, unit start, credential reads, runtime arming or environment
fallback. Bootstrap must supply pinned host/private namespace descriptors and
the exact kernel-created listener inventory. Original Roundcube routes stay out.
"""
from dataclasses import dataclass
import ipaddress
import os
import re
import socket
import stat
import sys

PROTOCOLS=frozenset({'imaps','pop3s','submission'})


class NetworkBoundaryError(ValueError):
    def __init__(self,code,**details):self.code,self.details=code,details;super().__init__(code)


def need(value,code,**details):
    if value is not True:raise NetworkBoundaryError(code,**details)


def endpoint(value):
    need(type(value)in (tuple,list)and len(value)in (2,4)and type(value[0])is str
        and type(value[1])is int and 0<value[1]<=65535,'endpoint_shape')
    ip=ipaddress.ip_address(value[0]);need(not ip.is_unspecified and not ip.is_multicast and '%'not in value[0],'endpoint_scope')
    need(len(value)==2 or(ip.version==6 and tuple(value[2:])==(0,0)),'endpoint_ipv6_scope')
    return str(ip),value[1]


def namespace_identity(fd):
    need(sys.platform=='linux'and type(fd)is int and fd>2,'linux_namespace_descriptor')
    info=os.fstat(fd);name=os.readlink('/proc/self/fd/'+str(fd))
    need(stat.S_ISREG(info.st_mode)and re.fullmatch(r'net:\[[0-9]+\]',name)is not None,'network_namespace_descriptor_type')
    return info.st_dev,info.st_ino


@dataclass(frozen=True)
class NamespaceScope:
    host_fd:int
    private_fd:int
    runtime:object

    def verify(self):
        self.runtime.require_armed()
        need(self.host_fd!=self.private_fd,'namespace_descriptor_alias')
        host,private=namespace_identity(self.host_fd),namespace_identity(self.private_fd)
        need(host!=private,'host_namespace_not_isolated')
        # Socket creation is per-thread. Do not inspect only the process leader.
        fd=os.open('/proc/thread-self/ns/net',os.O_RDONLY|os.O_CLOEXEC)
        try:need(namespace_identity(fd)==private,'wrong_current_thread_namespace')
        finally:os.close(fd)
        return private


class NamespaceBackend:
    def __init__(self,scope,backends,external_routes):
        need(type(scope)is NamespaceScope and type(backends)is dict and set(backends)==PROTOCOLS
            and type(external_routes)is dict and bool(external_routes),'backend_inventory')
        self.scope=scope;self.backends={p:endpoint(v)for p,v in backends.items()}
        need(all(ipaddress.ip_address(v[0]).is_loopback for v in self.backends.values()),'backend_not_loopback')
        need(len(set(self.backends.values()))==3,'backend_endpoint_alias')
        self.routes={endpoint(k):v for k,v in external_routes.items()}
        need(set(self.routes.values())==PROTOCOLS and len(self.routes)==len(external_routes),'external_route_inventory')
        need(not(set(self.routes)&set(self.backends.values())),'external_backend_route_overlap')

    def open(self,protocol,identity,source,destination):
        self.scope.verify()  # Before creating a socket or copying protocol bytes.
        need(protocol in PROTOCOLS and self.routes.get(endpoint(destination))==protocol,'unreviewed_backend_route')
        endpoint(source)
        address=self.backends[protocol];family=socket.AF_INET6 if ipaddress.ip_address(address[0]).version==6 else socket.AF_INET
        channel=socket.socket(family,socket.SOCK_STREAM)
        try:
            channel.settimeout(5);channel.connect(address);self.scope.verify();return channel
        except Exception:channel.close();raise


def adopted_listeners(descriptors,expected,runtime):
    """Take ownership of explicit LISTEN_FDS, validated against sealed bootstrap data.

    No accept/bind or implicit fd3 fallback. Only the supplied descriptors are
    wrapped; all protocol labels come from bootstrap, never incoming requests.
    """
    runtime.require_armed()
    need(type(descriptors)is dict and type(expected)is dict and set(descriptors)==set(expected)==PROTOCOLS
        and all(type(fd)is int and fd>2 for fd in descriptors.values())and len(set(descriptors.values()))==3,'activation_descriptor_inventory')
    channels={};inodes=set()
    try:
        for protocol,fd in descriptors.items():
            info=os.fstat(fd);need(stat.S_ISSOCK(info.st_mode),'activation_descriptor_not_socket')
            identity=info.st_dev,info.st_ino;need(identity not in inodes,'activation_socket_inode_alias');inodes.add(identity)
            channel=socket.socket(fileno=fd);channels[protocol]=channel
            need(channel.family in {socket.AF_INET,socket.AF_INET6}
                and channel.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)==socket.SOCK_STREAM
                and channel.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN)==1,'activation_socket_kind')
            need(endpoint(channel.getsockname())==endpoint(expected[protocol]),'activation_listener_endpoint_mismatch')
            if channel.family==socket.AF_INET6:
                need(channel.getsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY)==1,'activation_dual_stack_denied')
            os.set_inheritable(fd,False)
        return channels
    except Exception:
        for channel in channels.values():channel.close()
        raise
