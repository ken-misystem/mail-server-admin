"""Concrete-address dual-stack inventory and kernel-bound per-connection routing.

Never bind a host wildcard: loopback SMTP/Roundcube routes must remain separate.
No listener, namespace change, TLS operation or arming occurs on construction.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import ipaddress
import os
import socket
import stat
from network_guard import NamespaceScope,endpoint,need

PORTS={'imaps':993,'pop3s':995,'submission':587}


@dataclass(frozen=True)
class Listener:
    name:str
    protocol:str
    address:tuple


class Inventory:
    def __init__(self,entries):
        need(type(entries)is tuple and 3<=len(entries)<=48,'listener_inventory_size')
        self.entries={};self.addresses={}
        for entry in entries:
            need(type(entry)is Listener and type(entry.name)is str and entry.name.isascii()
                and entry.name.replace('_','').isalnum()and len(entry.name)<=64
                and entry.name not in self.entries and entry.protocol in PORTS,'listener_entry')
            address=endpoint(entry.address)
            need(address not in self.addresses,'listener_address_alias')
            self.entries[entry.name]=entry;self.addresses[address]=entry.name
        need({v.protocol for v in entries}==set(PORTS),'listener_protocol_coverage')
        self.frame=ContextVar('certificate_kernel_admission',default=None)

    def require_production(self,public_addresses):
        need(type(public_addresses)is frozenset and bool(public_addresses),'explicit_public_addresses')
        canonical={str(ipaddress.ip_address(v))for v in public_addresses}
        need(canonical==set(public_addresses)and all(ipaddress.ip_address(v).is_global for v in canonical),'global_public_addresses_only')
        expected={(ip,port)for ip in canonical for port in PORTS.values()}
        need(set(self.addresses)==expected and all(endpoint(v.address)[1]==PORTS[v.protocol]for v in self.entries.values()),'complete_production_listener_inventory')
        return self

    def acquire(self,runtime,environment=None):
        runtime.require_armed();env=os.environ if environment is None else environment
        need(env.get('LISTEN_PID')==str(os.getpid())and env.get('LISTEN_FDS')==str(len(self.entries)),'activation_pid_count')
        owned={};inodes=set()
        try:
            for fd in range(3,3+len(self.entries)):
                info=os.fstat(fd);need(stat.S_ISSOCK(info.st_mode),'activation_not_socket')
                identity=info.st_dev,info.st_ino;need(identity not in inodes,'activation_inode_alias');inodes.add(identity)
                channel=socket.socket(fileno=fd)
                # Own every wrapped descriptor even if a later check fails.
                owned[fd]=channel
                need(channel.family in {socket.AF_INET,socket.AF_INET6}
                    and channel.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)==socket.SOCK_STREAM
                    and channel.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN)==1,'activation_socket_profile')
                address=endpoint(channel.getsockname());need(address in self.addresses,'activation_unknown_endpoint')
                if channel.family==socket.AF_INET6:need(channel.getsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY)==1,'activation_dual_stack_alias')
                os.set_inheritable(fd,False)
            result={self.addresses[endpoint(c.getsockname())]:c for c in owned.values()}
            need(set(result)==set(self.entries),'activation_missing_endpoint')
            for key in ('LISTEN_PID','LISTEN_FDS','LISTEN_FDNAMES'):env.pop(key,None)
            return result
        except BaseException:
            for channel in owned.values():channel.close()
            raise

    @contextmanager
    def admitted(self,label,channel):
        need(label in self.entries and self.frame.get()is None,'admission_scope')
        entry=self.entries[label];info=os.fstat(channel.fileno())
        need(stat.S_ISSOCK(info.st_mode)and endpoint(channel.getsockname())==endpoint(entry.address),'admission_kernel_destination')
        value={'protocol':entry.protocol,'source':endpoint(channel.getpeername()),'destination':endpoint(channel.getsockname()),
            'fd':channel.fileno(),'inode':(info.st_dev,info.st_ino)}
        token=self.frame.set(value)
        try:yield entry.protocol
        finally:self.frame.reset(token)

    def current(self,protocol,source,destination):
        value=self.frame.get();need(value is not None,'admission_missing')
        need((protocol,endpoint(source),endpoint(destination))==(value['protocol'],value['source'],value['destination']),'admission_tuple_mismatch')
        info=os.fstat(value['fd']);need(stat.S_ISSOCK(info.st_mode)and(info.st_dev,info.st_ino)==value['inode'],'admission_descriptor_replaced')
        return value


class PrivateBackend:
    def __init__(self,scope,inventory,backends):
        need(type(scope)is NamespaceScope and type(inventory)is Inventory and type(backends)is dict and set(backends)==set(PORTS),'private_backend_inventory')
        self.scope,self.inventory=scope,inventory;self.addresses={p:endpoint(v)for p,v in backends.items()}
        need(all(ipaddress.ip_address(v[0]).is_loopback for v in self.addresses.values())and len(set(self.addresses.values()))==3,'private_backend_endpoints')
        need(not(set(self.addresses.values())&set(inventory.addresses)),'private_public_endpoint_alias')

    def open(self,protocol,identity,source,destination):
        self.scope.verify();self.inventory.current(protocol,source,destination)
        need(protocol in self.addresses,'private_backend_protocol')
        address=self.addresses[protocol];channel=socket.socket(socket.AF_INET6 if ':'in address[0]else socket.AF_INET,socket.SOCK_STREAM)
        try:
            channel.settimeout(5);channel.connect(address);self.scope.verify();self.inventory.current(protocol,source,destination);return channel
        except BaseException:channel.close();raise
