"""Dual-stack FD inventory -> existing TLS identity/lease/policy implementation.

All listeners are inherited explicitly. No bind, wildcard, native-host fallback,
runtime arming or certificate creation. Roundcube routes never enter this actor.
"""
import ipaddress
import socket
from topology import Inventory,PrivateBackend
from network_guard import NamespaceScope,endpoint,need
from tls_gate import TLSGate,SessionBook
from gateway_policy import decide
from control import serve_policy


class Entrance:
    def __init__(self,*,runtime,readiness,scope,inventory,backends,policy_endpoint,contexts,registry,relay,clock,audit):
        need(type(scope)is NamespaceScope and scope.runtime is runtime and type(inventory)is Inventory,'entrance_runtime_scope')
        self.runtime,self.readiness,self.scope,self.inventory=runtime,readiness,scope,inventory
        self.clock,self.audit,self.registry=clock,audit,registry
        self.policy_endpoint=endpoint(policy_endpoint)
        need(ipaddress.ip_address(self.policy_endpoint[0]).is_loopback
            and self.policy_endpoint not in inventory.addresses and self.policy_endpoint not in {endpoint(v)for v in backends.values()},'entrance_private_policy_endpoint')
        self.sessions=SessionBook();self.backend=PrivateBackend(scope,inventory,backends)
        self.gate=TLSGate(contexts,registry,self.sessions,self.backend,relay,clock)
        self.listeners=None
    def adopt(self,environment=None):
        need(self.listeners is None,'entrance_already_adopted');self.scope.verify()
        self.readiness.require_current('external_certificate_routes')
        self.listeners=self.inventory.acquire(self.runtime,environment)
        return dict(self.listeners)
    def accepted(self,label,channel):
        try:
            self.runtime.require_armed();self.scope.verify();self.readiness.require_current('external_certificate_routes')
            need(self.listeners is not None and label in self.listeners,'entrance_unadopted_listener')
            with self.inventory.admitted(label,channel)as protocol:self.gate.accepted(channel,protocol)
        finally:channel.close()
    def policy_peer(self,channel):
        self.scope.verify()
        need(channel.family in {socket.AF_INET,socket.AF_INET6}
            and channel.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)==socket.SOCK_STREAM
            and endpoint(channel.getsockname())==self.policy_endpoint
            and ipaddress.ip_address(endpoint(channel.getpeername())[0]).is_loopback,'entrance_policy_realm')
    def policy(self,channel):
        return serve_policy(channel,self.runtime,self.readiness,self.policy_peer,decide,
            self.sessions,self.registry,self.audit,self.clock)
