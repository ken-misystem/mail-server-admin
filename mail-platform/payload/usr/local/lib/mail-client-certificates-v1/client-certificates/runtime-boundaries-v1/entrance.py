"""Inert owner-policy/TLS assembly; no bind, connect, keys or service changes."""
import ipaddress
import socket
from types import MappingProxyType
from frozen import require, TLSGate, SessionBook, decide
from ipc import kernel_peer

PROTOCOLS = frozenset({'imaps', 'pop3s', 'submission'})


def endpoint(value):
    require(type(value) in (tuple, list) and len(value) in (2, 4)
            and type(value[0]) is str and type(value[1]) is int and 0 < value[1] <= 65535,
            'route_endpoint_shape', 'route')
    ip = ipaddress.ip_address(value[0])
    require(not ip.is_unspecified and not ip.is_multicast and '%' not in value[0],
            'route_endpoint_scope', 'route')
    # Scoped IPv6 is deliberately not supported by the current PROXY adapter.
    require(len(value) == 2 or (ip.version == 6 and value[2:] in ((0, 0), [0, 0])),
            'route_ipv6_scope', 'route')
    return str(ip), value[1]


class Routes:
    def __init__(self, entries, protected):
        require(type(entries) is dict and bool(entries) and type(protected) is frozenset and bool(protected),
                'route_manifest_required', 'route')
        denied = {endpoint(p) for p in protected}
        routes = {}
        for address, protocol in entries.items():
            key = endpoint(address)
            require(protocol in PROTOCOLS and key not in routes and key not in denied
                    and key[1] not in {25, 443}, 'route_scope_denied', 'route')
            routes[key] = protocol
        require(set(routes.values()) == PROTOCOLS, 'route_protocol_coverage', 'route')
        self.entries = MappingProxyType(routes)

    def protocol(self, channel):
        require(channel.family in {socket.AF_INET, socket.AF_INET6}
                and channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM,
                'route_socket_type', 'route')
        key = endpoint(channel.getsockname())
        require(key in self.entries, 'route_not_reviewed', 'route')
        require(ipaddress.ip_address(key[0]).version == (4 if channel.family == socket.AF_INET else 6),
                'route_family_mismatch', 'route')
        return self.entries[key]


class Entrance:
    """The policy and TLS gate share EXACTLY one in-process lease book/registry.

    runtime.require_armed must include native backend/PROXY/IPv4+IPv6 bypass,
    Roundcube separation, authzid/master/re-AUTH and revocation/drain proofs.
    There is no built-in production arming implementation or true default.
    """
    def __init__(self, runtime, readiness, routes, contexts, registry, backend, relay, clock, policy_uid, policy_gid):
        require(type(routes) is Routes, 'route_manifest_required', 'tls_entry')
        self.runtime, self.readiness, self.routes = runtime, readiness, routes
        self.sessions, self.registry = SessionBook(), registry
        self.gate = TLSGate(contexts, registry, self.sessions, backend, relay, clock)
        self.uid, self.gid, self.clock = policy_uid, policy_gid, clock

    def accepted(self, channel):
        try:
            self.runtime.require_armed()
            self.readiness.require_current('external_tls')
            protocol = self.routes.protocol(channel)  # Never chosen from client input.
            self.gate.accepted(channel, protocol)
        finally:
            channel.close()

    def policy(self, channel):
        try:
            self.runtime.require_armed()
            self.readiness.require_current('smtp_policy')
            kernel_peer(channel, self.uid, self.gid)
            deadline, raw = self.clock() + 5, bytearray()
            # Native Postfix policy is LF-terminated key=value, NOT JSON/owner IPC.
            while not raw.endswith(b'\n\n'):
                require(len(raw) < 32768 and self.clock() < deadline, 'policy_frame_bound', 'policy_entry')
                channel.settimeout(deadline - self.clock())
                byte = channel.recv(1)
                require(type(byte) is bytes and len(byte) == 1, 'policy_eof', 'policy_entry')
                raw.extend(byte)
            return decide(bytes(raw), self.sessions, self.registry, peer_verified=True)
        except Exception:
            return b'action=451 4.3.5 Device authorization unavailable\n\n'
        finally:
            channel.close()
