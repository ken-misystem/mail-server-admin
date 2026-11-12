"""Private Unix backend, bounded P12 stream and live-state relay candidates.

Endpoint paths, UIDs and expected parent metadata come from a future reviewed
manifest, not from browser input. No socket is created at import or by tests.
"""
import os
import select
import socket
import stat
import struct
import time
from core import require


def unix_peer(endpoint, expected_uid):
    require(endpoint.family == socket.AF_UNIX and hasattr(socket, "SO_PEERCRED"),
            "linux_private_peer_required", "private_peer")
    pid, uid, gid = struct.unpack("3i", endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    require(pid > 0 and uid == expected_uid, "private_peer_uid", "private_peer")


class UnixBackend:
    def __init__(self, endpoints, manifest_guard, runtime):
        self.endpoints, self.guard, self.runtime = endpoints, manifest_guard, runtime

    def open(self, protocol, identity, source, destination):
        self.runtime.require_armed()
        require(protocol in self.endpoints and protocol in {"imaps", "pop3s", "submission"},
                "backend_scope", "private_backend")
        path, expected_uid = self.endpoints[protocol]
        held = self.guard.open_socket_parent(path)
        try:
            # Guard must anchor no-follow directories and enforce root/daemon-only
            # ownership/modes. Connecting by anchored /proc FD avoids parent swap.
            self.guard.verify_leaf(held)
            endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                endpoint.settimeout(5)
                endpoint.connect(self.guard.anchored_socket_name(held))
                unix_peer(endpoint, expected_uid)
                self.guard.verify_leaf(held)
                return endpoint
            except Exception:
                endpoint.close(); raise
        finally:
            self.guard.close(held)


class P12Destination:
    def __init__(self, endpoint, expected_web_uid, clock=time.monotonic):
        unix_peer(endpoint, expected_web_uid)
        self.endpoint, self.clock = endpoint, clock

    def send_region(self, region, deadline):
        require(0 < region.length <= 131072 and self.clock() < deadline,
                "p12_bound_or_deadline", "p12_stream")
        # Encrypted P12 only. Private-key FD is NEVER an allowed stream source.
        self.endpoint.setblocking(False)
        offset = 0
        while offset < region.length:
            remaining = deadline - self.clock()
            require(remaining > 0, "p12_stream_timeout", "p12_stream")
            require(bool(select.select([], [self.endpoint], [], remaining)[1]), "p12_stream_timeout", "p12_stream")
            try: sent = os.sendfile(self.endpoint.fileno(), region.fd, offset, region.length-offset)
            except BlockingIOError: continue
            require(sent > 0, "p12_stream_eof", "p12_stream")
            offset += sent


def relay(client, backend, identity, registry, clock):
    """No body/header recording. DB failure closes, never last-good fallback.

    Nonblocking queues are bounded, so revocation checks do not wait behind a
    blocked send. The gate owns exactly these socket objects; no duplicated FDs.
    """
    client.setblocking(False); backend.setblocking(False)
    queues = {client: bytearray(), backend: bytearray()}
    counterpart = {client: backend, backend: client}
    check_at, last_io = clock(), clock()
    try:
        while True:
            now = clock()
            if now >= check_at:
                registry.require_active(identity)
                check_at = clock() + 5
            require(clock()-last_io < 1800, "relay_idle_deadline", "relay")
            reads = [s for s in queues if len(queues[counterpart[s]]) < 65536]
            writes = [s for s, data in queues.items() if data]
            readable, writable, _ = select.select(reads, writes, [], max(0, min(check_at-clock(), 1)))
            for endpoint in readable:
                try: data = endpoint.recv(16384)
                except (BlockingIOError, socket.timeout, __import__('ssl').SSLWantReadError, __import__('ssl').SSLWantWriteError): continue
                if not data: return
                queues[counterpart[endpoint]].extend(data)
                require(len(queues[counterpart[endpoint]]) <= 81920, "relay_queue_bound", "relay")
                last_io = clock()
            for endpoint in writable:
                try: sent = endpoint.send(queues[endpoint])
                except (BlockingIOError, socket.timeout, __import__('ssl').SSLWantReadError, __import__('ssl').SSLWantWriteError): continue
                require(sent > 0, "relay_write_eof", "relay")
                del queues[endpoint][:sent]
                last_io = clock()
    finally:
        for endpoint in (client, backend): endpoint.close()
