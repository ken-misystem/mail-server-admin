"""One-request Unix STREAM IPC adapter, uninstalled and with no listener.

    SO_PEERCRED is connection identity, NOT Roundcube user identity. A separate
    trusted session authority must atomically consume a short-lived opaque ticket
    bound to peer, operation and input digest, returning current SessionContext.
    No HTTP-supplied context/owner/verified flag can replace that authority.
"""
import array
from dataclasses import dataclass
from hashlib import sha256
import json
import os
import re
import socket
import struct
import sys
import secrets
import threading
from frozen import require, OwnerIdentity, SessionContext

LIMIT = 65536
INPUTS = {'list': {'cursor'}, 'issue_options': {'label', 'request_id'},
          'issue_finish': {'action_id', 'assertion', 'p12_password'},
          'revoke_options': {'device_id', 'request_id'},
          'revoke_finish': {'action_id', 'assertion'}}


@dataclass(frozen=True)
class Peer:
    pid: int
    uid: int
    gid: int


def kernel_peer(channel, uid, gid):
    require(sys.platform == 'linux' and channel.family == socket.AF_UNIX
            and channel.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM
            and hasattr(socket, 'SO_PEERCRED') and type(uid) is int and uid > 0
            and type(gid) is int and gid > 0, 'ipc_linux_stream', 'ipc_peer')
    value = channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
    require(type(value) is bytes and len(value) == struct.calcsize('3i'),
            'ipc_credentials_shape', 'ipc_peer')
    peer = Peer(*struct.unpack('3i', value))
    require(peer.pid > 0 and (peer.uid, peer.gid) == (uid, gid), 'ipc_peer_denied', 'ipc_peer')
    return peer


def read_exact(channel, size, deadline, clock):
    result = bytearray()
    while len(result) < size:
        remaining = deadline - clock()
        require(remaining > 0, 'ipc_deadline', 'ipc_frame')
        channel.settimeout(remaining)
        data, ancillary, flags, address = channel.recvmsg(
            size - len(result), socket.CMSG_SPACE(16 * array.array('i').itemsize),
            getattr(socket, 'MSG_CMSG_CLOEXEC', 0))
        # Even rejected SCM_RIGHTS messages create FDs; close EVERY received FD.
        try:
            require(not ancillary and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC),
                    'ipc_ancillary_or_truncated', 'ipc_frame')
        finally:
            for level, kind, payload in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    fds = array.array('i')
                    fds.frombytes(payload[:len(payload) - len(payload) % fds.itemsize])
                    for fd in fds:
                        os.close(fd)
        require(type(data) is bytes and 0 < len(data) <= size - len(result),
                'ipc_eof', 'ipc_frame')
        result.extend(data)
    return bytes(result)


def receive(channel, clock, deadline, maximum=LIMIT):
    size = struct.unpack('!I', read_exact(channel, 4, deadline, clock))[0]
    require(0 < size <= maximum, 'ipc_frame_bound', 'ipc_frame')
    return read_exact(channel, size, deadline, clock)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'ipc_duplicate_key', 'ipc_parse')
        result[key] = value
    return result


def request(raw):
    require(type(raw) is bytes and 0 < len(raw) <= LIMIT,
            'ipc_frame_bound', 'ipc_parse')
    # Bound nesting before the JSON decoder (no unbounded recursion acceptance).
    depth = 0; quoted = escaped = False
    for char in raw.decode('utf-8', 'strict'):
        if quoted:
            if escaped: escaped = False
            elif char == '\\': escaped = True
            elif char == '"': quoted = False
        elif char == '"': quoted = True
        elif char in '[{':
            depth += 1
            require(depth <= 16, 'ipc_depth_bound', 'ipc_parse')
        elif char in ']}': depth -= 1
    value = json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('ipc_nonfinite')))
    require(type(value) is dict and set(value) == {'version', 'operation', 'ticket', 'input'}
            and type(value['version']) is int and value['version'] == 1
            and type(value['operation']) is str and value['operation'] in INPUTS,
            'ipc_request_shape', 'ipc_parse')
    operation, ticket, payload = value['operation'], value['ticket'], value['input']
    require(type(ticket) is str and re.fullmatch('[A-Za-z0-9_-]{43,128}', ticket) is not None
            and type(payload) is dict and set(payload) <= INPUTS[operation],
            'ipc_input_shape', 'ipc_parse')
    return operation, ticket, payload, input_digest(operation, payload)


def input_digest(operation, payload):
    require(type(operation) is str and operation in INPUTS and type(payload) is dict
            and set(payload) <= INPUTS[operation], 'ipc_input_shape', 'ipc_parse')
    return sha256(json.dumps(payload, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=True, allow_nan=False).encode()).hexdigest()


class SessionTickets:
    """Same-process one-use authority; no shared file, cookie or signed token.

    The trusted route verifier checks live Roundcube session + POST/CSRF and
    returns SessionContext, not a body claim. Its native integration is pending.
    Tickets are connection-process bound (PID/UID/GID), operation/input bound,
    <=30 seconds, bounded1024. Restart invalidates all; no persistent replay state.
    issue() is INTERNAL ONLY, never an unauthenticated public mint endpoint.
    """
    def __init__(self, runtime, route_verifier, clock):
        self.runtime, self.verifier, self.clock = runtime, route_verifier, clock
        self.lock, self.entries = threading.Lock(), {}

    def issue(self, route_request, peer, operation, payload):
        self.runtime.require_armed()
        require(type(peer) is Peer and peer.pid > 0 and peer.uid > 0 and peer.gid > 0,
                'ipc_peer_denied', 'ipc_session')
        digest = input_digest(operation, payload)
        context = self.verifier.authenticated(route_request, operation, digest)
        require(type(context) is SessionContext, 'ipc_session_unverified', 'ipc_session')
        with self.lock:
            now = self.clock()
            self.entries = {k: v for k, v in self.entries.items() if v[0] > now}
            require(len(self.entries) < 1024, 'ipc_ticket_capacity', 'ipc_session')
            ticket = secrets.token_urlsafe(32)
            key = sha256(ticket.encode()).digest()
            require(key not in self.entries, 'ipc_ticket_collision', 'ipc_session')
            self.entries[key] = (now + 30, peer, operation, digest, context)
            return ticket

    def consume(self, ticket, peer, operation, digest):
        self.runtime.require_armed()
        require(type(ticket) is str and re.fullmatch('[A-Za-z0-9_-]{43,128}', ticket) is not None,
                'ipc_ticket_invalid', 'ipc_session')
        with self.lock:
            row = self.entries.pop(sha256(ticket.encode()).digest(), None)
        # Pop BEFORE all callbacks: failed/unknown validation never reuses ticket.
        require(row is not None and self.clock() < row[0] and row[1:4] == (peer, operation, digest),
                'ipc_ticket_invalid', 'ipc_session')
        current = self.verifier.current(row[4])
        require(type(current) is SessionContext and current == row[4],
                'ipc_session_changed', 'ipc_session')
        return current


class RequestSession:
    """Not serialized; usable only by this identity resolution invocation."""
    def __init__(self, context): self.context, self.key = context, object()

    def authenticated(self, key):
        require(key is self.key, 'ipc_session_reference', 'ipc_session')
        return self.context


class OwnerIPC:
    def __init__(self, runtime, uid, gid, session_authority, reader, actions, clock):
        self.runtime, self.uid, self.gid = runtime, uid, gid
        self.authority, self.reader, self.actions, self.clock = session_authority, reader, actions, clock

    def one(self, channel):
        try:
            self.runtime.require_armed()  # Before peer/frame/secret processing.
            peer = kernel_peer(channel, self.uid, self.gid)
            operation, ticket, payload, digest = request(receive(channel, self.clock, self.clock() + 5))
            context = self.authority.consume(ticket, peer, operation, digest)
            require(type(context) is SessionContext, 'ipc_session_unverified', 'ipc_session')
            session = RequestSession(context)
            owner = OwnerIdentity(session, self.reader).resolve(session.key)
            # actions remains a trusted adapter. It MUST retain purpose-bound UV
            # and resolve current identity again for each existing core callback.
            # P12 download uses a separate cancellable stream, NEVER this JSON RPC.
            return self.actions.dispatch(operation, owner, context, payload)
        finally:
            channel.close()  # No pipelining or automatic second request/retry.

