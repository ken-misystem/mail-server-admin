"""TLS entrance candidate; no bind(), listener, credentials or default backend.

Roundcube never passes through this gate. A later socket-activated dedicated
process supplies externally accepted sockets and reviewed private backend ports.
"""
import base64
from dataclasses import dataclass
import hashlib
import ipaddress
import socket
import ssl
import struct
import threading
import uuid
from core import AdapterError, require


@dataclass(frozen=True)
class Identity:
    device_id: str
    fingerprint: str
    owner_id: int
    mailbox: str
    epoch: int
    identity_version: int
    generation: int


class ContextFactory:
    def __init__(self, server_certificate_fd, server_key_fd, client_ca_crl_fd, runtime):
        self.certificate, self.key, self.ca, self.runtime = server_certificate_fd, server_key_fd, client_ca_crl_fd, runtime

    def fresh(self):
        self.runtime.require_armed()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version, context.maximum_version = ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.post_handshake_auth = False
        context.options |= ssl.OP_NO_TICKET | ssl.OP_NO_COMPRESSION
        context.num_tickets = 0
        context.verify_flags |= ssl.VERIFY_X509_STRICT | ssl.VERIFY_CRL_CHECK_CHAIN
        context.load_cert_chain("/proc/self/fd/" + str(self.certificate), "/proc/self/fd/" + str(self.key))
        context.load_verify_locations(cafile="/proc/self/fd/" + str(self.ca))
        # A new context for EVERY connection, not an SNI-shared session cache.
        return context


class SessionBook:
    def __init__(self):
        self.lock, self.sessions, self.denied = threading.RLock(), {}, {}
        self.routes = {}

    def admit(self, fingerprint, lookup, closer):
        with self.lock:
            identity = lookup(fingerprint)  # Live DB, no last-good allow cache.
            require(type(identity) is Identity and identity.fingerprint == fingerprint
                    and identity.device_id not in self.denied, "device_inactive", "admit")
            require(len(self.sessions) < 1024, "session_bound", "admit")
            token = str(uuid.uuid4())
            self.sessions[token] = (identity, closer)
            return token, identity

    def finished(self, token):
        with self.lock:
            self.sessions.pop(token, None)
            self.routes = {key: value for key, value in self.routes.items() if value != token}

    @staticmethod
    def route_key(source, destination):
        return (str(ipaddress.ip_address(source[0])), int(source[1]),
                str(ipaddress.ip_address(destination[0])), int(destination[1]))

    def bind_route(self, token, source, destination):
        with self.lock:
            key = self.route_key(source, destination)
            require(token in self.sessions and key not in self.routes, "route_lease_conflict", "route_bind")
            self.routes[key] = token

    def resolve_route(self, source, destination):
        with self.lock:
            token = self.routes.get(self.route_key(source, destination))
            require(token in self.sessions, "route_lease_missing", "route_lookup")
            identity = self.sessions[token][0]
            require(identity.device_id not in self.denied, "device_inactive", "route_lookup")
            return identity

    def attach(self, token, opener):
        with self.lock:
            require(token in self.sessions, "session_already_revoked", "backend_attach")
            identity = self.sessions[token][0]
            require(identity.device_id not in self.denied, "device_inactive", "backend_attach")
            return opener()  # Opener updates the closer's shared socket holder before release.

    def revoke(self, device_id, generation):
        with self.lock:
            require(type(generation) is int and generation > 0
                    and generation >= self.denied.get(device_id, 0), "stale_generation", "drain")
            self.denied[device_id] = generation  # Blocks races BEFORE closers run.
            targets = [(token, close) for token, (identity, close) in self.sessions.items() if identity.device_id == device_id]
            for token, close in targets:
                require(close() is True, "close_unverified", "drain")
                self.finished(token)
            return {"generation": generation, "closed": len(targets), "remaining": 0}


def line(channel, clock, deadline, maximum=4096):
    content = bytearray()
    while len(content) < maximum:
        remaining = deadline - clock()
        require(remaining > 0, "protocol_deadline", "protocol_read")
        channel.settimeout(remaining)
        byte = channel.recv(1)  # Never prefetch a TLS ClientHello or next command.
        require(type(byte) is bytes and len(byte) == 1, "unexpected_eof", "protocol_read")
        content.extend(byte)
        if content.endswith(b"\r\n"):
            require(b"\r" not in content[:-2] and b"\n" not in content[:-2] and b"\x00" not in content,
                    "protocol_framing", "protocol_read")
            return bytes(content[:-2])
    raise AdapterError("line_bound", phase="protocol_read")


def starttls(channel, clock):
    deadline = clock() + 30
    channel.sendall(b"220 Client certificate gateway ESMTP\r\n")
    greeted = False
    for _ in range(10):
        value = line(channel, clock, deadline, 512)
        command, separator, argument = value.partition(b" ")
        command = command.upper()
        if command in {b"EHLO", b"HELO"} and separator and 0 < len(argument) <= 255:
            greeted = True
            channel.sendall(b"250-gateway\r\n250 STARTTLS\r\n" if command == b"EHLO" else b"250 gateway\r\n")
        elif command == b"STARTTLS" and not separator and greeted:
            channel.sendall(b"220 Ready to start TLS\r\n")
            return
        elif command == b"QUIT" and not separator:
            channel.sendall(b"221 Bye\r\n")
            raise AdapterError("client_closed", phase="starttls")
        elif command == b"NOOP":
            channel.sendall(b"250 OK\r\n")
        else:
            channel.sendall(b"530 5.7.0 STARTTLS required\r\n")
    raise AdapterError("pre_tls_command_bound", phase="starttls")


def proxy_v2(source, destination, identity, version, *, owner_name=True):
    src, dst = ipaddress.ip_address(source[0]), ipaddress.ip_address(destination[0])
    require(src.version == dst.version and all(type(p) is int and 0 < p <= 65535 for p in (source[1], destination[1])),
            "endpoint_shape", "proxy_header")
    require(version in {"TLSv1.2", "TLSv1.3"}, "tls_version", "proxy_header")
    address = src.packed + dst.packed + struct.pack("!HH", source[1], destination[1])
    tls_version = version.encode("ascii")
    attributes = b"\x21" + struct.pack("!H", len(tls_version)) + tls_version
    if owner_name:
        name = identity.mailbox.encode("ascii", "strict")
        require(3 <= len(name) <= 254 and name.count(b"@") == 1
                and all(0x21 <= c <= 0x7e for c in name), "owner_name_shape", "proxy_header")
        attributes += b"\x22" + struct.pack("!H", len(name)) + name
    # SSL + certificate present on this connection; verify=0 means success.
    payload = b"\x07\x00\x00\x00\x00" + attributes
    tlv = b"\x20" + struct.pack("!H", len(payload)) + payload
    return b"\r\n\r\n\x00\r\nQUIT\n" + bytes((0x21, 0x11 if src.version == 4 else 0x21)) + struct.pack("!H", len(address + tlv)) + address + tlv


def decoded(value):
    require(type(value) is bytes and 0 < len(value) <= 4096, "sasl_bound", "smtp_auth")
    try: return base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error): raise AdapterError("sasl_encoding", phase="smtp_auth") from None


def owner_login(value, identity, resolve):
    try: user = value.decode("ascii", "strict")
    except UnicodeError: raise AdapterError("login_shape", phase="smtp_auth") from None
    require(3 <= len(user) <= 254 and user.count("@") == 1
            and all(0x21 <= ord(c) <= 0x7e for c in user), "login_shape", "smtp_auth")
    require(resolve(user) == identity.owner_id, "certificate_owner_mismatch", "smtp_auth")


def response(channel, clock, deadline):
    values, code = [], None
    for _ in range(32):
        value = line(channel, clock, deadline)
        require(len(value) >= 4 and value[:3].isdigit() and value[3:4] in {b"-", b" "},
                "smtp_response_shape", "smtp_backend")
        if code is None: code = value[:3]
        require(value[:3] == code, "smtp_response_code_changed", "smtp_backend")
        values.append(value)
        if value[3:4] == b" ": return code, values
    raise AdapterError("smtp_response_bound", phase="smtp_backend")


def smtp_auth(client, backend, identity, resolve, clock):
    """Only PLAIN/LOGIN pre-auth; password verification remains the existing SASL.

    No MAIL/DATA/XCLIENT is forwarded before auth. For LOGIN, cert-owner check
    precedes the password prompt; PLAIN is checked before any backend forwarding.
    Post-auth opaque relay is allowed only on a reviewed backend with no XCLIENT,
    XFORWARD/master-user bypass and with the live owner policy still enforced.
    """
    deadline = clock() + 120
    code, _ = response(backend, clock, deadline)
    require(code == b"220", "smtp_backend_greeting", "smtp_backend")
    greeted = False
    for _ in range(20):
        value = line(client, clock, deadline)
        command, _, rest = value.partition(b" ")
        command = command.upper()
        if command in {b"EHLO", b"HELO"}:
            require(rest and len(rest) <= 255, "smtp_greeting_shape", "smtp_auth")
            backend.sendall(command + b" " + rest + b"\r\n")
            code, reply = response(backend, clock, deadline)
            require(code == b"250", "smtp_backend_ehlo", "smtp_backend")
            caps = [r[4:] for r in reply if r[4:].split(b" ", 1)[0].upper() not in
                    {b"STARTTLS", b"AUTH", b"XCLIENT", b"XFORWARD"}]
            if not caps: caps = [b"gateway"]
            if command == b"EHLO": caps.append(b"AUTH PLAIN LOGIN")
            client.sendall(b"".join(b"250" + (b" " if i == len(caps)-1 else b"-") + c + b"\r\n" for i,c in enumerate(caps)))
            greeted = True
        elif command == b"AUTH" and greeted:
            mechanism, _, initial = rest.partition(b" ")
            mechanism = mechanism.upper()
            if mechanism == b"PLAIN":
                if not initial:
                    client.sendall(b"334 \r\n"); initial = line(client, clock, deadline)
                if initial == b"*": client.sendall(b"501 5.7.0 Cancelled\r\n"); continue
                parts = decoded(initial).split(b"\x00")
                require(len(parts) == 3 and len(parts[2]) <= 2048, "plain_shape", "smtp_auth")
                owner_login(parts[1], identity, resolve)
                if parts[0]: owner_login(parts[0], identity, resolve)
                backend.sendall(b"AUTH PLAIN " + initial + b"\r\n")
            elif mechanism == b"LOGIN":
                if not initial:
                    client.sendall(b"334 VXNlcm5hbWU6\r\n"); initial = line(client, clock, deadline)
                if initial == b"*": client.sendall(b"501 5.7.0 Cancelled\r\n"); continue
                owner_login(decoded(initial), identity, resolve)
                client.sendall(b"334 UGFzc3dvcmQ6\r\n")
                password = line(client, clock, deadline)
                if password == b"*": client.sendall(b"501 5.7.0 Cancelled\r\n"); continue
                require(len(decoded(password)) <= 2048, "login_password_bound", "smtp_auth")
                backend.sendall(b"AUTH LOGIN\r\n")
                require(response(backend, clock, deadline)[0] == b"334", "login_challenge", "smtp_backend")
                backend.sendall(initial + b"\r\n")
                require(response(backend, clock, deadline)[0] == b"334", "login_challenge", "smtp_backend")
                backend.sendall(password + b"\r\n")
                password = None
            else:
                client.sendall(b"504 5.5.4 Mechanism not supported\r\n"); continue
            code, replies = response(backend, clock, deadline)
            require(code in {b"235", b"535", b"454"}, "smtp_auth_result", "smtp_backend")
            client.sendall(b"".join(row + b"\r\n" for row in replies))
            if code == b"235": return
        elif command == b"QUIT":
            client.sendall(b"221 Bye\r\n")
            raise AdapterError("client_closed", phase="smtp_auth")
        elif command in {b"NOOP", b"RSET"}:
            client.sendall(b"250 OK\r\n")
        else:
            client.sendall(b"530 5.7.0 Authentication required\r\n")
    raise AdapterError("auth_command_bound", phase="smtp_auth")


class TLSGate:
    def __init__(self, contexts, registry, sessions, private_backend, relay, clock):
        self.contexts, self.registry, self.sessions = contexts, registry, sessions
        self.private_backend, self.relay, self.clock = private_backend, relay, clock

    def accepted(self, raw, protocol):
        require(protocol in {"imaps", "pop3s", "submission"}, "protocol_scope", "tls_accept")
        source, destination = raw.getpeername(), raw.getsockname()
        tls, backend, token = None, None, None
        holder = {"tls": None, "backend": None}
        try:
            if protocol == "submission": starttls(raw, self.clock)
            raw.settimeout(30)
            tls = self.contexts.fresh().wrap_socket(raw, server_side=True)
            holder["tls"] = tls
            require(tls.session_reused is False, "resumption_denied", "tls_accept")
            require(tls.version() in {"TLSv1.2", "TLSv1.3"}, "tls_version", "tls_accept")
            certificate = tls.getpeercert(binary_form=True)
            require(type(certificate) is bytes and 0 < len(certificate) <= 32768,
                    "certificate_missing_or_bound", "tls_accept")
            fingerprint = hashlib.sha256(certificate).hexdigest()
            def close():
                # Relay implementation must own no duplicated socket descriptors.
                for endpoint in holder.values():
                    if endpoint is not None:
                        try: endpoint.shutdown(socket.SHUT_RDWR)
                        except OSError: pass
                        endpoint.close()
                return all(s is None or s.fileno() == -1 for s in holder.values())
            token, identity = self.sessions.admit(fingerprint, self.registry.lookup, close)
            self.sessions.bind_route(token, source, destination)
            def open_backend():
                self.registry.require_active(identity)
                holder["backend"] = self.private_backend.open(protocol, identity, source, destination)
                return holder["backend"]
            backend = self.sessions.attach(token, open_backend)
            backend.sendall(proxy_v2(source, destination, identity, tls.version(), owner_name=protocol != "submission"))
            if protocol == "submission":
                smtp_auth(tls, backend, identity, self.registry.resolve_login, self.clock)
            # Relay periodically checks live state and closes on DB/error/revoke;
            # it must never create a new backend or synthesize an allow decision.
            self.relay(tls, backend, identity, self.registry, self.clock)
        finally:
            for endpoint in (backend, tls, raw):
                if endpoint is not None: endpoint.close()
            if token is not None: self.sessions.finished(token)
