"""Nonce/request/peer-bound session authentication candidate. No default key.

Separate NEW IPC HMAC key is delivered privately by future dedicated bootstrap.
Not a CA key, cookie, password or owner claim. No real key generated here.
Same-UID/code compromise is outside the protection of this attestor; dedicated
web pool/secret FD/session verifier and Linux peer path remain native gates.
"""
import base64
from hashlib import sha256
import hmac
import json
import re
import secrets
import threading
import os
import stat
import sys
from frozen_runtime import SessionContext, require

OPERATIONS = frozenset({'list','issue_options','issue_finish','revoke_options','revoke_finish','download'})
DOMAIN = b'mail-device-ipc-v1\x00'


def hex64(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def peer_shape(peer):
    return type(peer) is tuple and len(peer) == 3 and all(type(v) is int and v > 0 for v in peer)


def unbase64(value):
    require(type(value) is str and re.fullmatch('[A-Za-z0-9_-]{1,8192}', value) is not None,
            'attestation_encoding', 'attestation')
    raw = base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)
    require(base64.urlsafe_b64encode(raw).rstrip(b'=').decode() == value,
            'attestation_encoding', 'attestation')
    return raw


def unique(items):
    result = {}
    for key, value in items:
        require(key not in result, 'attestation_duplicate_key', 'attestation')
        result[key] = value
    return result


class KeyFD:
    def __init__(self, fd, runtime):
        require(type(fd) is int and fd > 2, 'attestation_key_fd', 'attestation')
        self.fd, self.runtime = fd, runtime
    def __call__(self):
        self.runtime.require_armed()
        require(sys.platform == 'linux', 'attestation_linux_key', 'attestation')
        before = os.fstat(self.fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
                and before.st_mode & 0o077 == 0 and before.st_size == 32
                and os.get_inheritable(self.fd) is False, 'attestation_key_metadata', 'attestation')
        value = os.pread(self.fd,33,0)
        fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        require(len(value)==32 and tuple(getattr(before,n) for n in fields)==
                tuple(getattr(os.fstat(self.fd),n) for n in fields), 'attestation_key_drift', 'attestation')
        return value


class SessionAuthority:
    def __init__(self, runtime, key_reader, live_session, monotonic):
        self.runtime, self.key_reader, self.live = runtime, key_reader, live_session
        self.clock, self.lock, self.pending = monotonic, threading.Lock(), {}

    def challenge(self, peer, operation, input_sha256):
        self.runtime.require_armed()
        require(peer_shape(peer) and type(operation) is str and operation in OPERATIONS and hex64(input_sha256),
                'attestation_scope', 'attestation')
        with self.lock:
            now = self.clock()
            self.pending = {k:v for k,v in self.pending.items() if v[0] > now}
            require(len(self.pending) < 1024, 'attestation_capacity', 'attestation')
            nonce = secrets.token_hex(32)
            require(nonce not in self.pending, 'attestation_nonce_collision', 'attestation')
            self.pending[nonce] = (now+10, peer, operation, input_sha256)
        return {'nonce':nonce,'peer':list(peer),'operation':operation,'input_sha256':input_sha256}

    def consume(self, challenge, proof, peer, operation, input_sha256):
        self.runtime.require_armed()
        require(type(challenge) is dict and hex64(challenge.get('nonce')),
                'attestation_challenge_shape', 'attestation')
        with self.lock: row = self.pending.pop(challenge['nonce'], None)
        # Consumed even on malformed proof/key/live-session failure; never retry.
        require(row is not None and self.clock() < row[0] and row[1:] == (peer,operation,input_sha256),
                'attestation_replay_or_scope', 'attestation')
        require(type(proof) is dict and set(proof) == {'payload','mac'} and hex64(proof['mac']),
                'attestation_proof_shape', 'attestation')
        raw = unbase64(proof['payload'])
        require(0 < len(raw) <= 4096, 'attestation_bound', 'attestation')
        key = self.key_reader()  # Private held FD, only after runtime/peer challenge checks.
        try:
            require(type(key) is bytes and len(key) == 32, 'attestation_key_shape', 'attestation')
            expected = hmac.digest(key, DOMAIN+raw, 'sha256').hex()
            require(hmac.compare_digest(expected, proof['mac']), 'attestation_mac', 'attestation')
        finally: key = None  # Not a claim of Python string zeroization.
        value = json.loads(raw, object_pairs_hook=unique)
        require(type(value) is dict and set(value) == {'version','nonce','peer','operation','input_sha256','context'}
                and type(value['version']) is int and value['version'] == 1
                and value['nonce'] == challenge['nonce'] and type(value['peer']) is list
                and peer_shape(tuple(value['peer'])) and tuple(value['peer']) == peer
                and value['operation'] == operation and value['input_sha256'] == input_sha256,
                'attestation_claim_binding', 'attestation')
        context = value['context']
        require(type(context) is dict and set(context) == {'roundcube_id','username','mail_host','binding_hash'}
                and type(context['roundcube_id']) is int and 0 < context['roundcube_id'] <= 4294967295
                and type(context['username']) is str and context['mail_host'] == 'mx.mi-sys.jp'
                and hex64(context['binding_hash']), 'attestation_context_shape', 'attestation')
        verified = SessionContext(**context)
        current = self.live.current(verified)
        require(type(current) is SessionContext and current == verified,
                'attestation_session_changed', 'attestation')
        return verified


class AuthenticatedDispatcher:
    def __init__(self, authority, dispatcher): self.authority, self.dispatcher = authority, dispatcher
    def call(self, challenge, proof, peer, operation, raw_input):
        require(type(raw_input) is bytes and 0<len(raw_input)<=65536,
                'attestation_input_bound', 'attestation')
        context = self.authority.consume(challenge,proof,peer,operation,sha256(raw_input).hexdigest())
        data = json.loads(raw_input,object_pairs_hook=unique)
        require(type(data) is dict, 'attestation_input_shape', 'attestation')
        return self.dispatcher.dispatch(operation,context,data)

