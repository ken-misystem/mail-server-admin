"""Uninstalled DATA-stage policy candidate; caller must verify the Unix peer."""
from dataclasses import dataclass
import hashlib
import json
import re

CONTEXT = 'owner_send_limits_v1'
UNAVAILABLE = b'action=451 4.3.0 Send quota unavailable\n\n'
EXCEEDED = b'action=451 4.7.1 Send quota exceeded; retry later\n\n'
CONTINUE = b'action=DUNNO\n\n'


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


@dataclass(frozen=True)
class Limit:
    seconds: int
    messages: int
    recipients: int

    def __post_init__(self):
        need(all(type(v) is int for v in (self.seconds, self.messages, self.recipients)), 'limit_type')
        need(1 <= self.seconds <= 86400 and 1 <= self.messages <= 1000000
             and 1 <= self.recipients <= 1000000, 'limit_bounds')


@dataclass(frozen=True)
class Admission:
    principal: str
    request_key: str
    payload_hash: str
    recipients: int


def parse_frame(raw):
    # Same bounded LF/key=value grammar as candidate-v1/smtp_policy.parse_frame.
    need(type(raw) is bytes and 0 < len(raw) <= 32768 and raw.endswith(b'\n\n')
         and b'\r' not in raw and b'\0' not in raw, 'policy_frame')
    lines = raw[:-2].decode('utf-8', 'strict').split('\n')
    need(len(lines) <= 128, 'policy_fields')
    fields = {}
    for line in lines:
        key, separator, value = line.partition('=')
        need(separator and re.fullmatch('[a-z][a-z0-9_]*', key) and key not in fields
             and len(line.encode()) <= 4096 and all(32 <= ord(c) != 127 for c in value), 'policy_field')
        fields[key] = value
    return fields


def principal(username, resolve_mailbox):
    need(type(username) is str and 0 < len(username.encode()) <= 254, 'sasl_identity')
    legacy = re.fullmatch(r'legacy-smtp-([1-9][0-9]{0,18})', username)
    if legacy:
        identity = 'legacy:' + legacy[1]
    else:
        mailbox_id = resolve_mailbox(username)
        need(type(mailbox_id) is int and mailbox_id > 0, 'canonical_mailbox_required')
        identity = 'mailbox:' + str(mailbox_id)
    return hashlib.sha256(identity.encode()).hexdigest()


def request(raw, connection_nonce, resolve_mailbox):
    fields = parse_frame(raw)
    need(fields.get('request') == 'smtpd_access_policy' and fields.get('protocol_state') == 'DATA'
         and fields.get('policy_context') == CONTEXT, 'policy_scope')
    need(type(connection_nonce) is bytes and len(connection_nonce) == 32, 'connection_nonce')
    instance = fields.get('instance', '')
    need(re.fullmatch('[A-Za-z0-9_.:-]{1,128}', instance), 'instance_required')
    count = fields.get('recipient_count', '')
    need(re.fullmatch('[1-9][0-9]{0,3}', count) and int(count) <= 1000, 'recipient_count')
    owner = principal(fields.get('sasl_username', ''), resolve_mailbox)
    request_key = hashlib.sha256(connection_nonce + b'\0' + instance.encode()).hexdigest()
    payload = json.dumps([owner, int(count), fields.get('sender', ''), fields.get('size', '')], separators=(',', ':')).encode()
    return Admission(owner, request_key, hashlib.sha256(payload).hexdigest(), int(count))


def evaluate(raw, connection_nonce, resolve_mailbox, ledger, now, limits, *, peer_verified=False):
    try:
        need(peer_verified is True, 'untrusted_peer')
        admission = request(raw, connection_nonce, resolve_mailbox)
        outcome = ledger.admit(admission, now, limits)
        need(outcome in ('admitted', 'duplicate', 'exceeded'), 'ledger_outcome')
        return EXCEEDED if outcome == 'exceeded' else CONTINUE
    except Exception:
        return UNAVAILABLE
