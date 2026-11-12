"""900-second server-owned UV lease and one-use, target-bound authorizations.

No browser flag/sessionStorage is an authority. Verifier/credential status are
explicit trusted ports. No default implementation, keys, DB or service boot.
"""
from dataclasses import dataclass
import re
import secrets
import threading

PURPOSES = frozenset({'passkey_add', 'passkey_disable', 'passkey_policy', 'recovery_codes',
                      'app_password_issue', 'app_password_revoke', 'certificate_issue', 'certificate_revoke',
                      'password_change', 'recovery_address'})


class Denied(Exception): pass


def need(ok, code):
    if ok is not True: raise Denied(code)


@dataclass(frozen=True)
class Binding:
    owner_id: int
    roundcube_id: int
    epoch: int
    identity_version: int
    session_hash: str

    def validate(self):
        need(all(type(v) is int and v > 0 for v in (self.owner_id, self.roundcube_id, self.identity_version))
             and type(self.epoch) is int and self.epoch >= 0 and type(self.session_hash) is str
             and re.fullmatch('[a-f0-9]{64}', self.session_hash) is not None, 'owner_session_binding')


@dataclass(frozen=True)
class VerifiedCredential:
    """Construct only after existing RP/origin/challenge/owner/UP/UV verification."""
    credential_id: bytes


@dataclass(frozen=True)
class Lease:
    credential_id: bytes
    issued: float
    expires: float


@dataclass(frozen=True)
class Grant:
    binding: Binding
    purpose: str
    target: str
    lease: Lease
    expires: float


class Authority:
    TTL = 900
    GRANT_TTL = 120
    LIMIT = 1024

    def __init__(self, verifier, monotonic):
        self.verifier = verifier; self.clock = monotonic
        self.lock = threading.RLock(); self.leases = {}; self.pending = {}; self.grants = {}; self.last = None

    def now(self):
        value = self.clock()
        need(type(value) in (int, float) and value >= 0, 'monotonic_clock')
        if self.last is not None and value < self.last:
            self.leases.clear(); self.pending.clear(); self.grants.clear()
            self.last = value; raise Denied('clock_regressed_all_leases_cleared')
        self.last = value
        self.leases = {k: v for k, v in self.leases.items() if v.expires > value}
        self.pending = {k: v for k, v in self.pending.items() if v[2] > value}
        self.grants = {k: v for k, v in self.grants.items() if v.expires > value}
        return value

    def current(self, binding, now):
        lease = self.leases.get(binding)
        if lease is None: return None
        # Recheck the actual credential on every use, including within15 minutes.
        try: enabled = self.verifier.enabled(binding, lease.credential_id)
        except Exception:
            self.invalidate(binding); raise Denied('credential_status_unavailable') from None
        if enabled is not True or not lease.issued <= now < lease.expires:
            self.invalidate(binding); return None
        return lease

    def status(self, binding):
        binding.validate()
        with self.lock:
            now = self.now(); lease = self.current(binding, now)
            return {'authentication_required': lease is None, 'remaining_seconds': max(0, int(lease.expires - now)) if lease else 0}

    def begin(self, binding):
        binding.validate()
        with self.lock:
            now = self.now()
            if self.current(binding, now): return self.status(binding)
            need(len(self.pending) < self.LIMIT and sum(v[0] == binding for v in self.pending.values()) < 2, 'verification_pending_limit')
            ceremony, options = self.verifier.begin(binding)
            need(type(ceremony) is str and bool(ceremony) and type(options) is dict and options.get('userVerification') == 'required', 'existing_uv_options')
            action = secrets.token_urlsafe(32); self.pending[action] = (binding, ceremony, now + 300)
            return {'authentication_required': True, 'action_id': action, 'publicKey': options}

    def finish(self, binding, action_id, assertion):
        binding.validate()
        with self.lock:
            now = self.now(); row = self.pending.pop(action_id, None)
            need(row is not None and row[0] == binding and now < row[2], 'verification_action_binding')
            # Caller-supplied success booleans cannot mint a lease.
            receipt = self.verifier.finish(binding, row[1], assertion)
            need(type(receipt) is VerifiedCredential and type(receipt.credential_id) is bytes
                 and 0 < len(receipt.credential_id) <= 1023, 'verified_credential_receipt')
            need(self.verifier.enabled(binding, receipt.credential_id) is True, 'credential_disabled_after_verification')
            need(len(self.leases) < self.LIMIT or binding in self.leases, 'verification_lease_limit')
            now = self.now(); self.leases[binding] = Lease(receipt.credential_id, now, now + self.TTL)
            return {'authentication_required': False, 'remaining_seconds': self.TTL}

    def authorize(self, binding, purpose, target):
        binding.validate()
        need(purpose in PURPOSES and type(target) is str and re.fullmatch('[a-f0-9]{64}', target) is not None, 'action_purpose_target')
        with self.lock:
            now = self.now(); lease = self.current(binding, now); need(lease is not None, 'fresh_passkey_required')
            need(len(self.grants) < self.LIMIT * 2, 'authorization_limit')
            grant = secrets.token_urlsafe(32)
            self.grants[grant] = Grant(binding, purpose, target, lease, min(lease.expires, now + self.GRANT_TTL))
            return {'authorization_id': grant, 'remaining_seconds': int(lease.expires - now)}

    def consume(self, binding, purpose, target, authorization):
        binding.validate()
        with self.lock:
            now = self.now(); grant = self.grants.pop(authorization, None)
            need(grant is not None and grant.binding == binding and grant.purpose == purpose and grant.target == target
                 and now < grant.expires, 'one_use_owner_action_binding')
            need(self.current(binding, now) == grant.lease, 'verification_lease_changed')
            return True

    def invalidate(self, binding):
        # Called on logout/session rotation/password/epoch/policy/credential change.
        with self.lock:
            self.leases.pop(binding, None)
            self.pending = {k: v for k, v in self.pending.items() if v[0] != binding}
            self.grants = {k: v for k, v in self.grants.items() if v.binding != binding}
