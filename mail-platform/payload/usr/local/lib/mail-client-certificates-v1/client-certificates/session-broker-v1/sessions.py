"""Fresh server-side session record + existing identity snapshot. No store default.

The records port must independently read CURRENT authoritative session state, not
echo signed caller claims. Actual Roundcube storage/epoch reader remains a native
integration gate. No persistent session/credential read occurs on construction.
"""
from dataclasses import dataclass
import math
from frozen_seams import require, SessionContext, OwnerIdentity, canonical


@dataclass(frozen=True)
class SessionRecord:
    context: SessionContext
    auth_epoch: int
    expires_at: int
    observed_at: float
    authenticated: bool
    gate_pending: bool
    recovery_pending: bool


class EpochBoundSession:
    def __init__(self, runtime, records, identity_reader, clock):
        self.runtime, self.records, self.reader, self.clock = runtime, records, identity_reader, clock

    def record(self, context):
        self.runtime.require_armed()
        require(type(context) is SessionContext, 'session_context_type', 'live_session')
        row = self.records.current(context.binding_hash)  # No caller fields select account/SQL/path.
        now = self.clock()
        require(type(row) is SessionRecord and type(row.context) is SessionContext and row.context == context,
                'session_record_binding', 'live_session')
        require(type(now) in (int, float) and math.isfinite(now)
                and type(row.observed_at) in (int, float) and math.isfinite(row.observed_at)
                and 0 <= now - row.observed_at <= 1
                and type(row.expires_at) is int and row.expires_at > now,
                'session_record_stale', 'live_session')
        require(type(row.auth_epoch) is int and 0 <= row.auth_epoch < 2**64
                and row.authenticated is True and row.gate_pending is False and row.recovery_pending is False,
                'session_gate_or_epoch_shape', 'live_session')
        require(canonical(context.username) == context.username, 'session_username_canonical', 'live_session')
        return row

    def current(self, context):
        before = self.record(context)
        class TrustedSession:
            def authenticated(_, key):
                require(key is context, 'session_reference', 'live_session')
                return context
        owner = OwnerIdentity(TrustedSession(), self.reader).resolve(context)
        require(owner.epoch == before.auth_epoch, 'session_epoch_changed', 'live_session')
        after = self.record(context)
        # observed_at is a fresh read timestamp, not part of the authenticated session.
        require((after.context, after.auth_epoch, after.expires_at) ==
                (before.context, before.auth_epoch, before.expires_at), 'session_changed_during_identity', 'live_session')
        return context

