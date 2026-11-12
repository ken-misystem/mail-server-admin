"""Validated profile refresh at the policy boundary; storage failures refuse DATA."""
import re
import threading
import time
from policy import Limit, request, need, CONTINUE, EXCEEDED, UNAVAILABLE

FIELDS = ('minute_messages', 'minute_recipients', 'hour_messages', 'hour_recipients')


def parse(rows):
    need(type(rows) is list and len(rows) == 2, 'profile_inventory')
    profiles = {}
    for row in rows:
        need(type(row) is dict and row.get('profile') in ('mailbox', 'legacy'), 'profile_identity')
        key = row['profile']
        need(key not in profiles, 'duplicate_profile')
        values = []
        for name in (*FIELDS, 'revision'):
            value = row.get(name)
            need(type(value) in (str, int) and re.fullmatch('[1-9][0-9]{0,14}', str(value)), 'profile_number')
            values.append(int(value))
        minute_messages, minute_recipients, hour_messages, hour_recipients, revision = values
        need(all(value <= 1000000 for value in values[:4])
             and minute_messages <= hour_messages and minute_recipients <= hour_recipients
             and minute_messages <= minute_recipients and hour_messages <= hour_recipients, 'profile_limits')
        profiles[key] = (revision, (Limit(60, minute_messages, minute_recipients), Limit(3600, hour_messages, hour_recipients)))
    return profiles


class Profiles:
    def __init__(self, load, clock=time.monotonic):
        self.load = load
        self.clock = clock
        self.lock = threading.Lock()
        self.values = None
        self.previous = None
        self.expires = 0.0

    def get(self, username):
        with self.lock:
            now = self.clock()
            if self.values is None or now >= self.expires:
                # Expire before fetching so failure never extends an old profile.
                self.values = None
                started = now
                values = parse(self.load())
                need(self.clock() - started < 1.0, 'profile_refresh_slow')
                if self.previous is not None:
                    for key, value in values.items():
                        old = self.previous[key]
                        need(value[0] >= old[0] and (value[0] != old[0] or value == old), 'profile_revision_changed')
                self.values = values
                self.previous = values
                self.expires = started + 1.0
            key = 'legacy' if re.fullmatch(r'legacy-smtp-[1-9][0-9]{0,18}', username) else 'mailbox'
            return self.values[key]


def evaluate(raw, nonce, resolve_mailbox, ledger, now, profiles, *, peer_verified=False):
    from policy import parse_frame
    try:
        need(peer_verified is True, 'untrusted_peer')
        admission = request(raw, nonce, resolve_mailbox)
        username = parse_frame(raw)['sasl_username']
        revision, limits = profiles.get(username)
        outcome = ledger.admit(admission, now, limits)
        need(outcome in ('admitted', 'duplicate', 'exceeded'), 'ledger_outcome')
        return EXCEEDED if outcome == 'exceeded' else CONTINUE
    except Exception:
        return UNAVAILABLE
