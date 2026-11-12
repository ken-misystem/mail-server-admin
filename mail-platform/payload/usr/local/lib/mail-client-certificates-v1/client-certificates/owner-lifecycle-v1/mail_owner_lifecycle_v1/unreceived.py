"""Bounded automatic revocation coordinator. No user sessions or fake UV proof.

Repository claim must durably deny before RPC, under the existing owner lock;
only newly issued, deadline-expired, non-stream-completed downloads qualify.
"""
from dataclasses import dataclass
import re
import traceback
from pathlib import Path

COMPONENTS = frozenset({'crl', 'existing_sessions', 'imaps', 'pop3s', 'resumption', 'submission', 'material_retired'})
DOWNLOAD_STATES = frozenset({'ready', 'consumed', 'unknown', 'expired'})


class GuardError(Exception): pass


def need(ok, code):
    if ok is not True: raise GuardError(code)


@dataclass(frozen=True)
class DownloadObservation:
    created_at: int
    expires_at: int
    state: str
    device_state: str
    owner_matches: bool


def eligible(row, now, activation_cutoff):
    need(type(row) is DownloadObservation and type(now) is int and type(activation_cutoff) is int
         and activation_cutoff > 0, 'unreceived_policy_inputs')
    # 30s grace excludes transfers started just before the deadline and their commits.
    return (row.owner_matches is True and row.created_at >= activation_cutoff and row.state in DOWNLOAD_STATES
            and row.device_state in ('active', 'revoke_pending') and row.expires_at + 30 <= now)


@dataclass(frozen=True)
class Claim:
    id: str
    owner_id: int
    epoch: int
    identity_version: int
    generation: int


class Sweeper:
    def __init__(self, repository, enforcement, issuer_cleanup, audit, clock, activation_cutoff):
        need(type(activation_cutoff) is int and activation_cutoff > 0, 'explicit_rollout_cutoff_required')
        self.repo, self.enforcement, self.cleanup, self.audit = repository, enforcement, issuer_cleanup, audit
        self.clock, self.cutoff = clock, activation_cutoff

    def once(self):
        counts = {'selected': 0, 'claimed': 0, 'completed': 0, 'pending': 0, 'failed': 0}
        candidates = self.repo.candidates(self.clock(), self.cutoff, 32)
        need(type(candidates) in (list, tuple) and len(candidates) <= 32, 'sweep_candidate_bound')
        for candidate in candidates:
            counts['selected'] += 1; phase = 'durable_unreceived_claim'
            try:
                # Rechecks deadline/state/owner under lock; commit must succeed before return.
                claim = self.repo.claim(candidate, self.clock(), self.cutoff)
                if claim is None: continue
                need(type(claim) is Claim and claim.owner_id > 0 and claim.generation > 0, 'committed_claim_receipt')
                counts['claimed'] += 1; phase = 'retire_unreceived_material'; acknowledgements = set()
                retired = self.cleanup.retire_unreceived(claim)
                need(retired is True, 'material_retirement_unverified'); acknowledgements.add('material_retired')
                phase = 'publish_revocation'; generation, acks = self.enforcement.revoke(claim)
                need(generation == claim.generation and type(acks) is frozenset and acks <= COMPONENTS - {'material_retired'}, 'revocation_ack_binding')
                acknowledgements.update(acks); phase = 'save_revocation_components'
                complete = self.repo.complete(claim, frozenset(acknowledgements))
                need(type(complete) is bool and complete == (acknowledgements == COMPONENTS), 'revocation_completion_contract')
                counts['completed' if complete else 'pending'] += 1
            except Exception as error:
                counts['failed'] += 1
                # Preserve denial/pending state. No re-sign, no deletion, no active rollback.
                self.audit.failure({'phase': phase, 'class': type(error).__name__,
                                    'reason': error.args[0] if type(error) is GuardError else 'cleanup_or_database_unverified',
                                    'errno': getattr(error, 'errno', None),
                                    'native_code': error.args[0] if error.args and type(error.args[0]) is int else None,
                                    'frames': [{'source': Path(v.filename).name, 'function': v.name, 'line': v.lineno}
                                               for v in traceback.extract_tb(error.__traceback__)[-6:]], 'raw_error_saved': False})
        return counts
