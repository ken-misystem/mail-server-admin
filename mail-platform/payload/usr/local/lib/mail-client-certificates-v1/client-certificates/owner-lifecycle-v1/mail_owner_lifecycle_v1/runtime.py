"""Actor-local integration. No boot, secret/config discovery or host action."""
from dataclasses import asdict
import threading
import time
import uuid
from .backend import Authority, TrustedVerifier, SharedDispatcher, wrap_actions
from .cleanup_repository import Repository
from .unreceived import Sweeper, COMPONENTS, GuardError, need
from . import lifecycle_sql as sql


def report(audit, error, phase):
    import traceback
    from pathlib import Path
    import re
    reason = error.args[0] if type(error) is GuardError and error.args and type(error.args[0]) is str else None
    audit.failure({'phase':phase,'class':type(error).__name__,
        'reason':reason if reason is not None and re.fullmatch('[a-z][a-z0-9_]{1,95}',reason) else 'external_or_database_failure',
        'metadata_types':getattr(error,'metadata_types',[]) if type(error)is GuardError else [],
        'errno':getattr(error,'errno',None), 'native_code':error.args[0] if error.args and type(error.args[0]) is int else None,
        'frames':[{'source':Path(f.filename).name,'function':f.name,'line':f.lineno}
                  for f in traceback.extract_tb(error.__traceback__)[-6:]], 'raw_error_saved':False})


class ResilientSweeper(Sweeper):
    """A failed material RPC does not prevent DB denial and connection draining."""
    def once(self):
        counts = {'selected':0,'claimed':0,'completed':0,'pending':0,'failed':0}
        rows = self.repo.candidates(self.clock(), self.cutoff, 32)
        need(type(rows) in (list,tuple) and len(rows)<=32,'sweep_candidate_bound')
        for candidate in rows:
            counts['selected'] += 1
            try: claim = self.repo.claim(candidate, self.clock(), self.cutoff)
            except Exception as error:
                counts['failed'] += 1; report(self.audit,error,'durable_unreceived_claim'); continue
            if claim is None: continue
            counts['claimed'] += 1; acknowledgements = set(); failed = False
            try:
                generation, acks = self.enforcement.revoke(claim)
                need(generation == claim.generation and type(acks) is frozenset and acks <= COMPONENTS-{'material_retired'}, 'cleanup_enforcement_binding')
                acknowledgements.update(acks)
            except Exception as error:
                failed = True; report(self.audit,error,'publish_revocation')
            try:
                need(self.cleanup.retire_unreceived(claim) is True,'material_retirement_unverified')
                acknowledgements.add('material_retired')
            except Exception as error:
                failed = True; report(self.audit,error,'retire_unreceived_material')
            try:
                done = self.repo.complete(claim, frozenset(acknowledgements))
                need(type(done) is bool and done == (acknowledgements == COMPONENTS), 'cleanup_completion_contract')
                counts['completed' if done else 'pending'] += 1
            except Exception as error:
                failed = True; report(self.audit,error,'save_revocation_components')
            counts['failed'] += int(failed)
        return counts


def attach_owner(built, verifier_wire, monotonic):
    from frozen_runtime import actions
    previous = built['dispatcher']
    authority = Authority(TrustedVerifier(verifier_wire, built['scope'].owner), monotonic)
    previous.ceremonies = wrap_actions(previous.ceremonies, authority, actions)
    built['dispatcher'] = SharedDispatcher(previous, authority)
    built['verification_authority'] = authority


class IssuerRetirement:
    def __init__(self, wire): self.wire = wire
    def retire_unreceived(self, claim):
        result = self.wire.call('retire_unreceived', asdict(claim))
        need(type(result) is dict and set(result) == {'retired','generation'} and result['retired'] is True
             and type(result['generation']) is int and result['generation'] == claim.generation, 'issuer_retirement_receipt')
        return True


def issuer_retirement(connector, broker, previous):
    """This handler is installed ONLY on the existing owner-peer-checked endpoint."""
    def handle(operation, data):
        if operation != 'retire_unreceived': return previous(operation, data)
        need(type(data) is dict and set(data) == {'id','owner_id','epoch','identity_version','generation'}, 'retirement_fields')
        need(type(data['id']) is str and str(uuid.UUID(data['id'])) == data['id']
             and uuid.UUID(data['id']).version == 4
             and all(type(data[k]) is int and data[k] > 0 for k in ('owner_id','identity_version','generation'))
             and type(data['epoch']) is int and data['epoch'] >= 0, 'retirement_metadata')
        connection = connector(); cursor = None
        try:
            cursor = connection.cursor(); cursor.execute('START TRANSACTION READ ONLY')
            cursor.execute(sql.ISSUER_CLAIM, (uuid.UUID(data['id']).bytes, data['owner_id']))
            rows = cursor.fetchmany(2); connection.rollback()
            expected = (data['generation'], 'revoke_pending', 'expired', 1, data['epoch'], data['identity_version'])
            need(rows in ([expected], (expected,)), 'retirement_committed_claim')
            # Idempotent retirement: material already expired/retired is also safe.
            broker.retire(data['id'])
            return {'retired': True, 'generation': data['generation']}
        finally:
            try:
                if cursor is not None: cursor.close()
            finally: connection.close()
    return handle


class CleanupTick:
    """Once/minute, at most one bounded sweep. Never delays an IPC listener."""
    def __init__(self, sweeper, audit, monotonic=time.monotonic):
        self.sweeper, self.audit, self.clock = sweeper, audit, monotonic
        self.next = 0.0; self.thread = None; self.lock = threading.Lock()
    def __call__(self):
        now = self.clock()
        with self.lock:
            if now < self.next or self.thread is not None and self.thread.is_alive(): return
            self.next = now + 60
            self.thread = threading.Thread(target=self.run, name='unreceived-p12-expiry', daemon=True)
            self.thread.start()
    def run(self):
        try:
            result = self.sweeper.once()
            # Fixed numeric metadata only; do not serialize candidate IDs/owners.
            if result['failed'] or result['pending']:
                self.audit.failure({'phase':'unreceived_p12_sweep','counts':result,'raw_error_saved':False})
        except Exception as error:
            import traceback
            from pathlib import Path
            frames = traceback.extract_tb(error.__traceback__)[-6:]
            self.audit.failure({'phase':'unreceived_p12_sweep','class':type(error).__name__,
                'errno':getattr(error,'errno',None), 'native_code':error.args[0] if error.args and type(error.args[0]) is int else None,
                'frames':[{'source':Path(f.filename).name,'function':f.name,'line':f.lineno} for f in frames],
                'raw_error_saved':False})


def cleanup_tick(context, publisher):
    cutoff = context.config.get('owner_lifecycle_activation_cutoff')
    need(type(cutoff) is int and cutoff > 0, 'cleanup_activation_cutoff')
    from rpc import Client
    repo = Repository(context.role('orchestrator'), cutoff)
    retirement = IssuerRetirement(Client(context.factory('issuer', 'crl_owner')))
    sweep = ResilientSweeper(repo, publisher, retirement, context.audit, lambda:int(time.time()), cutoff)
    return CleanupTick(sweep, context.audit)
