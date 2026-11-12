"""Owner assembly with separate freshness (fractional) and domain (integer) clocks."""
from dataclasses import asdict
from peer import need
from lifecycle import BootstrapReader,FirstUseSession
from actions_store import ActionStore
from verifier import ExistingWebauthnClient
from session_connection import SessionApplication
def owner_application(*,fd_set,principals,sql_socket,session_connector,records,references,
        lifecycle_wire,verifier_wire,broker_channel,enforcement,audit,wallclock,freshclock):
    from role_startup import orchestrator
    from frozen_runtime import actions,IdentitySnapshot,SessionContext
    from sessions import EpochBoundSession
    need(type(wallclock())is int and type(freshclock())in(int,float),'separate_clock_types')
    need(records.clock is freshclock and records.connector is session_connector,'session_clock_and_role_binding')
    connectors=fd_set.connectors(principals,sql_socket);raw=BootstrapReader(connectors['identity_reader'],SessionContext)
    class Lifecycle:
        def ensure(self,context):return lifecycle_wire.call('ensure',{'context':asdict(context)})
    gate=EpochBoundSession(fd_set.runtime,records,IdentitySnapshot(connectors['identity_reader']),freshclock)
    live=FirstUseSession(gate,raw,Lifecycle(),gate);box={}
    uv=ExistingWebauthnClient(verifier_wire,lambda:box['scope'].owner());store=ActionStore(wallclock,actions.BoundAction)
    built=orchestrator(fd_set,principals,sql_socket,live,broker_channel,enforcement,audit,store,uv,wallclock)
    original=built['dispatcher'].service
    class ObservedService(type(original)):
        def check_receipt(self,row,receipt,started):
            from issue_clock import fresh_time
            return super().check_receipt(row,receipt,fresh_time(self.clock,started))
        def record(self,error,phase):
            # Avoid the legacy top-level 'diagnostics' module-name collision.
            import traceback
            from pathlib import Path
            frames=traceback.extract_tb(error.__traceback__)[-8:]
            row={'phase':phase,'error_class':type(error).__name__,'reason_code':getattr(error,'code',None),
                'frames':[{'source':Path(f.filename).name,'function':f.name,'line':f.lineno}for f in frames],
                'errno':getattr(error,'errno',None),'raw_message_saved':False}
            try:self.audit.failure(row);return dict(row,audit_saved=True)
            except Exception as failure:return dict(row,audit_saved=False,audit_error_class=type(failure).__name__)
    service=ObservedService(original.identity,original.proof,original.db,original.issuer,original.enforcement,original.audit,original.clock)
    built['dispatcher'].service=service;built['dispatcher'].ceremonies.service=service
    from mail_owner_lifecycle_v1.runtime import attach_owner
    from time import monotonic
    attach_owner(built,verifier_wire,monotonic)
    box['scope']=built['scope'];built['session_application']=SessionApplication(references,records,gate,raw,live,built['dispatcher'])
    return built
