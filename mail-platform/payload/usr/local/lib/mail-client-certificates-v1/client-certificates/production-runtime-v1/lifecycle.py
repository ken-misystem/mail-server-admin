"""Authenticated first-use binding without seeding all mail users or changing them."""
from dataclasses import dataclass
from contextlib import contextmanager


def need(value,code):
    if value is not True:raise ValueError(code)


@dataclass(frozen=True)
class BootstrapOwner:
    owner_id:int
    epoch:int
    mailbox:str
    active:bool


class BootstrapReader:
    RC='SELECT user_id,username,mail_host FROM roundcube.users WHERE user_id=%s LIMIT 2'
    LOGIN='SELECT owner_id FROM mail_management.mail_client_bootstrap_login_owners WHERE BINARY login_name=BINARY %s AND active=1 LIMIT 2'
    OWNER='SELECT owner_id,auth_epoch,canonical_mailbox,active FROM mail_management.mail_client_bootstrap_current_owners WHERE owner_id=%s LIMIT 2'
    BOUND='SELECT owner_id,identity_version,active FROM mail_management.mail_client_current_owners WHERE owner_id=%s LIMIT 2'
    def __init__(self,connector,context_type):self.connector,self.context_type=connector,context_type
    def current(self,context):
        need(type(context)is self.context_type and type(context.roundcube_id)is int and context.roundcube_id>0
            and context.username==context.username.lower()and context.mail_host=='mx.mi-sys.jp','bootstrap_context')
        connection=self.connector()
        try:
            cursor=connection.cursor();cursor.execute("SET SESSION time_zone = '+00:00'");cursor.execute('SET SESSION max_statement_time=2')
            cursor.execute('SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ');cursor.execute('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY')
            def one(sql,args):
                cursor.execute(sql,args);rows=cursor.fetchmany(3);need(len(rows)==1,'bootstrap_missing_or_ambiguous');return rows[0]
            row=one(self.RC,(context.roundcube_id,));need(row==(context.roundcube_id,context.username,context.mail_host),'bootstrap_roundcube_mismatch')
            login=one(self.LOGIN,(context.username,));need(len(login)==1 and type(login[0])is int and login[0]>0,'bootstrap_owner_shape')
            row=one(self.OWNER,(login[0],));need(len(row)==4 and row[0]==login[0]and type(row[1])is int and row[1]>=0 and type(row[2])is str and row[3]==1,'bootstrap_owner_inactive')
            cursor.execute(self.BOUND,(row[0],));bound=cursor.fetchmany(3);need(len(bound)<=1,'bootstrap_bound_ambiguous')
            if bound:need(len(bound[0])==3 and bound[0][0]==row[0]and type(bound[0][1])is int and bound[0][1]>0 and bound[0][2]==1,'bootstrap_existing_binding_conflict')
            return BootstrapOwner(row[0],row[1],row[2],True),bool(bound)
        finally:
            try:connection.rollback()
            finally:connection.close()


class LifecycleService:
    def __init__(self,runtime,reader,connector,prepare_binding):
        self.runtime,self.reader,self.connector,self.prepare_binding=runtime,reader,connector,prepare_binding
    def ensure(self,context):
        self.runtime.require_armed();before,bound=self.reader.current(context)
        if bound:return {'owner_id':before.owner_id,'already_bound':True}
        version=self.prepare_binding(self.connector(),before.owner_id)
        after,bound=self.reader.current(context)
        need(after==before and bound and type(version)is int and version>0,'lifecycle_postcondition')
        return {'owner_id':before.owner_id,'already_bound':False}


class FirstUseSession:
    """Fresh server session first, optional metadata binding, then real Owner view.

    bootstrap_current never constructs domain.Owner or authorizes signing.
    The lifecycle port is a separate peer-checked actor, not a FPM allow flag.
    """
    def __init__(self,records_gate,bootstrap,lifecycle,epoch_bound):
        self.records_gate,self.bootstrap,self.lifecycle,self.epoch_bound=records_gate,bootstrap,lifecycle,epoch_bound
    def current(self,context):
        record=self.records_gate.record(context);owner,bound=self.bootstrap.current(context)
        need(owner.epoch==record.auth_epoch,'first_use_epoch_changed')
        if not bound:
            response=self.lifecycle.ensure(context)
            need(type(response)is dict and response.get('owner_id')==owner.owner_id,'first_use_lifecycle_owner')
        return self.epoch_bound.current(context)
