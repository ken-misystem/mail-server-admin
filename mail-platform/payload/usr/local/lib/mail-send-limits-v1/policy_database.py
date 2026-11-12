"""Bounded read-only SQL for SMTP identity and current editable limit profiles."""
from contextlib import contextmanager
import re
import threading
from policy import need
from legacy_queries import ELIGIBLE, JOINS

PROFILE_COLUMNS=('profile','minute_messages','minute_recipients','hour_messages','hour_recipients','revision')
PROFILES='SELECT '+','.join(PROFILE_COLUMNS)+' FROM mail_management.mail_send_limit_profiles ORDER BY profile LIMIT 3'
MAILBOX=(
    'SELECT o.owner_id FROM mail_management.mail_client_login_owners l '
    'JOIN mail_management.mail_client_current_owners o ON o.owner_id=l.owner_id '
    'WHERE BINARY l.login_name=BINARY %s AND l.active=1 AND o.active=1 LIMIT 2'
)
LEGACY='SELECT c.id '+JOINS+'WHERE c.id=%s AND '+ELIGIBLE+' LIMIT 2'
QUERIES={PROFILES:3,MAILBOX:2,LEGACY:2}


class DatabaseFailure(Exception):
    def __init__(self, phase, error=None, cleanup=()):
        super().__init__('policy_database_unavailable')
        self.phase=phase
        self.native_code=error.args[0] if error is not None and error.args and type(error.args[0]) is int else None
        self.error_class=type(error).__name__ if error is not None else None
        self.cleanup=list(cleanup)


class Reader:
    def __init__(self, connect, on_failure=None):
        self.connect=connect
        self.on_failure=on_failure
        self.slots=threading.BoundedSemaphore(8)

    @contextmanager
    def snapshot(self):
        if not self.slots.acquire(timeout=0.5):
            raise DatabaseFailure('connection_capacity')
        connection=cursor=None
        primary=None
        phase='connect'
        cleanup=[]
        try:
            connection=self.connect()
            connection.autocommit(False)
            phase='cursor'
            cursor=connection.cursor()
            phase='readonly_begin'
            cursor.execute('SET SESSION max_statement_time=2')
            cursor.execute('SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ')
            cursor.execute('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY')
            phase='query'
            yield cursor
        except Exception as error:
            primary=DatabaseFailure(phase,error)
        finally:
            for label,resource,method in (('rollback',connection,'rollback'),('cursor_close',cursor,'close'),('connection_close',connection,'close')):
                if resource is not None:
                    try:
                        getattr(resource,method)()
                    except Exception:
                        cleanup.append(label)
            self.slots.release()
        if primary is not None or cleanup:
            failure=primary or DatabaseFailure('cleanup')
            failure.cleanup=cleanup
            if self.on_failure is not None:
                self.on_failure({'phase':failure.phase,'native_code':failure.native_code,
                    'class':failure.error_class,'cleanup':cleanup})
            raise failure from None

    def read(self, query, args=()):
        need(query in QUERIES and type(args) is tuple and len(args)==int(query!=PROFILES),'query_scope')
        with self.snapshot() as cursor:
            cursor.execute(query,args)
            rows=cursor.fetchmany(QUERIES[query])
            need(type(rows) in (tuple,list) and all(type(row) is tuple for row in rows),'tuple_rows')
        return rows

    def profiles(self):
        rows=self.read(PROFILES)
        need(len(rows)==2 and all(len(row)==len(PROFILE_COLUMNS) for row in rows),'profile_rows')
        return [dict(zip(PROFILE_COLUMNS,row)) for row in rows]

    def mailbox(self, login):
        need(type(login) is str and 3<=len(login)<=254 and login.count('@')==1
             and not login.startswith('@') and not login.endswith('@')
             and re.fullmatch(r'[\x21-\x7e]+',login) is not None,'mailbox_login')
        rows=self.read(MAILBOX,(login.lower(),))
        need(len(rows)==1 and len(rows[0])==1 and type(rows[0][0]) is int
             and 0<rows[0][0]<2**64,'mailbox_missing_or_ambiguous')
        return rows[0][0]

    def legacy(self, username):
        match=re.fullmatch(r'legacy-smtp-([1-9][0-9]{0,18})',username)
        need(match is not None,'legacy_principal')
        identity=int(match[1])
        rows=self.read(LEGACY,(identity,))
        need(len(rows)==1 and rows[0]==(identity,),'legacy_inactive_or_ambiguous')


def connector(driver, socket_path, credential):
    """Credentials are supplied by the service's private credential loader."""
    need(type(credential) is dict and set(credential)=={'user','password'},'credential_fields')
    need(credential['user']=='mail_send_limit_reader' and type(credential['password']) is str
         and 16<=len(credential['password'])<=256,'credential_shape')
    need(type(socket_path) is str and socket_path.startswith('/') and '\0' not in socket_path,'socket_path')
    def connect():
        return driver.connect(unix_socket=socket_path,user=credential['user'],password=credential['password'],
            database='mail_management',charset='utf8mb4',autocommit=False,
            cursorclass=driver.cursors.Cursor,connect_timeout=2,read_timeout=2,write_timeout=2,
            local_infile=False,client_flag=0)
    return connect
