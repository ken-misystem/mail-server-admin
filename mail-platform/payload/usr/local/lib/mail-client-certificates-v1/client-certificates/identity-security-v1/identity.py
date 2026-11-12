"""Uninstalled identity seam: trusted RC session -> RC row -> unique mail owner.

No connection/default credentials/bootstrap. Forward aliases are not login aliases.
SQL views and the owner-incarnation lock table are inert candidates in this folder.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
import re
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent / "adapters-v1"
if str(BASE) not in sys.path:
    sys.path.insert(0, str(BASE))
from core import AdapterError, Owner, require
from repository import MariaRepository

MAIL_HOST = "mx.mi-sys.jp"  # Existing AccountIdentity.php, not a new endpoint.


def canonical(value):
    require(type(value) is str and 3 <= len(value) <= 254
            and re.fullmatch(r"[\x21-\x7e]+", value) is not None
            and value.count("@") == 1 and not value.startswith("@")
            and not value.endswith("@"), "login_shape", "identity")
    return value.lower()


def uint(value, *, positive=False):
    require(type(value) is int and int(positive) <= value < 2**64,
            "integer_shape", "identity")
    return value


@dataclass(frozen=True)
class SessionContext:
    roundcube_id: int
    username: str
    mail_host: str
    binding_hash: str


def current_owner(row):
    require(type(row) in (tuple, list) and len(row) == 5,
            "owner_row_shape", "identity")
    owner_id, epoch, incarnation, mailbox, active = row
    uint(owner_id, positive=True); uint(epoch); uint(incarnation, positive=True)
    require(type(active) in (bool, int) and active == 1,
            "owner_inactive", "identity")
    require(canonical(mailbox) == mailbox, "owner_canonical_shape", "identity")
    return owner_id, epoch, incarnation, mailbox


class OwnerIdentity:
    """session_port.authenticated() is a server-owned RC-session/IPC verifier.

    It MUST NOT deserialize an HTTP object into SessionContext or accept a caller's
    authenticated/owner flag. RC numeric ID is never a mailserver owner ID.
    reader.read(sql,args,bound) supplies one fresh, bounded READ ONLY snapshot.
    """
    RC_QUERY = "SELECT user_id,username,mail_host FROM roundcube.users WHERE user_id=%s"
    LOGIN_QUERY = ("SELECT owner_id FROM mail_management.mail_client_login_owners "
                   "WHERE BINARY login_name=BINARY %s AND active=1")
    OWNER_QUERY = ("SELECT owner_id,auth_epoch,identity_version,canonical_mailbox,active "
                   "FROM mail_management.mail_client_current_owners WHERE owner_id=%s")

    def __init__(self, session_port, reader):
        self.session_port, self.reader = session_port, reader

    @staticmethod
    def one(rows, reason):
        require(type(rows) in (tuple, list) and len(rows) == 1,
                reason, "identity")
        return rows[0]

    def resolve(self, session):
        context = self.session_port.authenticated(session)
        require(type(context) is SessionContext, "trusted_session_required", "identity")
        uint(context.roundcube_id, positive=True)
        login = canonical(context.username)
        require(context.mail_host == MAIL_HOST
                and re.fullmatch("[0-9a-f]{64}", context.binding_hash or "") is not None,
                "session_binding", "identity")
        # Same snapshot for both DBs; no permissive cached-owner fallback.
        with self.reader.snapshot() as db:
            row = self.one(db.read(self.RC_QUERY, (context.roundcube_id,), 2), "rc_missing_or_ambiguous")
            require(len(row) == 3 and type(row[0]) is int and row[0] == context.roundcube_id
                    and canonical(row[1]) == login and row[2] == MAIL_HOST,
                    "rc_session_mismatch", "identity")
            owner = self.one(db.read(self.LOGIN_QUERY, (login,), 2), "login_missing_or_ambiguous")
            require(len(owner) == 1, "login_row_shape", "identity")
            owner_id = uint(owner[0], positive=True)
            current = current_owner(self.one(db.read(self.OWNER_QUERY, (owner_id,), 2),
                                            "owner_missing_or_ambiguous"))
            require(current[0] == owner_id, "owner_binding", "identity")
        return Owner(owner_id, context.roundcube_id, current[1], current[2], context.binding_hash, True)


class BoundMariaRepository(MariaRepository):
    """Reuse V1 durable transitions, add live owner/incarnation checks under lock.

    Native MERGE-view/base-row locking and cross-connection races remain explicit
    native validation gates, not established by local DB-API fixtures.
    """
    def __init__(self, connector, owner_provider):
        super().__init__(connector)
        self.owner_provider = owner_provider

    @contextmanager
    def locked(self, owner_id):
        expected = self.owner_provider()
        require(type(expected) is Owner and expected.active is True and expected.owner_id == owner_id,
                "owner_context_required", "owner_transaction")
        with super().locked(owner_id):
            def check():
                rows = self.query(OwnerIdentity.OWNER_QUERY + " FOR UPDATE", (owner_id,), owner=owner_id, bound=1)
                require(len(rows) == 1, "owner_missing_or_ambiguous", "owner_transaction")
                actual = current_owner(rows[0])
                require(actual[:3] == (owner_id, expected.epoch, expected.identity_version),
                        "owner_incarnation_changed", "owner_transaction")
            check()
            yield self
            check()  # Before V1's commit; any mismatch rolls back, never retries.


class SnapshotReader:
    """Tuple DB-API reader, one snapshot; no implicit reconnect or row logging."""
    def __init__(self, connector):
        self.connector = connector

    @contextmanager
    def snapshot(self):
        connection = None
        phase = "identity_connect"
        try:
            connection = self.connector()
            cursor = connection.cursor()
            cursor.execute("SET SESSION time_zone = '+00:00'")
            cursor.execute("SET SESSION max_statement_time=2")
            cursor.execute("SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            cursor.execute("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY")
            phase = "identity_snapshot"
            class Read:
                def read(self, sql, args, bound):
                    require(sql in {OwnerIdentity.RC_QUERY, OwnerIdentity.LOGIN_QUERY, OwnerIdentity.OWNER_QUERY}
                            and bound == 2, "identity_query_scope", phase)
                    cursor.execute(sql, args)
                    rows = cursor.fetchmany(3)
                    require(len(rows) <= bound, "identity_row_bound", phase)
                    return rows
            yield Read()
            connection.rollback()
        except AdapterError:
            raise
        except Exception as error:
            code = error.args[0] if error.args and type(error.args[0]) is int else None
            raise AdapterError("identity_read_failed", phase=phase, native_code=code) from None
        finally:
            if connection is not None:
                try:
                    connection.rollback()
                finally:
                    connection.close()
