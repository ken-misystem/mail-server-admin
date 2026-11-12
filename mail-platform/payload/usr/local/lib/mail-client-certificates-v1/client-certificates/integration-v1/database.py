"""Uninstalled DB-API integration; connectors are server-owned, never HTTP data.

No driver installation, default connection, credential discovery, DDL or GRANT.
Old durable SQL/state transitions and identity decisions are inherited unchanged.
"""
from contextlib import contextmanager
import threading
from compat import AdapterError, Owner, old_identity, old_repository, old_registry, require

SETUP = ("SET SESSION time_zone = '+00:00'", "SET SESSION max_statement_time=2",
         "SET SESSION innodb_lock_wait_timeout=2")
READ_START = "START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY"


def failure(error, phase):
    code = error.args[0] if error.args and type(error.args[0]) is int else None
    return AdapterError('commit_unknown' if phase == 'commit' else 'database_adapter_failed',
                        phase=phase, native_code=code)


def finish(connection, cursor, *, rollback):
    """Try every cleanup even if one fails. No raw native message is retained."""
    failed = []
    if rollback and connection is not None:
        try: connection.rollback()
        except Exception: failed.append('rollback')
    if cursor is not None:
        try: cursor.close()
        except Exception: failed.append('cursor_close')
    if connection is not None:
        try: connection.close()
        except Exception: failed.append('connection_close')
    return failed


@contextmanager
def session(connector, *, readonly):
    connection = cursor = None
    phase = 'connect'; primary = None; committed = False
    try:
        connection = connector()
        connection.autocommit(False)
        phase = 'cursor_open'; cursor = connection.cursor()
        phase = 'session_setup'
        for sql in SETUP: cursor.execute(sql)
        cursor.execute('SET SESSION TRANSACTION ISOLATION LEVEL ' + ('REPEATABLE READ' if readonly else 'READ COMMITTED'))
        phase = 'read_begin' if readonly else 'write_begin'
        if readonly: cursor.execute(READ_START)
        else: connection.begin()
        phase = 'adapter_body'
        yield connection, cursor
        if not readonly:
            phase = 'commit'
            connection.commit()  # Official API succeeds with None; no truthiness gate.
            committed = True
    except Exception as error:
        primary = error if isinstance(error, AdapterError) else failure(error, phase)
        raise primary from error if primary is not error else None
    finally:
        cleanup = finish(connection, cursor, rollback=not committed)
        if primary is not None:
            # Fixed cleanup labels only; preserve the original phase/native code.
            primary.details = {**(primary.details or {}), 'cleanup_failures': cleanup}
        elif cleanup:
            raise AdapterError('database_cleanup_failed', phase='cleanup', details={'cleanup_failures': cleanup})


class IdentitySnapshot:
    QUERIES = {old_identity.OwnerIdentity.RC_QUERY, old_identity.OwnerIdentity.LOGIN_QUERY,
               old_identity.OwnerIdentity.OWNER_QUERY}

    def __init__(self, connector): self.connector = connector

    @contextmanager
    def snapshot(self):
        lease = {'active': True, 'thread': threading.get_ident()}
        try:
            with session(self.connector, readonly=True) as (_, cursor):
                class Read:
                    def read(_, sql, args, bound):
                        require(lease['active'] and lease['thread'] == threading.get_ident(),
                                'snapshot_lease_closed', 'identity_snapshot')
                        require(type(sql) is str and sql in IdentitySnapshot.QUERIES
                                and type(bound) is int and bound == 2 and type(args) is tuple and len(args) == 1,
                                'identity_query_scope', 'identity_snapshot')
                        cursor.execute(sql, args)
                        rows = cursor.fetchmany(bound + 1)
                        require(type(rows) in (tuple, list) and len(rows) <= bound
                                and all(type(r) is tuple for r in rows), 'tuple_row_contract', 'identity_snapshot')
                        return rows
                yield Read()
        finally: lease['active'] = False


class BoundRepository(old_repository.MariaRepository):
    """Preserve inherited device/download SQL; manage fresh transaction explicitly."""
    def __init__(self, connector, owner_provider):
        super().__init__(connector); self.owner_provider = owner_provider

    @contextmanager
    def locked(self, owner_id):
        require(type(owner_id) is int and 0 < owner_id < 2**64, 'owner_shape', 'owner_transaction')
        require(getattr(self.local, 'connection', None) is None, 'nested_transaction', 'owner_transaction')
        expected = self.owner_provider()
        require(type(expected) is Owner and expected.active is True and expected.owner_id == owner_id,
                'owner_context_required', 'owner_transaction')
        try:
            with session(self.connector, readonly=False) as (connection, cursor):
                self.local.connection, self.local.cursor, self.local.owner = connection, cursor, owner_id
                cursor.execute('SELECT owner_id FROM mail_client_owner_locks WHERE owner_id=%s FOR UPDATE', (owner_id,))
                rows = cursor.fetchmany(2)
                require(rows in (((owner_id,),), [(owner_id,)]), 'owner_lock_missing_or_ambiguous', 'owner_lock')
                def check():
                    rows = self.query(old_identity.OwnerIdentity.OWNER_QUERY + ' FOR UPDATE',
                                      (owner_id,), owner=owner_id, bound=1)
                    require(len(rows) == 1 and old_identity.current_owner(rows[0])[:3] ==
                            (owner_id, expected.epoch, expected.identity_version),
                            'owner_incarnation_changed', 'owner_transaction')
                check(); yield self; check()
        finally:
            self.local.connection = self.local.cursor = self.local.owner = None

    def query(self, sql, args, *, owner=None, bound=12):
        require(type(bound) is int and 0 <= bound <= 12, 'query_bound', 'query')
        require(owner is None or type(owner) is int, 'owner_shape', 'query')
        return super().query(sql, args, owner=owner, bound=bound)


class LiveRegistry(old_registry.LiveRegistry):
    def read(self, query, args):
        # Public parent methods own the query text; the class is an internal DB
        # component, not a remotely callable arbitrary-SQL service.
        with session(self.connector, readonly=True) as (_, cursor):
            cursor.execute(query, args)
            rows = cursor.fetchmany(2)
            require(type(rows) in (tuple, list) and len(rows) == 1 and type(rows[0]) is tuple,
                    'metadata_missing_or_ambiguous', 'live_registry')
            return rows[0]


def components(identity_connector, writer_connector, gateway_connector, session_port, owner_provider):
    """Explicit assembly only. No default principal/credential/runtime arming."""
    require(all(callable(c) for c in (identity_connector, writer_connector, gateway_connector, owner_provider)),
            'connector_contract', 'assembly')
    return {'identity': old_identity.OwnerIdentity(session_port, IdentitySnapshot(identity_connector)),
            'repository': BoundRepository(writer_connector, owner_provider),
            'registry': LiveRegistry(gateway_connector)}

