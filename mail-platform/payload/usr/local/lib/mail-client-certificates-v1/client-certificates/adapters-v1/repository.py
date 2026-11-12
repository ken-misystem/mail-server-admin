"""MariaDB/InnoDB adapter using PyMySQL tuple-cursor APIs; no connection default.

Caller supplies a reviewed private connector. No DSN/config/credentials read here.
Every operation requires an owner-row transaction; a fresh connection is closed
on exit and NEVER reconnected/retried after uncertain commit.
"""
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
import json
import threading
import uuid
from core import AdapterError, Device, Download, require


COLS = ("id,owner_id,owner_epoch,owner_identity_version,label,request_id,request_digest,"
        "created_at,state,certificate_sha256,issuer_id,serial,not_before,expires_at,"
        "revocation_generation,pending_components")
STATES = {"pending", "active", "issuance_unknown", "failed", "revoke_pending", "revoked", "expired"}
COMPONENTS = {"imaps", "pop3s", "submission", "resumption", "existing_sessions", "crl", "material_retired"}
TRANSITIONS = {
    "pending": {"pending", "active", "issuance_unknown", "revoke_pending"},
    "active": {"active", "issuance_unknown", "revoke_pending", "expired"},
    "issuance_unknown": {"issuance_unknown", "revoke_pending"},
    "failed": {"failed"}, "expired": {"expired", "revoke_pending"},
    "revoke_pending": {"revoke_pending", "revoked"}, "revoked": {"revoked"},
}


def binary_id(value):
    parsed = uuid.UUID(value)
    require(str(parsed) == value and parsed.version == 4, "uuid_shape", "repository_input")
    return parsed.bytes


def hex_bytes(value, size=32):
    if value is None: return None
    result = bytes.fromhex(value)
    require(len(result) == size and value == result.hex(), "digest_shape", "repository_input")
    return result


def date(value):
    return datetime.fromtimestamp(value, timezone.utc).replace(tzinfo=None) if value else None


def epoch(value):
    return int(value.replace(tzinfo=timezone.utc).timestamp()) if value else 0


def decode(row):
    values = list(row)
    require(len(values) == 16, "row_shape", "repository_decode")
    values[0] = str(uuid.UUID(bytes=values[0]))
    values[5] = str(uuid.UUID(bytes=values[5]))
    values[6] = values[6].hex()
    values[7] = epoch(values[7])
    values[9] = values[9].hex() if values[9] else None
    values[10] = str(uuid.UUID(bytes=values[10])) if values[10] else None
    values[11] = values[11].hex() if values[11] else None
    values[12], values[13] = epoch(values[12]), epoch(values[13])
    values[14] = values[14] or 0
    pending = json.loads(values[15])
    require(type(pending) is list and len(pending) <= 7 and set(pending) <= COMPONENTS,
            "pending_shape", "repository_decode")
    values[15] = tuple(pending)
    return Device(*values)


class MariaRepository:
    def __init__(self, connector):
        self.connector = connector
        self.local = threading.local()

    @contextmanager
    def locked(self, owner_id):
        require(type(owner_id) is int and 0 < owner_id < 2**64, "owner_shape", "transaction")
        require(getattr(self.local, "connection", None) is None, "nested_transaction", "transaction")
        connection = None
        phase = "connect"
        try:
            connection = self.connector()  # Fresh configured PyMySQL connection, never browser data.
            connection.autocommit(False)
            cursor = connection.cursor()
            cursor.execute("SET SESSION time_zone = '+00:00'")
            cursor.execute("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED")
            connection.begin()
            self.local.connection, self.local.cursor, self.local.owner = connection, cursor, owner_id
            phase = "owner_lock"
            # Missing lock rows are NOT silently created from a Web request.
            cursor.execute("SELECT owner_id FROM mail_client_owner_locks WHERE owner_id=%s FOR UPDATE", (owner_id,))
            rows = cursor.fetchmany(2)
            require(rows == ((owner_id,),) or rows == [(owner_id,)], "owner_lock_missing_or_ambiguous", phase)
            yield self
            phase = "commit"
            connection.commit()  # PyMySQL commit returns None; do not test truthiness.
        except Exception as error:
            if connection is not None:
                try: connection.rollback()
                except Exception: pass  # Commit uncertainty never becomes an automatic retry.
            if isinstance(error, AdapterError): raise
            code = error.args[0] if error.args and type(error.args[0]) is int else None
            raise AdapterError("commit_unknown" if phase == "commit" else "database_operation_failed",
                               phase=phase, native_code=code) from None
        finally:
            self.local.connection = self.local.cursor = self.local.owner = None
            if connection is not None:
                connection.close()

    def query(self, sql, args, *, owner=None, bound=12):
        require(getattr(self.local, "cursor", None) is not None, "transaction_required", "query")
        if owner is not None:
            require(owner == self.local.owner, "cross_owner", "query")
        cursor = self.local.cursor
        cursor.execute(sql, args)
        if cursor.description is None:
            return []
        rows = cursor.fetchmany(bound + 1)
        require(len(rows) <= bound, "row_bound", "query")
        return rows

    def get(self, owner_id, device_id):
        rows = self.query("SELECT " + COLS + " FROM mail_client_devices WHERE owner_id=%s AND id=%s FOR UPDATE",
                          (owner_id, binary_id(device_id)), owner=owner_id, bound=1)
        return decode(rows[0]) if rows else None

    def by_request(self, owner_id, request_id):
        rows = self.query("SELECT " + COLS + " FROM mail_client_devices WHERE owner_id=%s AND request_id=%s FOR UPDATE",
                          (owner_id, binary_id(request_id)), owner=owner_id, bound=1)
        return decode(rows[0]) if rows else None

    def list(self, owner_id, before, limit):
        require(type(limit) is int and 1 <= limit <= 11, "page_bound", "listing")
        # Numeric creation sequence is internal. Public cursors remain opaque UUIDs.
        args, clause = (owner_id,), ""
        if before is not None:
            cursor = self.query("SELECT sequence_id FROM mail_client_devices WHERE owner_id=%s AND id=%s",
                                (owner_id, binary_id(before)), owner=owner_id, bound=1)
            require(len(cursor) == 1, "cursor_not_owned", "listing")
            clause, args = " AND sequence_id<%s", args + (cursor[0][0],)
        rows = self.query("SELECT " + COLS + " FROM mail_client_devices WHERE owner_id=%s" + clause
                          + " ORDER BY sequence_id DESC LIMIT %s", args + (limit,), owner=owner_id, bound=limit)
        return [decode(row) for row in rows]

    def counts(self, owner_id, now):
        rows = self.query("SELECT SUM(state NOT IN ('revoked','expired','failed')),"
                          "SUM(created_at>%s) FROM mail_client_devices WHERE owner_id=%s",
                          (date(now - 3600), owner_id), owner=owner_id, bound=1)
        require(len(rows) == 1, "counts_shape", "counts")
        return tuple(int(value or 0) for value in rows[0])

    def put(self, row):
        require(type(row) is Device and row.state in STATES and set(row.pending_components) <= COMPONENTS,
                "device_shape", "put_device")
        old = self.get(row.owner_id, row.id)
        if old is None:
            require(row.state == "pending" and row.generation == 0 and row.certificate_sha256 is None,
                    "new_device_state", "put_device")
            values = (binary_id(row.id), row.owner_id, row.epoch, row.identity_version, row.label,
                      binary_id(row.request_id), hex_bytes(row.request_digest), date(row.created), "pending", "[]")
            self.query("INSERT INTO mail_client_devices (id,owner_id,owner_epoch,owner_identity_version,label,"
                       "request_id,request_digest,created_at,state,pending_components) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                       values, owner=row.owner_id, bound=0)
            return
        require(row.state in TRANSITIONS[old.state] and row.generation >= old.generation,
                "state_regression", "put_device")
        immutable = ("owner_id", "epoch", "identity_version", "label", "request_id", "request_digest", "created")
        require(all(getattr(old, key) == getattr(row, key) for key in immutable), "immutable_identity", "put_device")
        for key in ("certificate_sha256", "issuer_id", "serial_hex", "not_before", "expires"):
            require(getattr(old, key) in (None, 0) or getattr(old, key) == getattr(row, key),
                    "certificate_identity_changed", "put_device")
        self.query("UPDATE mail_client_devices SET state=%s,certificate_sha256=%s,issuer_id=%s,serial=%s,"
                   "not_before=%s,expires_at=%s,revocation_generation=%s,pending_components=%s WHERE owner_id=%s AND id=%s",
                   (row.state, hex_bytes(row.certificate_sha256), binary_id(row.issuer_id) if row.issuer_id else None,
                    bytes.fromhex(row.serial_hex) if row.serial_hex else None, date(row.not_before), date(row.expires),
                    row.generation, json.dumps(list(row.pending_components)), row.owner_id, binary_id(row.id)),
                   owner=row.owner_id, bound=0)

    def get_download(self, device_id):
        owner = self.local.owner
        rows = self.query("SELECT device_id,owner_id,session_binding_hash,handle_hash,expires_at,state FROM mail_client_downloads"
                          " WHERE owner_id=%s AND device_id=%s FOR UPDATE", (owner, binary_id(device_id)), owner=owner, bound=1)
        if not rows: return None
        row = rows[0]
        return Download(str(uuid.UUID(bytes=row[0])), row[1], row[2].hex(), row[3].hex(), epoch(row[4]), row[5])

    def put_download(self, row):
        require(type(row) is Download and row.owner_id == self.local.owner, "cross_owner", "put_download")
        old = self.get_download(row.device_id)
        if old is None:
            require(row.state == "ready", "download_state", "put_download")
            self.query("INSERT INTO mail_client_downloads (device_id,owner_id,session_binding_hash,handle_hash,expires_at,state)"
                       " VALUES (%s,%s,%s,%s,%s,%s)", (binary_id(row.device_id), row.owner_id,
                        hex_bytes(row.session_hash), hex_bytes(row.handle_hash), date(row.expires), row.state),
                       owner=row.owner_id, bound=0)
            return
        require(replace(old, state=row.state) == row, "immutable_download", "put_download")
        allowed = {"ready": {"consumed", "cancelled", "expired"},
                   "consumed": {"stream_completed", "unknown"}}
        require(row.state == old.state or row.state in allowed.get(old.state, set()),
                "download_replay", "put_download")
        self.query("UPDATE mail_client_downloads SET state=%s WHERE device_id=%s AND owner_id=%s AND state=%s",
                   (row.state, binary_id(row.device_id), row.owner_id, old.state), owner=row.owner_id, bound=0)

    def reserve_serial(self, owner_id, device_id, issuer_id, serial_hex):
        # Metadata-only reservation BEFORE signing. A unique journal survives an
        # uncertain signing outcome; it is never cleared or reused by this adapter.
        require(0 < int(serial_hex, 16) < 2**159 and len(serial_hex) % 2 == 0,
                "serial_shape", "reserve_serial")
        row = self.get(owner_id, device_id)
        require(row is not None and row.state == "pending", "issuer_reservation_state", "reserve_serial")
        self.query("INSERT INTO mail_client_issuer_journal (device_id,issuer_id,serial,state) VALUES (%s,%s,%s,'reserved')",
                   (binary_id(device_id), binary_id(issuer_id), bytes.fromhex(serial_hex)), owner=owner_id, bound=0)
