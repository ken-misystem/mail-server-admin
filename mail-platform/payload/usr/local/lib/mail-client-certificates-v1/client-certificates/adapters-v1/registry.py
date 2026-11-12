"""Live read-only metadata adapter and fixed Unix-socket PyMySQL connector.

The two owner/login views are REQUIRED proposed read-only views, not deployed
objects. Their definitions depend on the already verified mail-auth schema and
canonical identity adapter and remain an explicit deployment gate.
"""
from contextlib import contextmanager
from hashlib import sha256
import json
import os
import stat
import uuid
from core import AdapterError, require
from tls_gate import Identity


class PrivateConnector:
    def __init__(self, config_fd, runtime):
        self.config_fd, self.runtime = config_fd, runtime

    def __call__(self):
        self.runtime.require_armed()
        metadata = os.fstat(self.config_fd)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                and metadata.st_mode & 0o077 == 0 and metadata.st_uid == os.geteuid()
                and 0 < metadata.st_size <= 8192, "private_config_metadata", "db_connect")
        raw = os.pread(self.config_fd, metadata.st_size + 1, 0)
        require(len(raw) == metadata.st_size and os.fstat(self.config_fd) == metadata,
                "private_config_drift", "db_connect")
        try:
            data = json.loads(raw)
            require(type(data) is dict and set(data) == {"unix_socket", "user", "password", "database"}
                    and all(type(value) is str and 0 < len(value) <= 1024 for value in data.values())
                    and data["unix_socket"].startswith("/"), "private_config_shape", "db_connect")
            import pymysql  # No install/import until the future explicit connection.
            return pymysql.connect(**data, charset="utf8mb4", autocommit=False,
                connect_timeout=5, read_timeout=5, write_timeout=5, cursorclass=pymysql.cursors.Cursor)
        except AdapterError: raise
        except Exception as error:
            code = error.args[0] if error.args and type(error.args[0]) is int else None
            raise AdapterError("private_connection_failed", phase="db_connect", native_code=code) from None
        finally:
            raw = None


class LiveRegistry:
    def __init__(self, connector): self.connector = connector

    def read(self, query, args):
        connection = None
        try:
            connection = self.connector()
            cursor = connection.cursor()
            cursor.execute("SET SESSION time_zone = '+00:00'")
            cursor.execute("SET SESSION max_statement_time=2")
            cursor.execute("START TRANSACTION READ ONLY")
            cursor.execute(query, args)
            rows = cursor.fetchmany(2)
            connection.rollback()
            require(len(rows) == 1, "metadata_missing_or_ambiguous", "live_registry")
            return rows[0]
        except AdapterError: raise
        except Exception as error:
            code = error.args[0] if error.args and type(error.args[0]) is int else None
            raise AdapterError("registry_unavailable", phase="live_registry", native_code=code) from None
        finally:
            if connection is not None: connection.close()

    def lookup(self, fingerprint):
        require(type(fingerprint) is str and len(fingerprint) == 64 and fingerprint == fingerprint.lower(),
                "fingerprint_shape", "live_registry")
        digest = bytes.fromhex(fingerprint)
        row = self.read(
            "SELECT d.id,d.certificate_sha256,d.owner_id,o.canonical_mailbox,d.owner_epoch,"
            "d.owner_identity_version,d.revocation_generation FROM mail_client_devices d "
            "JOIN mail_client_current_owners o ON o.owner_id=d.owner_id "
            "WHERE d.certificate_sha256=%s AND d.state='active' AND o.active=1 "
            "AND d.owner_epoch=o.auth_epoch AND d.owner_identity_version=o.identity_version "
            "AND d.not_before<=UTC_TIMESTAMP(6) AND d.expires_at>UTC_TIMESTAMP(6)", (digest,))
        require(len(row) == 7 and row[1] == digest and type(row[2]) is int and row[2] > 0,
                "registry_binding", "live_registry")
        return Identity(str(uuid.UUID(bytes=row[0])), row[1].hex(), row[2], row[3], row[4], row[5], row[6])

    def resolve_login(self, username):
        require(type(username) is str and 3 <= len(username) <= 254 and username.count("@") == 1
                and all(0x21 <= ord(c) <= 0x7e for c in username), "login_shape", "live_registry")
        row = self.read("SELECT owner_id FROM mail_client_login_owners WHERE login_name=%s AND active=1", (username.lower(),))
        require(len(row) == 1 and type(row[0]) is int and row[0] > 0, "login_owner_shape", "live_registry")
        return row[0]

    def require_active(self, identity):
        require(self.lookup(identity.fingerprint) == identity, "authorization_changed", "live_registry")

    def current_owner(self, owner_id):
        row = self.read("SELECT auth_epoch,identity_version FROM mail_client_current_owners WHERE owner_id=%s AND active=1", (owner_id,))
        require(len(row) == 2 and all(type(value) is int and value >= 0 for value in row),
                "owner_shape", "live_registry")
        return tuple(row)

    def reserved_owner(self, device_id, serial):
        row = self.read("SELECT d.owner_id FROM mail_client_devices d JOIN mail_client_issuer_journal j ON j.device_id=d.id "
                        "WHERE d.id=%s AND j.serial=%s", (uuid.UUID(device_id).bytes, bytes.fromhex(serial)))
        require(len(row) == 1 and type(row[0]) is int and row[0] > 0, "reservation_missing", "live_registry")
        return row[0]

    def device_active(self, device_id):
        row = self.read("SELECT certificate_sha256 FROM mail_client_devices WHERE id=%s AND state='active'", (uuid.UUID(device_id).bytes,))
        require(len(row) == 1 and type(row[0]) is bytes and len(row[0]) == 32,
                "device_inactive", "live_registry")
        return self.lookup(row[0].hex())
