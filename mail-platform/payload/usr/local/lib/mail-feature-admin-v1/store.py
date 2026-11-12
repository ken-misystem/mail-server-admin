"""CAS settings and secret-free audit records in a root-private SQLite connection."""
import json
import re
from policy import KINDS, credential_binding, credential_update, defaults, require, validate


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


class SettingsStore:
    def __init__(self, connection, authorize, clock):
        self.db = connection
        self.authorize = authorize
        self.clock = clock
        require(not connection.in_transaction, "transaction_active")
        require(connection.execute("PRAGMA synchronous").fetchone()[0] == 2, "FULL_durability_required")

    def current(self, kind):
        require(kind in KINDS, "configuration_kind")
        row = self.db.execute(
            "SELECT revision,payload,private_credential,applied_revision,phase,failure_code "
            "FROM protection_settings WHERE kind=?", (kind,)
        ).fetchone()
        if row is None:
            return {"kind": kind, "revision": 0, "payload": defaults(kind), "credential_present": False,
                    "applied_revision": 0, "phase": "applied", "failure_code": None}, None
        revision, payload, secret, applied, phase, failure = row
        public = {"kind": kind, "revision": revision, "payload": validate(kind, json.loads(payload)),
                  "credential_present": secret is not None, "applied_revision": applied,
                  "phase": phase, "failure_code": failure}
        private = json.loads(secret) if secret is not None else None
        if kind == "upstream":
            if private is not None:
                require(type(private) is dict, "stored_credential_format")
                private = credential_update(dict(private, action="replace"), None)
            credential_binding(public["payload"], private)
        return public, private

    def read(self, actor, epoch, kind):
        self.authorize(actor, epoch)
        return self.current(kind)[0]

    def save(self, actor, epoch, kind, revision, payload, credential, request_id):
        self.authorize(actor, epoch)
        payload = validate(kind, payload)
        require(type(revision) is int and 0 <= revision < 2147483647, "configuration_revision")
        require(type(request_id) is str and re.fullmatch(r"[a-f0-9]{32}", request_id), "request_id")
        require(type(credential) is dict, "credential_action")
        require(not self.db.in_transaction, "transaction_active")
        committing = False
        try:
            self.db.execute("BEGIN IMMEDIATE")
            previous = self.db.execute(
                "SELECT actor_id,kind,revision FROM protection_requests WHERE request_id=?", (request_id,)
            ).fetchone()
            if previous is not None:
                require(previous[0] == actor and previous[1] == kind, "request_owner")
                self.db.rollback()
                return {"state": "already_recorded", "kind": kind, "revision": previous[2]}
            before, secret = self.current(kind)
            require(before["revision"] == revision, "stale_revision")
            require(before["phase"] not in ("applying", "unknown"), "publication_unresolved")
            if kind == "upstream":
                if any(before["payload"][field] != payload[field] for field in ("host", "port", "tls")):
                    require(credential.get("action") != "keep" or secret is None, "credential_endpoint_changed")
                secret = credential_update(credential, secret)
                credential_binding(payload, secret)
            else:
                require(credential == {"action": "keep"}, "scanner_credential_forbidden")
            after = {"kind": kind, "revision": revision + 1, "payload": payload,
                     "credential_present": secret is not None, "applied_revision": before["applied_revision"],
                     "phase": "pending", "failure_code": None}
            secret_json = encode(secret) if secret is not None else None
            if revision == 0:
                self.db.execute("INSERT INTO protection_settings VALUES(?,?,?,?,?,'pending',NULL)",
                                (kind, 1, encode(payload), secret_json, 0))
            else:
                changed = self.db.execute(
                    "UPDATE protection_settings SET revision=?,payload=?,private_credential=?,phase='pending',"
                    "failure_code=NULL WHERE kind=? AND revision=?", (revision + 1, encode(payload), secret_json, kind, revision)
                )
                require(changed.rowcount == 1, "write_count")
            self.db.execute("INSERT INTO protection_requests VALUES(?,?,?,?,?,?,?)",
                            (request_id, actor, kind, revision + 1, encode(before), encode(after), int(self.clock())))
            committing = True
            self.db.commit()
            return {"state": "saved_pending_publication", "kind": kind, "revision": revision + 1}
        except BaseException:
            try:
                self.db.rollback()
            except BaseException:
                raise RuntimeError("rollback_unverified") from None
            if committing:
                raise RuntimeError("commit_result_unknown") from None
            raise

    def begin_apply(self, kind):
        require(not self.db.in_transaction, "transaction_active")
        try:
            self.db.execute("BEGIN IMMEDIATE")
            public, private = self.current(kind)
            require(public["phase"] == "pending", "publication_not_pending")
            updated = self.db.execute(
                "UPDATE protection_settings SET phase='applying' WHERE kind=? AND revision=? AND phase='pending'",
                (kind, public["revision"])
            )
            require(updated.rowcount == 1, "publication_claim")
            self.db.commit()
            return public, private
        except BaseException:
            self.db.rollback()
            raise

    def finish_apply(self, kind, revision, *, applied, restored):
        require(type(applied) is bool and type(restored) is bool and not (applied and restored), "publication_outcome")
        phase = "applied" if applied else ("failed" if restored else "unknown")
        code = None if applied else ("native_failed_restored" if restored else "manual_reconciliation_required")
        require(not self.db.in_transaction, "transaction_active")
        try:
            self.db.execute("BEGIN IMMEDIATE")
            updated = self.db.execute(
                "UPDATE protection_settings SET phase=?,failure_code=?,"
                "applied_revision=CASE WHEN ? THEN revision ELSE applied_revision END "
                "WHERE kind=? AND revision=? AND phase='applying'", (phase, code, applied, kind, revision)
            )
            require(updated.rowcount == 1, "publication_finish_CAS")
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
