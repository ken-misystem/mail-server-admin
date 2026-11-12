"""Uninstalled application core. No default DB, signing, IPC, TLS or Web adapter.

Every port below is trusted server code, not a caller-provided JSON flag.
Repository.locked must be a durable owner-row transaction; fixture locks are NOT
evidence of production DB isolation. Signing/streaming ports must enforce the
separate process, locked-memory, deadlines and per-device cancellation contract.
"""
from dataclasses import dataclass, replace
from hashlib import sha256
from hmac import compare_digest
from typing import Protocol
from contextlib import AbstractContextManager
import secrets
import unicodedata
import uuid


class Failure(Exception):
    CODES = frozenset({
        "owner_unverified", "input_invalid", "device_not_owned", "state_conflict",
        "fresh_passkey_required", "request_conflict", "quota_reached", "rate_limited",
        "issuance_unknown", "issuer_receipt_invalid", "download_unavailable",
        "download_unknown", "cleanup_unverified", "revocation_ack_mismatch",
        "authorization_unavailable", "certificate_inactive", "owner_mismatch",
        "protocol_invalid", "policy_frame_invalid", "transport_update_failed",
        "diagnostic_unavailable",
    })

    def __init__(self, code, diagnostic=None):
        self.code = code if code in self.CODES else "state_conflict"
        self.diagnostic = diagnostic  # Bounded private metadata, never Web response body.
        super().__init__(self.code)


def need(ok, code):
    if ok is not True:
        raise Failure(code)


def identifier(value):
    need(isinstance(value, str), "input_invalid")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise Failure("input_invalid") from None
    need(str(parsed) == value and parsed.version == 4, "input_invalid")
    return value


def label_text(value):
    need(isinstance(value, str), "input_invalid")
    value = value.strip()
    need(1 <= len(value) <= 100 and len(value.encode("utf-8")) <= 400
         and all(unicodedata.category(c) not in {"Cc", "Cf", "Cs"} for c in value),
         "input_invalid")
    return value


@dataclass(frozen=True)
class Owner:
    owner_id: int
    roundcube_id: int
    epoch: int
    identity_version: int
    session_hash: str
    active: bool = True


@dataclass(frozen=True)
class Device:
    id: str
    owner_id: int
    epoch: int
    identity_version: int
    label: str
    request_id: str
    request_digest: str
    created: int
    state: str = "pending"
    certificate_sha256: str | None = None
    issuer_id: str | None = None
    serial_hex: str | None = None
    not_before: int = 0
    expires: int = 0
    generation: int = 0
    pending_components: tuple = ()


@dataclass(frozen=True)
class Download:
    device_id: str
    owner_id: int
    session_hash: str
    handle_hash: str
    expires: int
    state: str = "ready"


@dataclass(frozen=True)
class Receipt:
    certificate_sha256: str
    issuer_id: str
    serial_hex: str
    not_before: int
    expires: int
    # Trusted issuer's independently parsed certificate profile, never Web input.
    device_id: str
    clientauth_only: bool
    ca_false: bool
    rsa_bits: int


ACTIVATION = frozenset({"imaps", "pop3s", "submission", "resumption"})
REVOCATION = frozenset({"imaps", "pop3s", "submission", "resumption",
                        "existing_sessions", "crl", "material_retired"})


class Identity(Protocol):
    def resolve(self, authenticated_session: object) -> Owner: ...


class Proof(Protocol):
    def consume(self, owner: Owner, purpose: str, target: str, action_id: str,
                assertion: object, now: int) -> None: ...


class Repository(Protocol):
    def locked(self, owner_id: int) -> AbstractContextManager: ...
    def by_request(self, owner_id: int, request_id: str) -> Device | None: ...
    def get(self, owner_id: int, device_id: str) -> Device | None: ...
    def list(self, owner_id: int, before: str | None, limit: int) -> list[Device]: ...
    def counts(self, owner_id: int, now: int) -> tuple[int, int]: ...
    def put(self, device: Device) -> None: ...
    def get_download(self, device_id: str) -> Download | None: ...
    def put_download(self, download: Download) -> None: ...


class Issuer(Protocol):
    # Device ID is the only subject selector. No caller CSR, DN, file or command.
    def prepare(self, device: Device, password: str, now: int) -> Receipt: ...
    def stream(self, device_id: str, writer) -> None: ...
    def retire(self, device_id: str) -> None: ...


class Enforcement(Protocol):
    # Return component acknowledgements for this exact device and generation.
    # Concrete adapter must verify payload digest, authenticated peer and epoch.
    def activate(self, device: Device) -> frozenset[str]: ...
    def revoke(self, device: Device) -> tuple[int, frozenset[str]]: ...


class Audit(Protocol):
    def failure(self, record: dict) -> None: ...


def view(device):
    return {"device_id": device.id, "label": device.label, "state": device.state,
            "created_at": device.created, "expires_at": device.expires or None,
            "revocation_pending_components": list(device.pending_components)}


class Service:
    def __init__(self, identity: Identity, proof: Proof, repository: Repository,
                 issuer: Issuer, enforcement: Enforcement, audit: Audit, clock):
        self.identity, self.proof, self.db = identity, proof, repository
        self.issuer, self.enforcement, self.clock = issuer, enforcement, clock
        self.audit = audit

    def record(self, error, phase):
        from diagnostics import shape
        try:
            record = shape(error, phase)
        except Exception:
            record = {"phase": phase, "reason_code": "diagnostic_unavailable",
                      "raw_message_saved": False}
        try:
            self.audit.failure(record)
            return {**record, "audit_saved": True}
        except Exception as audit_error:
            # Logging failure must NEVER bypass state denial or secret retirement.
            # The outer broker result collector must preserve this safe fallback.
            return {**record, "audit_saved": False,
                    "audit_error_class": "OSError" if isinstance(audit_error, OSError) else "unclassified",
                    "audit_errno": audit_error.errno if isinstance(audit_error, OSError) else None}

    def owner(self, session):
        owner = self.identity.resolve(session)
        need(isinstance(owner, Owner) and owner.active is True
             and type(owner.owner_id) is int and owner.owner_id > 0
             and type(owner.roundcube_id) is int and owner.roundcube_id > 0
             and type(owner.epoch) is int and owner.epoch >= 0
             and type(owner.identity_version) is int and owner.identity_version > 0
             and isinstance(owner.session_hash, str) and len(owner.session_hash) == 64,
             "owner_unverified")
        return owner

    def listing(self, session, before=None):
        owner = self.owner(session)
        if before is not None:
            identifier(before)
        with self.db.locked(owner.owner_id):
            rows = self.db.list(owner.owner_id, before, 11)
        return {"items": [view(row) for row in rows[:10]],
                "next": rows[9].id if len(rows) > 10 else None}

    @staticmethod
    def issue_target(request_id, label):
        return sha256((identifier(request_id) + "\x00" + label_text(label)).encode()).hexdigest()

    def issue(self, session, label, request_id, action_id, assertion, password):
        owner, now = self.owner(session), self.clock()
        label, request_id = label_text(label), identifier(request_id)
        target = self.issue_target(request_id, label)
        # Password is used only on first issuance, never for an idempotent replay.
        need(isinstance(password, str) and 16 <= len(password) <= 128
             and all(0x21 <= ord(c) <= 0x7e for c in password), "input_invalid")
        with self.db.locked(owner.owner_id):
            old = self.db.by_request(owner.owner_id, request_id)
            if old is not None:
                need(compare_digest(old.request_digest, target), "request_conflict")
                return view(old)  # No second key and no download handle replay.
            active, recent = self.db.counts(owner.owner_id, now)
            need(active < 10, "quota_reached")
            need(recent < 3, "rate_limited")
            self.proof.consume(owner, "issue", target, action_id, assertion, now)
            row = Device(str(uuid.uuid4()), owner.owner_id, owner.epoch,
                         owner.identity_version, label, request_id, target, now)
            self.db.put(row)  # Durable pending reservation BEFORE any signing.
        phase = "issuer"
        try:
            receipt = self.issuer.prepare(row, password, now)
            phase = "receipt"
            self.check_receipt(row, receipt, now)
            phase = "owner_recheck"
            latest = self.owner(session)
            need(latest == owner, "owner_unverified")
            row = replace(row, certificate_sha256=receipt.certificate_sha256,
                          issuer_id=receipt.issuer_id, serial_hex=receipt.serial_hex,
                          not_before=receipt.not_before, expires=receipt.expires)
            with self.db.locked(owner.owner_id):
                need(self.db.get(owner.owner_id, row.id).state == "pending", "state_conflict")
                self.db.put(row)
            phase = "activate"
            ack = self.enforcement.activate(row)
            need(type(ack) is frozenset and ack == ACTIVATION, "transport_update_failed")
            handle = secrets.token_urlsafe(32)
            phase = "issue_commit"
            with self.db.locked(owner.owner_id):
                need(self.db.get(owner.owner_id, row.id).state == "pending", "state_conflict")
                row = replace(row, state="active")
                self.db.put(row)
                self.db.put_download(Download(row.id, owner.owner_id, owner.session_hash,
                                             sha256(handle.encode()).hexdigest(), now + 300))
            return {**view(row), "download_handle": handle, "download_expires_at": now + 300}
        except Exception as error:
            diagnostic = self.record(error, phase)
            # Never reissue after uncertain CA/DB/publisher outcome. Live transport
            # checks authoritative row state; a distributed active map alone is insufficient.
            try:
                with self.db.locked(owner.owner_id):
                    current = self.db.get(owner.owner_id, row.id)
                    if current and current.state not in {"revoke_pending", "revoked"}:
                        self.db.put(replace(current, state="issuance_unknown"))
            finally:
                try:
                    self.issuer.retire(row.id)
                except Exception as cleanup:
                    raise Failure("cleanup_unverified", {"cause": diagnostic,
                        "cleanup": self.record(cleanup, "material_retire")}) from None
            raise Failure("issuance_unknown", diagnostic) from None
        finally:
            # Reference release is NOT a memory-zeroization guarantee in Python.
            password = None

    @staticmethod
    def check_receipt(row, receipt, now):
        need(isinstance(receipt, Receipt), "issuer_receipt_invalid")
        try:
            digest = bytes.fromhex(receipt.certificate_sha256)
            serial = int(receipt.serial_hex, 16)
            issuer = identifier(receipt.issuer_id)
        except (ValueError, TypeError, AttributeError, Failure):
            raise Failure("issuer_receipt_invalid") from None
        need(len(digest) == 32 and receipt.certificate_sha256 == digest.hex()
             and 0 < serial < 2**159 and issuer != row.id
             and receipt.device_id == row.id and receipt.ca_false is True
             and receipt.clientauth_only is True and receipt.rsa_bits == 3072
             and type(receipt.not_before) is int and type(receipt.expires) is int
             and now - 300 <= receipt.not_before <= now < receipt.expires
             and 0 < receipt.expires - receipt.not_before <= 90 * 86400,
             "issuer_receipt_invalid")

    def download(self, session, device_id, handle, writer):
        owner, now = self.owner(session), self.clock()
        identifier(device_id)
        need(isinstance(handle, str) and 32 <= len(handle) <= 128, "download_unavailable")
        with self.db.locked(owner.owner_id):
            row = self.db.get(owner.owner_id, device_id)
            download = self.db.get_download(device_id)
            need(row is not None and row.owner_id == owner.owner_id, "device_not_owned")
            need(row.state == "active" and row.epoch == owner.epoch
                 and row.identity_version == owner.identity_version
                 and row.not_before <= now < row.expires, "download_unavailable")
            need(download is not None and download.owner_id == owner.owner_id
                 and download.state == "ready" and now < download.expires
                 and compare_digest(download.session_hash, owner.session_hash)
                 and compare_digest(download.handle_hash, sha256(handle.encode()).hexdigest()),
                 "download_unavailable")
            self.db.put_download(replace(download, state="consumed"))
        streamed, retired = False, False
        try:
            # Concrete broker must acquire a cancellable per-device stream lease,
            # recheck authoritative state and bound output/time before first byte.
            self.issuer.stream(device_id, writer)
            streamed = True
        except Exception as error:
            raise Failure("download_unknown", self.record(error, "download_stream")) from None
        finally:
            try:
                self.issuer.retire(device_id)
                retired = True
            except Exception as error:
                raise Failure("cleanup_unverified", self.record(error, "material_retire")) from None
            finally:
                with self.db.locked(owner.owner_id):
                    current = self.db.get_download(device_id)
                    # A committed expiry/revocation claim wins over a late stream finalizer.
                    if current is not None and current.state == "consumed" and current.owner_id == owner.owner_id:
                        self.db.put_download(replace(current,
                            state="stream_completed" if streamed and retired else "unknown"))
        return {"state": "stream_completed_save_unverified"}

    def revoke(self, session, device_id, request_id, action_id, assertion):
        owner, now = self.owner(session), self.clock()
        identifier(device_id)
        target = identifier(request_id) + ":" + device_id
        with self.db.locked(owner.owner_id):
            row = self.db.get(owner.owner_id, device_id)
            need(row is not None and row.owner_id == owner.owner_id, "device_not_owned")
            self.proof.consume(owner, "revoke", target, action_id, assertion, now)
            if row.state == "revoked":
                return view(row)
            if row.state != "revoke_pending":
                row = replace(row, state="revoke_pending", generation=row.generation + 1,
                              pending_components=tuple(sorted(REVOCATION)))
                self.db.put(row)  # Revocation linearizes at this durable commit.
        phase = "material_retire"
        try:
            self.issuer.retire(row.id)
            phase = "revoke"
            generation, acks = self.enforcement.revoke(row)
            need(type(generation) is int and generation == row.generation
                 and type(acks) is frozenset and acks <= REVOCATION - {"material_retired"},
                 "revocation_ack_mismatch")
            acks = acks | {"material_retired"}
            phase = "ack_commit"
            with self.db.locked(owner.owner_id):
                current = self.db.get(owner.owner_id, row.id)
                need(current.state == "revoke_pending" and current.generation == generation,
                     "revocation_ack_mismatch")
                row = replace(current, state="revoked" if acks == REVOCATION else "revoke_pending",
                              pending_components=tuple(sorted(REVOCATION - acks)))
                self.db.put(row)
            return view(row)
        except Exception as error:
            diagnostic = self.record(error, phase)
            if diagnostic["audit_saved"] is not True:
                raise Failure("diagnostic_unavailable", diagnostic) from None
            # No rollback to active and no hidden success after a failed component.
            return {**view(row), "detail": error.code if isinstance(error, Failure)
                    else "transport_update_failed"}
