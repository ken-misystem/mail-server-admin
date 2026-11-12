"""Purpose-bound adapter around the EXISTING UV WebAuthn verifier.

No second verifier, browser-provided owner ID or generic recent-factor flag.
ActionStore is a new namespace, not the existing key-removal proof namespace.
The production session/ceremony adapter is deliberately not supplied here.
"""
from dataclasses import dataclass
from typing import Protocol
import uuid
from domain import Owner, Failure, need, identifier, label_text


@dataclass(frozen=True)
class BoundAction:
    id: str
    owner: Owner
    purpose: str
    target: str
    request_id: str
    device_id: str | None
    label: str | None
    ceremony_id: str
    expires: int


class ActionStore(Protocol):
    def create(self, action: BoundAction) -> None: ...
    def peek(self, owner_id: int, action_id: str) -> BoundAction | None: ...
    def pop(self, owner_id: int, action_id: str) -> BoundAction | None: ...


class ExistingWebauthn(Protocol):
    def begin(self, roundcube_id: int) -> tuple[str, dict]: ...
    def verify_uv(self, roundcube_id: int, ceremony_id: str, assertion: object) -> None: ...


class ActionProof:
    def __init__(self, store: ActionStore, webauthn: ExistingWebauthn):
        self.store, self.webauthn = store, webauthn

    @staticmethod
    def matches(action, owner, purpose, target, now):
        need(isinstance(action, BoundAction) and action.owner == owner
             and action.purpose == purpose and action.target == target
             and now < action.expires <= now + 300, "fresh_passkey_required")

    def consume(self, owner, purpose, target, action_id, assertion, now):
        identifier(action_id)
        action = self.store.pop(owner.owner_id, action_id)
        self.matches(action, owner, purpose, target, now)
        # Existing verifier MUST perform RP/origin/challenge/owner/UP/UV/signature.
        self.webauthn.verify_uv(owner.roundcube_id, action.ceremony_id, assertion)


class Actions:
    def __init__(self, service, store: ActionStore, webauthn: ExistingWebauthn):
        self.service, self.store, self.webauthn = service, store, webauthn

    def issue_options(self, session, label, request_id):
        label, request_id = label_text(label), identifier(request_id)
        owner = self.service.owner(session)
        return self.begin(owner, "issue", self.service.issue_target(request_id, label),
                          request_id, None, label)

    def revoke_options(self, session, device_id, request_id):
        device_id, request_id = identifier(device_id), identifier(request_id)
        owner = self.service.owner(session)
        with self.service.db.locked(owner.owner_id):
            row = self.service.db.get(owner.owner_id, device_id)
            need(row is not None, "device_not_owned")
        return self.begin(owner, "revoke", request_id + ":" + device_id,
                          request_id, device_id, None)

    def begin(self, owner, purpose, target, request_id, device_id, label):
        ceremony, options = self.webauthn.begin(owner.roundcube_id)
        need(isinstance(ceremony, str) and bool(ceremony) and type(options) is dict,
             "fresh_passkey_required")
        action = BoundAction(str(uuid.uuid4()), owner, purpose, target, request_id,
                             device_id, label, ceremony, self.service.clock() + 300)
        self.store.create(action)
        return {"action_id": action.id, "publicKey": options}

    def pending(self, session, action_id, purpose):
        owner = self.service.owner(session)
        action = self.store.peek(owner.owner_id, identifier(action_id))
        need(isinstance(action, BoundAction), "fresh_passkey_required")
        ActionProof.matches(action, owner, purpose, action.target, self.service.clock())
        return action

    def issue_finish(self, session, action_id, assertion, password):
        action = self.pending(session, action_id, "issue")
        return self.service.issue(session, action.label, action.request_id, action_id, assertion, password)

    def revoke_finish(self, session, action_id, assertion):
        action = self.pending(session, action_id, "revoke")
        return self.service.revoke(session, action.device_id, action.request_id, action_id, assertion)
