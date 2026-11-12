"""Broker peer/current-device/owner scoping, no signing or listener on import.

Called ONLY by a later authenticated broker wire dispatcher; not a Web endpoint.
The resolver must obtain current rows independently under existing DB policy.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from frozen_seams import require, Owner, domain


class BrokerScope:
    def __init__(self, runtime, peer_guard, resolver):
        self.runtime, self.peer, self.resolver = runtime, peer_guard, resolver
        self.frame = ContextVar('certificate_broker_owner', default=None)

    def owner(self):
        value = self.frame.get()
        require(type(value) is Owner, 'broker_owner_scope_required', 'broker_scope')
        return value

    @contextmanager
    def enter(self, device_id, *, pending=False):
        self.runtime.require_armed(); self.peer.require_peer()
        require(self.frame.get() is None, 'broker_scope_reentry', 'broker_scope')
        domain.identifier(device_id)
        owner, device = self.resolver.current(device_id)
        require(type(owner) is Owner and owner.active is True and type(device) is domain.Device
                and device.id == device_id and (device.owner_id, device.epoch, device.identity_version) ==
                (owner.owner_id, owner.epoch, owner.identity_version), 'broker_owner_device_binding', 'broker_scope')
        if pending:
            require(device.state == 'pending', 'broker_device_not_pending', 'broker_scope')
        token = self.frame.set(owner)
        try: yield device
        finally: self.frame.reset(token)


class ScopedBroker:
    def __init__(self, broker, scope): self.broker, self.scope = broker, scope
    def prepare(self, device, password, now):
        require(type(device) is domain.Device, 'broker_device_type', 'broker_scope')
        with self.scope.enter(device.id, pending=True) as current:
            require(current == device, 'broker_device_changed', 'broker_scope')
            return self.broker.prepare(current, password, now)
    def stream(self, device_id, writer):
        with self.scope.enter(device_id):
            return self.broker.stream(device_id, writer)
    def retire(self, device_id):
        # Cleanup is not blocked by changed/disabled identity. Peer/runtime remains
        # mandatory; only the authenticated orchestrator can retire encrypted material.
        self.scope.runtime.require_armed(); self.scope.peer.require_peer()
        domain.identifier(device_id)
        return self.broker.retire(device_id)

