"""Durable issuer journal and revalidation; fixed new metadata tables only."""
import secrets
import uuid
from core import require
from repository import binary_id, hex_bytes, date


class BrokerAuthority:
    def __init__(self, repository, registry): self.db, self.registry = repository, registry

    def reserve(self, device, issuer_id):
        with self.db.locked(device.owner_id):
            current = self.db.get(device.owner_id, device.id)
            require(current == device and current.state == "pending", "issuer_source_changed", "issuer_reserve")
            owner = self.registry.current_owner(device.owner_id)
            require(owner == (device.epoch, device.identity_version), "owner_epoch_changed", "issuer_reserve")
            serial = (b"\x01" + secrets.token_bytes(19)).hex()  # Positive 153-bit, <159-bit limit.
            self.db.reserve_serial(device.owner_id, device.id, issuer_id, serial)
        return serial

    def signed(self, device_id, serial, receipt):
        # Resolve owner only through the fixed durable reservation, never Web input.
        owner_id = self.registry.reserved_owner(device_id, serial)
        with self.db.locked(owner_id):
            current = self.db.get(owner_id, device_id)
            require(current is not None and current.state == "pending" and receipt.device_id == device_id,
                    "issuer_source_changed", "issuer_complete")
            self.db.query("UPDATE mail_client_issuer_journal SET state='signed',certificate_sha256=%s,not_before=%s,expires_at=%s "
                "WHERE device_id=%s AND serial=%s AND state='reserved'",
                (hex_bytes(receipt.certificate_sha256), date(receipt.not_before), date(receipt.expires),
                 binary_id(device_id), bytes.fromhex(serial)), owner=owner_id, bound=0)
            require(self.db.local.cursor.rowcount == 1, "issuer_journal_transition", "issuer_complete")

    def unknown(self, device_id, serial):
        owner_id = self.registry.reserved_owner(device_id, serial)
        with self.db.locked(owner_id):
            self.db.query("UPDATE mail_client_issuer_journal SET state='unknown' WHERE device_id=%s AND serial=%s AND state IN ('reserved','signed')",
                          (binary_id(device_id), bytes.fromhex(serial)), owner=owner_id, bound=0)

    def require_active(self, device_id):
        self.registry.device_active(device_id)
