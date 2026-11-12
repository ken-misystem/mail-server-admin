"""Separate issuer/P12 worker candidate. Importing does not issue certificates.

Linux secret-region and pinned-executable implementations live in native.py.
Tests inject synthetic regions/runner/inspector; never invoke OpenSSL issuance.
"""
from dataclasses import dataclass
import threading
import uuid
from core import AdapterError, Receipt, require

PROFILE = (b"[client]\nbasicConstraints=critical,CA:FALSE\n"
           b"keyUsage=critical,digitalSignature\nextendedKeyUsage=critical,clientAuth\n"
           b"subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")


@dataclass(frozen=True)
class Command:
    phase: str
    argv: tuple
    output_fd: int
    pass_fds: tuple


def plan(device_id, serial_hex, *, key, csr, cert, p12, password, profile,
         ca_certificate, ca_key, ca_password):
    parsed = uuid.UUID(device_id)
    require(str(parsed) == device_id and parsed.version == 4, "subject_shape", "command_plan")
    require(type(serial_hex) is str and len(serial_hex) <= 40 and len(serial_hex) % 2 == 0
            and serial_hex == serial_hex.lower() and 0 < int(serial_hex, 16) < 2**159,
            "serial_shape", "command_plan")
    fds = (key, csr, cert, p12, password, profile, ca_certificate, ca_key, ca_password)
    require(all(type(fd) is int and fd > 2 for fd in fds) and len(set(fds)) == len(fds),
            "descriptor_shape", "command_plan")
    path = lambda fd: "/proc/self/fd/" + str(fd)
    return (
        Command("key_generation", ("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"), key, ()),
        Command("csr", ("openssl", "req", "-new", "-sha256", "-key", path(key), "-subj", "/CN=" + device_id), csr, (key,)),
        Command("sign", ("openssl", "x509", "-req", "-in", path(csr), "-CA", path(ca_certificate),
            "-CAkey", path(ca_key), "-passin", "fd:" + str(ca_password), "-set_serial", "0x" + serial_hex,
            "-days", "90", "-sha256", "-copy_extensions", "none", "-extfile", path(profile), "-extensions", "client"),
            cert, (csr, ca_certificate, ca_key, ca_password, profile)),
        Command("p12", ("openssl", "pkcs12", "-export", "-inkey", path(key), "-in", path(cert),
            "-certfile", path(ca_certificate), "-name", "mail-device-" + device_id,
            "-keypbe", "AES-256-CBC", "-certpbe", "AES-256-CBC", "-macalg", "SHA256", "-iter", "100000",
            "-passout", "fd:" + str(password)), p12, (key, cert, ca_certificate, password)),
    )


@dataclass
class Pending:
    material: object
    expires: float
    consumed: bool = False


class IssuerBroker:
    """Required ports have no permissive defaults and no caller-supplied paths.

    authority.reserve checks durable pending owner/epoch/identity and reserves the
    issuer/serial journal in one transaction BEFORE any key generation. Repeated
    reserve must fail, not return permission to sign the same request again.
    """
    def __init__(self, authority, regions, runner, inspector, issuer, clock, audit):
        self.authority, self.regions, self.runner, self.inspector = authority, regions, runner, inspector
        self.issuer, self.clock, self.audit = issuer, clock, audit
        self.entries, self.lock = {}, threading.RLock()

    def prepare(self, device, password, now):
        require(type(password) is str and 16 <= len(password) <= 128
                and all(0x21 <= ord(c) <= 0x7e for c in password), "password_shape", "prepare")
        with self.lock:
            require(len(self.entries) < 32, "pending_material_bound", "prepare")
            require(device.id not in self.entries, "already_prepared", "prepare")
            # The reservation is durable and remains on failure. Never retry sign.
            serial = self.authority.reserve(device, self.issuer.id)
            buffers, keep = [], None
            phase = "allocate_locked_regions"
            try:
                def region(size):
                    item = self.regions.allocate(size)
                    buffers.append(item)
                    return item
                key, csr, cert = region(16384), region(16384), region(32768)
                p12, passwd, profile = region(131072), region(256), region(1024)
                passwd.write(password.encode("ascii") + b"\n")
                profile.write(PROFILE)
                commands = plan(device.id, serial, key=key.fd, csr=csr.fd, cert=cert.fd, p12=p12.fd,
                    password=passwd.fd, profile=profile.fd, ca_certificate=self.issuer.certificate_fd,
                    ca_key=self.issuer.key_fd, ca_password=self.issuer.password_fd)
                for command in commands:
                    phase = command.phase
                    self.runner.run(command, buffers)
                phase = "independent_certificate_inspection"
                receipt = self.inspector.inspect(cert, device, self.issuer, serial, now)
                require(type(receipt) is Receipt and receipt.device_id == device.id
                        and receipt.issuer_id == self.issuer.id and receipt.serial_hex == serial,
                        "receipt_binding", phase)
                require(0 < p12.length <= p12.capacity, "p12_bound", phase)
                self.authority.signed(device.id, serial, receipt)
                self.entries[device.id] = Pending(p12, self.clock() + 300)
                keep = p12
                return receipt
            except Exception as error:
                # Retain journal uncertainty even when the local audit sink fails.
                try: self.authority.unknown(device.id, serial)
                finally: self.audit.failure(error, phase)
                raise
            finally:
                cleanup_failed = False
                for item in buffers:
                    if item is not keep:
                        try: item.retire()
                        except Exception: cleanup_failed = True
                password = None
                if cleanup_failed:
                    # If any secret cleanup is unverified, do NOT retain a usable
                    # download or falsely return an issuance success.
                    entry = self.entries.pop(device.id, None)
                    if entry is not None:
                        try: entry.material.retire()
                        finally: raise AdapterError("cleanup_unverified", phase="prepare_cleanup")
                    raise AdapterError("cleanup_unverified", phase="prepare_cleanup")

    def stream(self, device_id, destination):
        # Lock is shared with retire: no new stream can pass a revocation barrier.
        # Actual destination enforces absolute deadline and authenticated IPC peer.
        with self.lock:
            entry = self.entries.get(device_id)
            require(entry is not None and not entry.consumed and self.clock() < entry.expires,
                    "download_unavailable", "download_claim")
            self.authority.require_active(device_id)
            entry.consumed = True
            try:
                destination.send_region(entry.material, deadline=min(entry.expires, self.clock() + 15))
            finally:
                self.entries.pop(device_id, None)
                entry.material.retire()

    def retire(self, device_id):
        with self.lock:
            entry = self.entries.pop(device_id, None)
            if entry is not None: entry.material.retire()

    def expire(self):
        with self.lock:
            expired = [key for key, entry in self.entries.items() if self.clock() >= entry.expires]
            for key in expired: self.retire(key)
        return len(expired)
