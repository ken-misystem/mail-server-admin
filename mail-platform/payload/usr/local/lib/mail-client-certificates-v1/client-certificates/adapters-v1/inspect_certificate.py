"""Public-certificate independent inspection; no private-key/P12 decoding.

Requires a separately reviewed cryptography dependency; not imported or used by
preparation tests. Full real CA/leaf interoperability remains untested here.
"""
import os
import uuid
import hashlib
from core import Receipt, require


class CertificateInspector:
    def inspect(self, region, device, issuer, serial_hex, now):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        require(0 < region.length <= 32768, "certificate_bound", "certificate_inspection")
        certificate = x509.load_pem_x509_certificate(os.pread(region.fd, region.length, 0))
        ca_metadata = os.fstat(issuer.certificate_fd)
        require(0 < ca_metadata.st_size <= 32768, "issuer_certificate_bound", "certificate_inspection")
        raw_ca = os.pread(issuer.certificate_fd, ca_metadata.st_size, 0)
        require(hashlib.sha256(raw_ca).hexdigest() == issuer.certificate_sha256,
                "issuer_certificate_pin", "certificate_inspection")
        ca = x509.load_pem_x509_certificate(raw_ca)
        certificate.verify_directly_issued_by(ca)
        eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        bc = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        ku = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
        names = list(certificate.subject)
        public = certificate.public_key()
        require(len(names) == 1 and names[0].oid == NameOID.COMMON_NAME and names[0].value == device.id
                and list(eku) == [ExtendedKeyUsageOID.CLIENT_AUTH] and bc.ca is False
                and ku.digital_signature is True and not any((ku.content_commitment,ku.key_encipherment,
                    ku.data_encipherment,ku.key_agreement,ku.key_cert_sign,ku.crl_sign))
                and isinstance(public, rsa.RSAPublicKey) and public.key_size == 3072
                and certificate.serial_number == int(serial_hex,16), "certificate_profile", "certificate_inspection")
        start, finish = int(certificate.not_valid_before_utc.timestamp()), int(certificate.not_valid_after_utc.timestamp())
        require(now-300 <= start <= now < finish and 0 < finish-start <= 90*86400
                and ca.not_valid_before_utc <= certificate.not_valid_before_utc
                and certificate.not_valid_after_utc <= ca.not_valid_after_utc,
                "certificate_time", "certificate_inspection")
        require(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
                and ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign is True,
                "issuer_profile", "certificate_inspection")
        return Receipt(certificate.fingerprint(hashes.SHA256()).hex(), issuer.id, serial_hex,
                       start, finish, device.id, True, True, 3072)
