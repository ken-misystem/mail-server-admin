"""Overlapping CA generations with independent CRL counters and validation."""
import base64
import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import uuid

from safety import need
from boot import public
from crl import Authority, Sequence, RotatingContexts


def previous(config):
    values = config.get('previous_ca', [])
    need(type(values) is list and len(values) <= 2, 'CA_previous_generation_bound')
    identities = [item['issuer_id'] for item in values]
    need(len(set(identities)) == len(identities), 'CA_duplicate_issuer')
    for identity in identities:
        need(str(uuid.UUID(identity)) == identity, 'CA_issuer_identity')
    return values


def credential_names(config):
    return tuple('ca_'+uuid.UUID(item['issuer_id']).hex+'_'+kind
                 for item in previous(config) for kind in ('certificate', 'key', 'password'))


def sequence(directory, identity):
    """Preserve the old single-issuer counter before its first generation move."""
    root = Path(directory)
    destination = root/'ca-sequences'/identity
    destination.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = destination.lstat()
    need(info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0 and not destination.is_symlink(), 'CA_sequence_directory')
    old = root/'sequence.json'
    if old.exists() and not (destination/'sequence.json').exists():
        from safety import held
        value = json.loads(held(str(old), 1024, owner=os.geteuid()))
        if value['issuer_id'] == identity:
            fd = os.open(destination/'sequence.json', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
            try:
                raw = json.dumps(value).encode()
                need(os.write(fd, raw) == len(raw), 'CA_sequence_copy')
                os.fsync(fd)
            finally:
                os.close(fd)
    return Sequence(str(destination), identity)


class CompositeAuthority:
    def __init__(self, authorities):
        self.authorities = authorities

    def bundle(self):
        values = [item.bundle() for item in self.authorities]
        return dict(values[0], previous=values[1:])


def authorities(context, current, checker, regions, connector):
    from custody import online_issuer
    from pc_custody import validate
    import time
    config = context.config
    current.sequence = sequence(config['state_directory'], current.issuer.id)
    entries = [current]
    for item in previous(config):
        old = dict(config, ca=item['ca'])
        custody = json.loads(public(old, 'custody'))
        validate(custody, json.loads(public(old, 'restoration')), json.loads(public(old, 'custody_statement')))
        prefix = 'ca_'+uuid.UUID(item['issuer_id']).hex+'_'
        material = online_issuer(context.runtime, regions,
            {'issuer_'+kind:context.fds[prefix+kind] for kind in ('certificate','key','password')},
            custody, public(old, 'root'), checker, time.time)
        need(material.id == item['issuer_id'] and public(old,'issuer') == os.pread(material.certificate_fd, 65536, 0), 'CA_previous_material_binding')
        chain = public(old,'root')+public(old,'issuer')+public(old,'root_crl')
        entries.append(Authority(context.runtime, connector, material, context.task(regions),
                                 sequence(config['state_directory'], material.id), chain))
    return CompositeAuthority(entries)


class OverlappingContexts(RotatingContexts):
    """Validate all pinned lineages before publishing one combined trust store."""
    def __init__(self, *args, generations=(), identities=(), **kwargs):
        super().__init__(*args, **kwargs)
        self.generations = list(generations)
        self.counters = {}
        self.identities = tuple(identities)

    def install(self, value, required_serial=None, required_issuer=None):
        if not self.generations:
            clean = dict(value)
            need(clean.pop('previous', []) == [], 'CA_unexpected_previous_trust')
            need(required_issuer is None or clean['issuer_id'] == required_issuer,'CA_revocation_issuer_binding')
            return super().install(clean, required_serial)
        need(type(value) is dict and set(value) == {'bundle','sha256','issuer_id','number','entries','previous'}, 'CA_bundle_fields')
        need(type(value['previous']) is list and len(value['previous']) == len(self.generations), 'CA_all_generations_required')
        values = [dict(value, previous=None), *value['previous']]
        values[0].pop('previous')
        need(tuple(item['issuer_id'] for item in values) == self.identities, 'CA_bundle_identity_binding')
        chains = [(self.root,self.issuer,self.root_crl), *self.generations]
        candidate, expiry, counters, certificates, crls = [], [], {}, set(), set()
        found = required_serial is None
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        with self.lock:
            for bundle, chain in zip(values, chains):
                identity = bundle['issuer_id']
                need(identity not in counters, 'CA_bundle_duplicate_issuer')
                shadow = RotatingContexts(self.certificate,self.key,*chain,self.runtime,self.clock)
                shadow.number = self.counters.get(identity, -1)
                shadow.install(bundle)
                raw = shadow.blob
                tail = raw[len(b''.join(chain)):]
                crl = x509.load_pem_x509_crl(tail)
                found = found or ((required_issuer is None or identity == required_issuer)
                                  and crl.get_revoked_certificate_by_serial_number(required_serial) is not None)
                candidate.append(raw)
                expiry.append(shadow.expires)
                counters[identity] = shadow.number
                for certificate in x509.load_pem_x509_certificates(chain[0]+chain[1]):
                    certificates.add(certificate.public_bytes(Encoding.DER))
                for raw_crl in (chain[2], tail):
                    crls.add(x509.load_pem_x509_crl(raw_crl).public_bytes(Encoding.DER))
            need(found, 'revoked_serial_not_in_any_CA_generation')
            # Build OpenSSL context against a detached copy before changing live state.
            trial = copy.copy(self)
            trial.blob, trial.expires = b''.join(candidate), min(expiry)
            trial.expected_ca_count, trial.expected_crl_count = len(certificates), len(crls)
            trial.fresh()
            self.blob, self.expires, self.counters = trial.blob, trial.expires, counters
            self.expected_ca_count, self.expected_crl_count = trial.expected_ca_count, trial.expected_crl_count
            self.number = values[0]['number']
        return {'number':value['number'],'sha256':value['sha256']}


def gate_contexts(context, clock):
    chains = []
    identities = [json.loads(public(context.config,'custody'))['issuer_id']]
    for item in previous(context.config):
        config = dict(context.config, ca=item['ca'])
        chains.append(tuple(public(config,name) for name in ('root','issuer','root_crl')))
        identities.append(item['issuer_id'])
    return OverlappingContexts(context.fds['server_certificate'],context.fds['server_key'],
        public(context.config,'root'),public(context.config,'issuer'),public(context.config,'root_crl'),
        context.runtime,clock,generations=chains,identities=identities)
