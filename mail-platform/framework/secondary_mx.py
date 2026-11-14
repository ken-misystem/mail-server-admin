"""Secondary-MX recipient snapshots and fixed transport configuration."""
import json
from pathlib import Path, PurePosixPath
import re
import time

from host_transaction import durable_json, regular
from release import canonical, sha, verify_signature


def hostname(value):
    if not isinstance(value, str) or len(value) > 253 or not all(
            re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in value.split('.')):
        raise ValueError('secondary_hostname')
    return value


def registry(value, now=None):
    now = time.time() if now is None else now
    fields = {'format', 'generation', 'issued', 'expires', 'domains', 'recipients'}
    if set(value) != fields or value['format'] != 1 or type(value['generation']) is not int or value['generation'] < 1:
        raise ValueError('secondary_registry_shape')
    if not all(type(value[name]) in (int, float) for name in ('issued', 'expires')):
        raise ValueError('secondary_registry_time')
    if not value['issued'] <= now < value['expires'] or value['expires'] - value['issued'] > 86400:
        raise ValueError('secondary_registry_expired')
    if type(value['domains']) is not list or not value['domains'] or len(value['domains']) != len(set(value['domains'])):
        raise ValueError('secondary_domains')
    domains = {hostname(name) for name in value['domains']}
    if type(value['recipients']) is not list or len(value['recipients']) != len(set(value['recipients'])):
        raise ValueError('secondary_recipients')
    for address in value['recipients']:
        if not isinstance(address, str) or not re.fullmatch(r'[a-z0-9_.+\-]*@[a-z0-9.\-]+', address):
            raise ValueError('secondary_recipient_syntax')
        if address.rsplit('@', 1)[1] not in domains:
            raise ValueError('secondary_recipient_domain')
    return value


def adopt(snapshot, signature, public_key, state, openssl='openssl', now=None):
    raw, metadata = regular(snapshot, 4*1024*1024)
    if metadata['uid'] != 0 or metadata['mode'] & 0o022:
        raise ValueError('secondary_snapshot_permissions')
    value = json.loads(raw)
    if raw != canonical(value):
        raise ValueError('secondary_snapshot_canonical')
    for trusted in (signature, public_key):
        _, attributes = regular(trusted, 16384)
        if attributes['uid'] != 0 or attributes['mode'] & 0o022:
            raise ValueError('secondary_trust_permissions')
    verify_signature(value, regular(signature, 1024)[0].decode().strip(), public_key, openssl)
    registry(value, now)
    previous = None
    if Path(state).exists():
        state_raw, attributes = regular(state)
        if attributes['uid'] != 0 or attributes['mode'] != 0o600:
            raise ValueError('secondary_state_permissions')
        previous = json.loads(state_raw)
    if previous and (value['generation'] < previous['generation'] or (
            value['generation'] == previous['generation'] and sha(raw) != previous['sha256'])):
        raise ValueError('secondary_snapshot_rollback')
    receipt = {'generation': value['generation'], 'sha256': sha(raw)}
    durable_json(state, receipt)
    return value


def recipient_action(value, recipient, now=None):
    try:
        registry(value, now)
    except ValueError:
        return '451 4.3.5 Recipient registry unavailable'
    if not isinstance(recipient, str) or recipient.count('@') != 1:
        return '550 5.1.1 Recipient unavailable'
    address = recipient.lower()
    domain = address.rsplit('@', 1)[1]
    if domain not in value['domains']:
        return '554 5.7.1 Relay denied'
    if address in value['recipients'] or '@'+domain in value['recipients']:
        return 'DUNNO'
    return '550 5.1.1 Recipient unavailable'


def render(value, host, primary, directory, lifetime_seconds, concurrency, *, milter_socket=None, message_size_limit=None):
    registry(value)
    hostname(host)
    hostname(primary)
    directory = PurePosixPath(directory)
    if not directory.is_absolute() or not re.fullmatch(r'/[a-zA-Z0-9_./-]+', str(directory)) or '..' in directory.parts:
        raise ValueError('secondary_directory')
    if type(lifetime_seconds) is not int or not 3600 <= lifetime_seconds <= 604800:
        raise ValueError('secondary_queue_lifetime')
    if type(concurrency) is not int or not 1 <= concurrency <= 20:
        raise ValueError('secondary_concurrency')
    if not isinstance(milter_socket, str) or not re.fullmatch('/[a-zA-Z0-9_./-]+', milter_socket) or '..' in milter_socket.split('/'):
        raise ValueError('secondary_filter_enrollment_required')
    if type(message_size_limit) is not int or not 1024 <= message_size_limit <= 128*1024*1024:
        raise ValueError('secondary_message_limit_required')
    main = {
        'myhostname': host, 'mydestination': '$myhostname, localhost',
        'mynetworks': '127.0.0.0/8', 'relay_domains': ', '.join(value['domains']),
        'relay_recipient_maps': 'texthash:'+str(directory/'recipients'),
        'transport_maps': 'texthash:'+str(directory/'transport'),
        'smtpd_relay_restrictions': 'reject_unauth_destination',
        'smtpd_recipient_restrictions': 'check_policy_service unix:private/secondary-recipients, reject_unlisted_recipient',
        'smtpd_policy_service_default_action': '451 4.3.5 Recipient registry unavailable',
        'smtpd_policy_service_timeout': '3s', 'smtpd_policy_service_try_limit': '1',
        'smtpd_sasl_auth_enable': 'no', 'disable_vrfy_command': 'yes',
        'smtpd_milters': 'unix:'+milter_socket, 'milter_default_action': 'tempfail', 'milter_protocol': '6',
        'message_size_limit': str(message_size_limit),
        'smtp_tls_security_level': 'verify', 'smtp_tls_loglevel': '1',
        'smtp_tls_CAfile': '/etc/ssl/certs/ca-certificates.crt',
        'relay_destination_concurrency_limit': str(concurrency),
        'maximal_queue_lifetime': str(lifetime_seconds)+'s',
    }
    return {'main.cf': ''.join(key+' = '+body+'\n' for key, body in main.items()).encode(),
            'recipients': ''.join(address+' OK\n' for address in value['recipients']).encode(),
            'transport': ''.join(domain+' relay:['+primary+']:25\n' for domain in value['domains']).encode()}
