"""Pure routing decisions. No DNS, DB, SMTP, mail or service operations."""
from dataclasses import dataclass, asdict
import ipaddress
import re


def need(value, reason):
    if not value:
        raise ValueError(reason)


def domain(value):
    need(type(value) is str and 1 < len(value) <= 253, 'invalid_domain')
    value = value.rstrip('.').lower()
    need('.' in value and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', p)
                             for p in value.split('.')), 'invalid_domain')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError('ip_is_not_domain')


def address(value):
    need(type(value) is str and '%' not in value, 'invalid_address')
    ip = ipaddress.ip_address(value)
    need(getattr(ip, 'ipv4_mapped', None) is None, 'mapped_address_not_supported')
    return ip


@dataclass(frozen=True)
class Decision:
    state: str
    reason: str
    checked_at: int
    expires_at: int

    def json(self):
        return asdict(self)


def decide(follow_mx, records, self_addresses, now):
    """records = bounded, complete MX + both A/AAAA observations from one worker."""
    need(type(now) is int and now > 0 and type(follow_mx) is bool, 'invalid_policy')
    if not follow_mx:
        return Decision('internal', 'configured_internal', now, now + 300)
    def hold(reason):
        return Decision('defer', reason, now, now + 15)
    try:
        own = {address(v) for v in self_addresses}
        need(bool(own), 'self_addresses_unknown')
        need(type(records) is dict, 'dns_shape')
        reason = records.get('failure')
        if reason is not None:
            need(reason in ('dns_timeout', 'dns_failure', 'no_mx', 'null_mx', 'dns_bound',
                            'address_lookup_failed', 'dns_shape'), 'dns_shape')
            return hold(reason)
        rows = records.get('mx')
        need(type(rows) is list and 0 < len(rows) <= 16, 'mx_count')
        ttls = []
        classified = []
        seen = set()
        for row in rows:
            need(type(row) is dict, 'dns_shape')
            pref, ttl = row.get('preference'), row.get('ttl')
            need(type(pref) is int and 0 <= pref <= 65535, 'dns_shape')
            need(type(ttl) is int and 0 < ttl <= 2147483647, 'dns_ttl')
            host = domain(row.get('host'))
            need((pref, host) not in seen, 'duplicate_mx')
            seen.add((pref, host)); ttls.append(ttl)
            ips = row.get('addresses')
            need(type(ips) is list and 0 < len(ips) <= 32, 'mx_address_count')
            kinds = set()
            for entry in ips:
                need(type(entry) is dict and type(entry.get('ttl')) is int and entry['ttl'] > 0, 'dns_ttl')
                ip = address(entry.get('ip')); ttls.append(entry['ttl'])
                kind = 'self' if ip in own else 'external'
                need(kind == 'self' or ip.is_global and not ip.is_multicast, 'unsafe_mx_address')
                kinds.add(kind)
            need(len(kinds) == 1, 'mixed_host_addresses')
            classified.append((pref, next(iter(kinds))))
        best = min(p for p, _ in classified)
        kinds = {k for p, k in classified if p == best}
        need(len(kinds) == 1, 'mixed_best_mx')
        state = 'internal' if kinds == {'self'} else 'external'
        return Decision(state, 'self_best_mx' if state == 'internal' else 'external_best_mx',
                        now, now + min(min(ttls), 300))
    except (ValueError, TypeError) as exc:
        reason = str(exc)
        if reason not in {'self_addresses_unknown', 'dns_shape', 'mx_count', 'dns_ttl', 'duplicate_mx',
                          'mx_address_count', 'unsafe_mx_address', 'mixed_host_addresses', 'mixed_best_mx'}:
            reason = 'dns_shape'
        return hold(reason)


def request_domain(key):
    need(type(key) is str and len(key.encode()) <= 512 and not any(ord(c) < 32 for c in key), 'invalid_key')
    # socketmap is a pattern table: handle full recipient keys ourselves, no localpart output.
    return domain(key.rsplit('@', 1)[-1])


def route_reply(key, snapshot, now, local_transport):
    need(re.fullmatch(r'lmtp:unix:(?:/?[A-Za-z0-9_-]+)(?:/[A-Za-z0-9_-]+)*', local_transport) is not None,
         'unvalidated_local_transport')
    try:
        name = request_domain(key)
    except ValueError:
        return 'NOTFOUND '
    need(type(snapshot) is dict and type(snapshot.get('domains')) is dict, 'snapshot_shape')
    row = snapshot['domains'].get(name)
    if row is None:
        return 'NOTFOUND '
    if (type(snapshot.get('generated_at')) is not int or not 0 <= now - snapshot['generated_at'] <= 300
            or type(row) is not dict or type(row.get('expires_at')) is not int
            or type(row.get('checked_at')) is not int or row['checked_at'] > now or row['expires_at'] <= now):
        return 'TEMP route_snapshot_expired'
    if row.get('state') == 'internal':
        return 'OK ' + local_transport
    if row.get('state') == 'external':
        return 'OK mx-follow-smtp:' + name
    return 'TEMP route_decision_pending'


def dns_reply(key, self_addresses):
    """Native Postfix DNS reply format; ignore unsafe/self address records only."""
    need(type(key) is str and len(key) <= 4096, 'dns_filter_bound')
    parts = key.split()
    need(len(parts) >= 5 and parts[1].isdigit() and parts[2].upper() == 'IN', 'dns_filter_shape')
    kind = parts[3].upper()
    if kind not in ('A', 'AAAA'):
        need(kind in ('MX', 'TLSA', 'CNAME'), 'dns_filter_type')
        return 'NOTFOUND '
    need(len(parts) == 5, 'dns_filter_shape')
    ip = address(parts[4]); own = {address(v) for v in self_addresses}
    need(bool(own), 'self_addresses_unknown')
    return 'OK IGNORE' if ip in own or not ip.is_global or ip.is_multicast else 'NOTFOUND '


def status_reply(key):
    """Do not turn recipient/auth/TLS failures into success. Only loop races -> retry."""
    if re.fullmatch(r'5\.4\.6 mail for [^\s]+ loops back to myself', key, re.IGNORECASE):
        return 'OK 4.4.6 MX transition detected; delivery deferred'
    return 'NOTFOUND '
