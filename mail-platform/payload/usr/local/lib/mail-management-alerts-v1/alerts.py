"""Preparation library: bounded evaluation and durable-outbox transitions; no I/O.

No main, network connection, subprocess, filesystem access or production action.
The caller must persist claim() BEFORE SMTP and finish() AFTER SMTP under one lock.
An interrupted inflight claim is UNKNOWN and must never be reclaimed automatically.
"""
import copy
import datetime as dt
import hashlib
import json
import re
import smtplib

SOURCE_SHA = '353ea8a1c444da78fb25580621feaf027ba3d57289a1dae23d1419d11098f219'
CHECKS = ('units', 'queue', 'system_storage', 'mail_storage', 'certificate', 'client_certificates')
CERT_CODES = ('private_unit_not_active', 'gate_observation_missing', 'gate_observation_stale',
              'gate_threads_failed', 'crl_expiring', 'crl_expired', 'tls_expiring', 'tls_expired',
              'root_ca_expiring', 'root_ca_expired', 'issuer_ca_expiring', 'issuer_ca_expired',
              'tls_reload_unverified', 'tls_source_invalid', 'tls_refresh_failed',
              'health_collection_failed', 'health_snapshot_stale')
LEVELS = {'ok': 0, 'warning': 1, 'critical': 2}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def number(v, low=0, high=2**63-1):
    need(type(v) is int and low <= v <= high, 'invalid_number')
    return v


def decode(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, 'duplicate_json_key')
            out[key] = value
        return out
    need(type(raw) is bytes and len(raw) <= 65536, 'snapshot_bound')
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite_json'))


def timestamp(value):
    need(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00', value), 'timestamp_shape')
    parsed = dt.datetime.fromisoformat(value)
    need(parsed.isoformat() == value, 'timestamp_value')
    return int(parsed.timestamp())


def policy(raw):
    p = decode(raw)
    need(type(p) is dict and type(p.get('version')) is int and p['version'] == 1, 'policy_version')
    need(p.get('recipient') == 'ken@mi-sys.co.jp', 'fixed_recipient')
    # This preparation has no authorized production sender or transport yet.
    need(p.get('enabled') is False and p.get('sender') is None and p.get('transport') is None,
         'delivery_not_prepared')
    names = ('snapshot_max_age_seconds confirm_observations recovery_observations '
             'disk_warning_percent disk_critical_percent disk_warning_bytes disk_critical_bytes '
             'inode_warning_available inode_critical_available deferred_warning_count '
             'queue_warning_age_seconds queue_critical_age_seconds submission_min_interval_seconds '
             'max_submissions_per_hour max_outbox_entries max_attempts').split()
    need(set(p) == set(names) | {'version', 'recipient', 'enabled', 'sender', 'transport', 'retry_seconds'}, 'policy_keys')
    for name in names:
        number(p[name], 1)
    need(1 <= p['disk_critical_percent'] < p['disk_warning_percent'] <= 100, 'percent_order')
    for low, high in (('disk_critical_bytes', 'disk_warning_bytes'),
                      ('inode_critical_available', 'inode_warning_available'),
                      ('queue_warning_age_seconds', 'queue_critical_age_seconds')):
        need(p[low] < p[high], 'threshold_order')
    need(p['max_outbox_entries'] <= 128 and p['max_attempts'] <= 5, 'policy_bound')
    need(type(p['retry_seconds']) is list and len(p['retry_seconds']) == p['max_attempts'], 'retry_shape')
    for n in p['retry_seconds']:
        number(n, 60, 86400)
    return p


def observations(raw, now, p, unit_names, oneshots):
    """Finite projection from the pinned producer; malformed input never recovers.

    A None domain denotes unknown, so a failed check cannot recover its incidents.
    No addresses, native streams or free-form exception text are ever projected.
    """
    number(now)
    try:
        s = decode(raw)
        need(type(s) is dict and s['source_sha256'] == SOURCE_SHA and
             s['operation'] == 'management-operations-read-v1', 'source_pin')
        observed = timestamp(s['observed_utc'])
        need(observed <= now, 'snapshot_future')
        if now-observed > p['snapshot_max_age_seconds']:
            return {'token': now, 'domains': {'snapshot': {'stale': 'critical'}}}
        checks = s['checks']
        need(type(checks) is dict and set(checks) == set(CHECKS), 'check_set')
        result = {'snapshot': {}, **{name: None for name in CHECKS}}
        for name in CHECKS:
            c = checks[name]
            need(type(c) is dict and c['status'] in ('ok', 'fail'), 'check_status')
            if c['status'] == 'fail':
                result['snapshot']['collection_'+name] = 'critical'
                continue
            data = c['data']
            need(type(data) is dict, 'check_data')
            findings = {}
            if name == 'units':
                need(set(unit_names) <= set(data) and len(data) <= len(unit_names)+200, 'unit_count')
                for unit, v in data.items():
                    extra = re.fullmatch(r'mail-pop-source@([1-9][0-9]{0,19})\.service', unit)
                    need(unit in unit_names or (extra and int(extra[1]) <= 18446744073709551615), 'unit_name')
                    need(type(v) is dict and v['load'] in ('loaded', 'not-found', 'error', 'bad-setting', 'masked', 'stub', 'merged', 'other')
                         and v['active'] in ('active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading', 'maintenance', 'refreshing', 'other')
                         and v['result'] in ('', 'success', 'exit-code', 'signal', 'core-dump', 'timeout', 'resources', 'start-limit-hit', 'watchdog', 'protocol', 'condition', 'assert', 'other'), 'unit_values')
                    if v['main_exit'] is not None:
                        number(v['main_exit'], -128, 4294967295)
                    failed = v['load'] != 'loaded' or v['active'] == 'failed' or v['result'] not in ('', 'success') or v['main_exit'] not in (None, 0)
                    inactive = v['active'] != 'active' and (unit.endswith(('.timer', '.socket')) or (unit not in oneshots and extra is None))
                    if failed or inactive:
                        findings[unit] = 'critical'
            elif name in ('system_storage', 'mail_storage'):
                total = number(data['total_bytes'], 1)
                free = number(data['available_bytes'], 0, total)
                inodes = number(data['available_inodes'])
                for label, threshold in (('bytes', free), ('inodes', inodes)):
                    if label == 'bytes':
                        critical = free <= p['disk_critical_bytes'] or free*100 <= total*p['disk_critical_percent']
                        warning = free <= p['disk_warning_bytes'] or free*100 <= total*p['disk_warning_percent']
                    else:
                        critical = threshold <= p['inode_critical_available']
                        warning = threshold <= p['inode_warning_available']
                    if critical or warning:
                        findings[label] = 'critical' if critical else 'warning'
            elif name == 'queue':
                q = data['by_queue']
                need(type(q) is dict and set(q) == set('active deferred hold incoming maildrop corrupt other'.split()), 'queue_keys')
                for n in q.values():
                    number(n, 0, 20000)
                need(sum(q.values()) <= 20000, 'queue_count')
                age = number(data['oldest_age_seconds'], 0, observed)
                if q['corrupt'] or q['other']:
                    findings['unexpected_queue'] = 'critical'
                if q['hold']:
                    findings['held_queue'] = 'warning'
                if sum(q.values()) and age >= p['queue_warning_age_seconds']:
                    findings['oldest_queue'] = 'critical' if age >= p['queue_critical_age_seconds'] else 'warning'
                if q['deferred'] >= p['deferred_warning_count']:
                    findings['deferred_count'] = 'warning'
            elif name == 'client_certificates':
                codes = data['finding_codes']
                need(type(codes) is list and len(codes) <= len(CERT_CODES) and all(type(x) is str and x in CERT_CODES for x in codes)
                     and len(set(codes)) == len(codes), 'cert_codes')
                health_time = timestamp(data['observed_utc'])
                need(health_time <= observed, 'health_future')
                need(data.get('status') in ('ok', 'warning', 'failed') and
                     (data['status'] == 'ok') == (not codes), 'health_status')
                for code in codes:
                    findings[code] = 'warning' if code.endswith('_expiring') else 'critical'
                if now-health_time > 900:
                    findings['health_snapshot_stale'] = 'critical'
            elif name == 'certificate':
                need(type(data['expired']) is bool, 'expired_boolean')
                expiry = timestamp(data['expires_utc'])
                need(data['expired'] == (expiry <= observed), 'expiry_consistency')
                if expiry <= now:
                    findings['expired'] = 'critical'
            result[name] = findings
        return {'token': observed, 'domains': result}
    except (ValueError, TypeError, KeyError, OverflowError, UnicodeError):
        return {'token': now, 'domains': {'snapshot': {'invalid': 'critical'}}}


def initial_state():
    return {'version': 1, 'last_now': 0, 'incidents': {}, 'outbox': [], 'submission_times': []}


def advance(state, observation, now, p):
    """Pure transition; persist returned state atomically before sending anything."""
    s = copy.deepcopy(state)
    number(now)
    need(now >= s['last_now'], 'clock_moved_backwards')
    s['last_now'] = now
    changes = []
    domains = observation['domains']
    token = number(observation['token'], 0, now)
    incidents = s['incidents']
    keys = set(incidents)
    for domain, findings in domains.items():
        if findings is not None:
            keys.update(domain+'/'+name for name in findings)
    for key in sorted(keys):
        domain, name = key.split('/', 1)
        if domain not in domains or domains[domain] is None:
            continue
        if domain == 'snapshot' and name not in domains[domain] and any(
                error in domains[domain] for error in ('stale', 'invalid')):
            # An unreadable/stale snapshot cannot clear a prior collection failure
            # or the other kind of availability failure. Wait for a fresh read.
            continue
        level = domains[domain].get(name, 'ok')
        need(level in LEVELS, 'level')
        item = incidents.get(key, {'pending': 'ok', 'count': 0, 'current': 'ok', 'token': -1})
        if item['token'] == token:
            continue  # Re-reading a single snapshot is not independent confirmation.
        # A stale/invalid observation uses wall-clock time; a fresh recovery uses
        # the producer timestamp, which can be lower. Other domains must advance.
        need(domain == 'snapshot' or token > item['token'], 'observation_moved_backwards')
        item['token'] = token
        item['count'] = min(1000, item['count']+1) if item['pending'] == level else 1
        item['pending'] = level
        required = p['recovery_observations'] if level == 'ok' else p['confirm_observations']
        if item['current'] != level and item['count'] >= required:
            changes.append({'key': key, 'before': item['current'], 'after': level})
            item['current'] = level
        incidents[key] = item
    need(len(incidents) <= 512, 'incident_bound')
    if changes:
        need(len(s['outbox']) < p['max_outbox_entries'], 'outbox_full')
        identity = hashlib.sha256(json.dumps([token, changes], sort_keys=True).encode()).hexdigest()
        s['outbox'].append({'id': identity, 'created': now, 'changes': changes, 'state': 'pending',
                            'attempts': 0, 'next_at': now, 'smtp_code': None})
    # No silent deletion/eviction of history; full state requires explicit maintenance.
    return s


def claim(state, now, p):
    """Reserve BEFORE SMTP. A crashed inflight item cannot be submitted twice."""
    s = copy.deepcopy(state)
    number(now)
    need(now >= s['last_now'], 'clock_moved_backwards')
    s['last_now'] = now
    times = [t for t in s['submission_times'] if t > now-3600]
    s['submission_times'] = times
    if times and (now-times[-1] < p['submission_min_interval_seconds'] or len(times) >= p['max_submissions_per_hour']):
        return s, None
    # Unknown results block subsequent notifications to retain chronological order.
    for item in s['outbox']:
        if item['state'] in ('inflight', 'unknown', 'blocked'):
            return s, None
        if item['state'] == 'pending':
            if item['next_at'] > now:
                return s, None
            item['state'] = 'inflight'
            item['attempts'] += 1
            s['submission_times'].append(now)
            return s, copy.deepcopy(item)
    return s, None


def finish(state, item_id, outcome, code, now, p):
    s = copy.deepcopy(state)
    number(now)
    need(now >= s['last_now'], 'clock_moved_backwards')
    s['last_now'] = now
    need(outcome in ('accepted', 'retry', 'blocked', 'unknown'), 'outcome')
    need(code is None or (type(code) is int and 200 <= code <= 599), 'smtp_code')
    need(outcome != 'accepted' or code == 250, 'acceptance_requires_250')
    need(outcome != 'retry' or code is None or 400 <= code < 500, 'retry_requires_safe_failure')
    item, = [x for x in s['outbox'] if x['id'] == item_id]
    need(item['state'] == 'inflight', 'unclaimed_outcome')
    item['smtp_code'] = code
    item['state'] = outcome
    if outcome == 'retry':
        if item['attempts'] >= p['max_attempts']:
            item['state'] = 'blocked'
        else:
            item['state'] = 'pending'
            item['next_at'] = now+p['retry_seconds'][item['attempts']-1]
    return s


def smtp_submit(smtp_factory, sender, recipient, message):
    """Unconnected adapter testable against REAL smtplib command/data methods.

    Caller selects a separately verified transport. No credentials accepted here.
    A final DATA250 is acceptance even when QUIT fails; not proof of delivery.
    Raw SMTP replies, including addresses, are never returned or logged.
    """
    address = r'[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}@[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?'
    need(type(sender) is str and re.fullmatch(address, sender) and recipient == 'ken@mi-sys.co.jp', 'envelope')
    need(type(message) is bytes and 0 < len(message) <= 16384 and b'\x00' not in message, 'message')
    client = None
    phase = 'connecting'
    try:
        client = smtp_factory()
        for phase, command in (('ehlo', lambda: client.ehlo()), ('mail', lambda: client.mail(sender)), ('rcpt', lambda: client.rcpt(recipient))):
            code, _ = command()
            if code not in ((250, 251) if phase == 'rcpt' else (250,)):
                return {'outcome': 'retry' if 400 <= code < 500 else 'blocked', 'code': code, 'phase': phase}
        phase = 'data'
        # SMTP.data raises SMTPDataError only when DATA is refused before payload.
        # Once data() starts, transport exceptions have an ambiguous acceptance result.
        try:
            code, _ = client.data(message)
        except smtplib.SMTPDataError as exc:
            return {'outcome': 'retry' if 400 <= exc.smtp_code < 500 else 'blocked', 'code': exc.smtp_code, 'phase': 'data_command'}
        return {'outcome': 'accepted' if code == 250 else 'retry' if 400 <= code < 500 else 'blocked', 'code': code, 'phase': 'data_end'}
    except (OSError, smtplib.SMTPException):
        return {'outcome': 'unknown' if phase == 'data' else 'retry', 'code': None, 'phase': phase}
    finally:
        if client is not None:
            try:
                client.quit()
            except (OSError, smtplib.SMTPException):
                try:
                    client.close()
                except (OSError, smtplib.SMTPException):
                    pass
