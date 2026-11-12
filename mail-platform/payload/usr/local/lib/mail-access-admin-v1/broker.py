"""Narrow Fail2Ban administration API for the authenticated mail admin frontend."""
import datetime
import hashlib
import ipaddress
import json
import re
import time

JAILS = ('dovecot', 'postfix-sasl', 'roundcube-auth', 'sshd', 'recidive')
REASONS = ('legitimate_user', 'configuration_fixed', 'operator_review')
MAX_BANS = 10000


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def address(value):
    require(type(value) is str and '%' not in value, 'ip_required')
    ip = ipaddress.ip_address(value)
    require(str(ip) == value, 'canonical_ip_required')
    return value


def ban_rows(jail, rows):
    require(type(rows) is list and len(rows) <= MAX_BANS, 'ban_list_bound')
    result = []
    seen = set()
    pattern = re.compile(r'([0-9a-fA-F:.]+)\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \+ (-?\d{1,12}) = (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)$')
    for raw in rows:
        require(type(raw) is str and len(raw) < 256, 'ban_row_shape')
        match = pattern.fullmatch(raw)
        require(match is not None, 'ban_time_shape')
        ip, started, duration, ends = match.groups()
        ip = str(ipaddress.ip_address(ip))
        require(ip not in seen, 'duplicate_ban')
        seen.add(ip)
        datetime.datetime.strptime(started, '%Y-%m-%d %H:%M:%S')
        datetime.datetime.strptime(ends, '%Y-%m-%d %H:%M:%S')
        duration = int(duration)
        require(duration == -1 or duration >= 0, 'ban_duration')
        result.append({'jail': jail, 'ip': ip, 'started': started,
                       'duration': duration, 'ends': ends,
                       'token': hashlib.sha256((jail + '\n' + raw).encode()).hexdigest()})
    return result


class Broker:
    def __init__(self, command, audit, clock=time.time):
        self.command = command
        self.audit = audit
        self.clock = clock
        self.cached = None
        self.cached_at = 0

    def bans(self, jail):
        require(jail in JAILS, 'jail_not_allowed')
        return ban_rows(jail, self.command(['get', jail, 'banip', '--with-time']))

    def overview(self):
        now = int(self.clock())
        if self.cached is not None and 0 <= now - self.cached_at < 30:
            return self.cached
        active_text = dict(self.command(['status']))['Jail list']
        require(type(active_text) is str and len(active_text) <= 4096, 'active_jails_shape')
        active = [name.strip() for name in active_text.split(',') if name.strip()]
        require(len(active) <= 64 and len(set(active)) == len(active)
                and all(re.fullmatch(r'[A-Za-z0-9_-]{1,80}', name) for name in active), 'active_jails_names')
        rows, bans = [], []
        for jail in JAILS:
            if jail not in active:
                rows.append({'jail': jail, 'active': False})
                continue
            status = dict(self.command(['status', jail]))
            filters, actions = dict(status['Filter']), dict(status['Actions'])
            values = {'failed_current': filters['Currently failed'], 'failed_total': filters['Total failed'],
                      'banned_current': actions['Currently banned'], 'banned_total': actions['Total banned']}
            for field in ('findtime', 'maxretry', 'bantime'):
                values[field] = self.command(['get', jail, field])
            require(all(type(v) is int and -1 <= v <= 10**15 for v in values.values()), 'counter_shape')
            rows.append({'jail': jail, 'active': True, **values})
            bans.extend(self.bans(jail))
            require(len(bans) <= MAX_BANS, 'total_bans_bound')
        self.cached = {'observed_at': now, 'timezone': time.strftime('%z'), 'jails': rows, 'bans': bans,
                       'unlisted_jails': len(set(active) - set(JAILS)), 'audit': self.audit.recent(100)}
        self.cached_at = now
        return self.cached

    def unban(self, request):
        require(set(request) == {'operation', 'id', 'actor', 'jail', 'ip', 'token', 'reason', 'issued_at'}, 'request_fields')
        require(type(request['id']) is str and re.fullmatch(r'[a-f0-9]{32}', request['id']), 'request_id')
        require(type(request['actor']) is str and re.fullmatch(r'[1-9][0-9]{0,19}', request['actor']), 'actor_id')
        require(request['jail'] in JAILS and request['reason'] in REASONS, 'operation_scope')
        require(type(request['token']) is str and re.fullmatch(r'[a-f0-9]{64}', request['token']), 'ban_token')
        address(request['ip'])
        require(type(request['issued_at']) is int and 0 <= self.clock() - request['issued_at'] <= 120, 'expired_request')
        previous = self.audit.lookup(request['id'])
        if previous:
            require(previous['request'] == request, 'reused_request_id')
            return previous.get('result', {'state': 'unknown'})
        current = next((row for row in self.bans(request['jail']) if row['ip'] == request['ip']), None)
        if current is not None:
            require(current['token'] == request['token'], 'ban_changed')
        # The durable intent precedes the privileged operation. An incomplete intent
        # is returned as unknown on retry, so the command is never replayed.
        self.audit.append({'id': request['id'], 'request': request, 'at': int(self.clock())})
        result = {'state': 'already_absent'}
        try:
            if current is not None:
                changed = self.command(['set', request['jail'], 'unbanip', request['ip']])
                require(type(changed) is int and changed in (0, 1), 'unban_reply')
                remaining = any(row['ip'] == request['ip'] for row in self.bans(request['jail']))
                result = {'state': 'still_banned' if remaining else 'released'}
        except Exception:
            result = {'state': 'unknown'}
        finally:
            self.cached = None
        self.audit.append({'id': request['id'], 'result': result, 'at': int(self.clock())})
        return result

    def handle(self, request):
        require(type(request) is dict, 'request_shape')
        if request == {'operation': 'overview'}:
            return self.overview()
        require(request.get('operation') == 'unban', 'operation_not_allowed')
        return self.unban(request)
