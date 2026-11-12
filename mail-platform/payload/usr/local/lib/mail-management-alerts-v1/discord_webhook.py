"""Incoming Discord webhook adapter; never executed by importing this module.

Credential acquisition, persistence and unit activation are separate future work.
Only a pre-reviewed caller may pass an actual secret URL and invoke submit().
"""
import http.client
import json
import re
import ssl
from decimal import Decimal, InvalidOperation, ROUND_CEILING

HOST = 'discord.com'
LIMIT = 65536
SNOWFLAKE = re.compile(r'[1-9][0-9]{0,19}\Z')


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


class Endpoint:
    """Never exposes credential material through repr, str or exception text."""
    __slots__ = ('_path',)

    def __init__(self, secret_url):
        need(type(secret_url) is str and len(secret_url) <= 512, 'invalid_discord_endpoint')
        match = re.fullmatch(r'https://discord\.com(/api/(?:v10/)?webhooks/[1-9][0-9]{0,19}/[A-Za-z0-9._-]{20,256})', secret_url)
        need(match is not None, 'invalid_discord_endpoint')
        self._path = match[1]+'?wait=true'

    def __repr__(self):
        return '<DiscordWebhookEndpoint redacted>'

    __str__ = __repr__


def _pairs(items):
    value = {}
    for key, item in items:
        need(key not in value, 'duplicate_json_key')
        value[key] = item
    return value


def _json(raw):
    return json.loads(raw, object_pairs_hook=_pairs,
                      parse_constant=lambda _: need(False, 'nonfinite_json'))


def _delay(value):
    if type(value) not in (int, float, str) or isinstance(value, bool):
        return None
    try:
        number = Decimal(str(value))
        if not number.is_finite() or not 0 <= number <= 86400:
            return None
        return max(1, int(number.to_integral_value(rounding=ROUND_CEILING)))
    except (InvalidOperation, ValueError):
        return None


def classify(status, raw, retry_headers):
    """Only finite diagnostics; never returns a raw HTTP response or token URL."""
    need(type(status) is int and 100 <= status <= 599 and type(raw) is bytes, 'http_shape')
    def result(outcome, reason, delay=None, message_id=None):
        return {'outcome': outcome, 'code': status, 'reason': reason,
                'retry_after_seconds': delay, 'message_id': message_id}
    if len(raw) > LIMIT:
        return result('unknown', 'response_bound')
    if status == 200:
        try:
            value = _json(raw)
            need(type(value) is dict and type(value.get('id')) is str and SNOWFLAKE.fullmatch(value['id']), 'message_identity')
            return result('accepted', 'message_created', message_id=value['id'])
        except (ValueError, TypeError, UnicodeError, RecursionError):
            return result('unknown', 'message_confirmation_invalid')
    if status == 429:
        delays = []
        if len(retry_headers) > 1:
            return result('blocked', 'rate_limit_invalid')
        if retry_headers:
            delay = _delay(retry_headers[0])
            if delay is None:
                return result('blocked', 'rate_limit_invalid')
            delays.append(delay)
        try:
            value = _json(raw)
            if type(value) is dict and 'retry_after' in value:
                delay = _delay(value['retry_after'])
                if delay is None:
                    return result('blocked', 'rate_limit_invalid')
                delays.append(delay)
        except (ValueError, TypeError, UnicodeError, RecursionError):
            pass  # A valid Retry-After header is sufficient even for an HTML body.
        return result('retry', 'rate_limited', max(delays)) if delays else result('blocked', 'rate_limit_missing')
    if 300 <= status < 400:
        return result('blocked', 'redirect_refused')
    if 400 <= status < 500:
        return result('blocked', 'request_rejected')
    # 204 with wait=true, 5xx and unexpected success responses do not prove whether
    # a message was stored. Do not automatically repeat a possibly accepted POST.
    return result('unknown', 'message_confirmation_missing')


def _connection():
    # HTTPSConnection does not use environment proxy variables or follow redirects.
    return http.client.HTTPSConnection(HOST, 443, timeout=10, context=ssl.create_default_context())


def submit(endpoint, payload, connection_factory=None):
    """One POST only. No retries, credential logging, command line or environment."""
    need(type(endpoint) is Endpoint, 'endpoint_type')
    need(type(payload) is dict and set(payload) == {'content', 'allowed_mentions'}, 'payload_keys')
    need(type(payload['content']) is str and 0 < len(payload['content']) <= 1900 and '\x00' not in payload['content'], 'content_bound')
    need(type(payload['allowed_mentions']) is dict and payload['allowed_mentions'] == {'parse': [], 'replied_user': False}
         and payload['allowed_mentions']['replied_user'] is False, 'mentions_disabled')
    raw = json.dumps(payload, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    need(len(raw) <= 16384, 'payload_bound')
    client = None
    phase = 'connecting'
    result = None
    try:
        client = (connection_factory or _connection)()
        client.set_debuglevel(0)
        client.connect()
        phase = 'posting'
        client.request('POST', endpoint._path, body=raw,
                       headers={'Content-Type': 'application/json', 'User-Agent': 'MailServerInternalAlerts/1'})
        response = client.getresponse()
        phase = 'response'
        body = response.read(LIMIT+1)
        result = classify(response.status, body, response.headers.get_all('Retry-After', []))
    except ssl.SSLCertVerificationError:
        result = {'outcome': 'blocked', 'code': None, 'reason': 'tls_verification_failed',
                  'retry_after_seconds': None, 'message_id': None}
    except (OSError, http.client.HTTPException):
        result = {'outcome': 'retry' if phase == 'connecting' else 'unknown', 'code': None,
                  'reason': 'connection_failed' if phase == 'connecting' else 'post_result_unknown',
                  'retry_after_seconds': None, 'message_id': None}
    finally:
        if client is not None:
            try:
                client.close()
            except (OSError, http.client.HTTPException):
                pass  # Cleanup cannot undo a successful message creation response.
    return result
