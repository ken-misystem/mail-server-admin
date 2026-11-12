"""Independent channel state, plus Japanese payloads with finite identifiers.

Pure preparation library, not a worker: the approved caller must lock/validate
and atomically persist this state before invoking any network adapter.
"""
import copy
import re
import alerts as a

CHANNELS = ('email', 'discord')
REASONS = ('message_created', 'message_confirmation_invalid', 'response_bound',
           'rate_limited', 'rate_limit_missing', 'rate_limit_invalid', 'redirect_refused',
           'request_rejected', 'message_confirmation_missing', 'tls_verification_failed',
           'connection_failed', 'post_result_unknown', 'smtp_accepted', 'smtp_retry',
           'smtp_blocked', 'smtp_unknown', 'worker_interrupted')
NAMES = {
    'snapshot/invalid': '監視データの形式異常', 'snapshot/stale': '監視データの更新停止',
    'system_storage/bytes': 'システム領域の空き容量', 'system_storage/inodes': 'システム領域の空きinode',
    'mail_storage/bytes': 'メール領域の空き容量', 'mail_storage/inodes': 'メール領域の空きinode',
    'queue/oldest_queue': '配送キューの滞留時間', 'queue/deferred_count': '配送延期キューの件数',
    'queue/held_queue': '保留キューの存在', 'queue/unexpected_queue': '破損・未分類キューの存在',
    'certificate/expired': 'ローカルTLS証明書の期限切れ',
}
CHECK_NAMES = {'units': 'サービス状態', 'queue': '配送キュー', 'system_storage': 'システム領域',
               'mail_storage': 'メール領域', 'certificate': 'TLS証明書', 'client_certificates': '端末証明書機能'}
UNIT_NAMES = {
    'postfix.service': 'メール配送', 'dovecot.service': 'メール受信・メールボックス接続',
    'mariadb.service': 'データベース', 'rspamd.service': '迷惑メール判定',
    'redis-server.service': '迷惑メール判定用データ', 'nginx.service': 'Web受付',
    'php8.4-fpm.service': 'Webアプリ実行', 'fail2ban.service': '不正接続の遮断',
    'postsrsd.service': '転送メールの送信元書換え', 'ufw.service': 'ファイアウォール',
    'mail-pop-general-dispatch.service': 'POP取得ディスパッチャー',
    'mail-junk-digest-general.service': '迷惑メール日報',
    'mail-pop-general-dispatch.timer': 'POP定期タイマー',
    'mail-junk-digest-general.timer': '迷惑メール日報タイマー',
    'mail-client-cert-network.service': '端末証明書のネットワーク隔離',
    'mail-client-cert-milter.service': '端末証明書の送信者照合',
    'mail-client-cert-coordination.service': '端末証明書の失効調整',
    'mail-client-cert-postfix-backend.service': '端末証明書のSMTP処理',
    'mail-client-cert-dovecot-backend.service': '端末証明書の受信処理',
    'mail-client-cert-issuer.service': '端末証明書の発行処理',
    'mail-client-cert-lifecycle.service': '未取得証明書の自動失効',
    'mail-client-cert-verifier.service': '端末証明書の検証',
    'mail-client-cert-gate.service': '端末証明書の接続ゲート',
    'mail-client-cert-owner.service': '端末証明書の本人管理',
    'mail-client-cert-gate.socket': '端末証明書の接続待受け',
    'mail-client-cert-health.service': '端末証明書・TLS監視',
    'mail-client-cert-health.timer': '端末証明書監視タイマー',
    'mail-legacy-smtp-auth.service': '互換SMTP認証',
    'mail-quota-collect-v1.service': 'メールボックス容量収集',
    'mail-management-log-viewer.service': 'ログ収集',
    'mail-management-log-viewer.timer': 'ログ収集タイマー',
    'mail-domain-routing.service': '配送先照会',
    'mail-domain-routing.socket': '配送先照会ソケット',
    'mail-domain-routing-collect.service': '配送先DNS更新',
    'mail-domain-routing-collect.timer': '配送先DNS更新タイマー',
    'mail-management-alerts-v1.service': '内部障害通知（定期実行）',
    'mail-access-admin-v1.service': '不正アクセス管理',
    'mail-access-admin-v1.socket': '不正アクセス管理ソケット',
    'mail-send-limits-v1.service': '本人単位の送信量制限',
    'mail-send-limits-v1.socket': '送信量制限ソケット',
    'mail-feature-admin-v1.service': '送信停止・配送待ち管理',
    'mail-feature-admin-v1.socket': '送信停止・配送待ち管理ソケット',
    'mail-feature-access-v1.service': '追加のSMTP許否判定',
    'mail-feature-access-v1.socket': 'SMTP許否判定ソケット',
    'mail-feature-config-v1.service': '転送・設定の反映',
    'mail-feature-observer-v1.service': '管理情報・公開DNS収集',
    'mail-feature-observer-v1.timer': '管理情報収集タイマー',
    'mail-feature-rspamd-native-v1.service': 'Rspamd設定照会',
    'mail-feature-rspamd-native-v1.socket': 'Rspamd設定照会ソケット',
    'mail-protection-clamav-v1.service': 'ウイルス検査',
    'mail-protection-definitions-v1.service': 'ウイルス定義更新',
    'mail-protection-definitions-v1.timer': 'ウイルス定義更新タイマー',
    'mail-protection-publish-v1.service': '保護・上流設定の反映',
    'mail-protection-publish-v1.timer': '保護・上流設定の反映タイマー',



    'mail-management-alerts-v1.timer': '内部障害通知タイマー',
}
CERT_NAMES = dict(zip(a.CERT_CODES, (
    '端末証明書サービス停止', '接続ゲートの監視値なし', '接続ゲートの監視値更新停止',
    '接続ゲートの処理異常', '失効リストの期限接近', '失効リストの期限切れ',
    'TLS証明書の期限接近', 'TLS証明書の期限切れ', 'ルートCAの期限接近', 'ルートCAの期限切れ',
    '発行用CAの期限接近', '発行用CAの期限切れ', 'TLS更新反映を未確認', 'TLS証明書元データ異常',
    'TLS更新失敗', '端末証明書の監視失敗', '端末証明書の監視値更新停止')))


def label(key, units):
    if key in NAMES:
        return NAMES[key]
    if key.startswith('snapshot/collection_') and key[len('snapshot/collection_'):] in CHECK_NAMES:
        return CHECK_NAMES[key[len('snapshot/collection_'):]]+'の収集失敗'
    if key.startswith('client_certificates/') and key.split('/', 1)[1] in CERT_NAMES:
        return CERT_NAMES[key.split('/', 1)[1]]
    if key.startswith('units/'):
        unit = key.split('/', 1)[1]
        if unit in units and unit in UNIT_NAMES:
            return UNIT_NAMES[unit]
        dynamic = re.fullmatch(r'mail-pop-source@([1-9][0-9]{0,19})\.service', unit)
        if dynamic and int(dynamic[1]) <= 18446744073709551615:
            return '外部POP定期取得ジョブ'
    raise ValueError('unrecognized_alert_key')


def event_check(event, units):
    a.need(type(event) is dict and type(event.get('id')) is str and re.fullmatch('[a-f0-9]{64}', event['id']), 'event_id')
    a.number(event['created'])
    a.need(type(event['changes']) is list and 1 <= len(event['changes']) <= 512, 'event_changes')
    keys = []
    for change in event['changes']:
        a.need(type(change) is dict and set(change) == {'key', 'before', 'after'}, 'event_change_keys')
        a.need(type(change['key']) is str, 'event_key')
        label(change['key'], units)
        a.need(change['before'] in a.LEVELS and change['after'] in a.LEVELS and change['before'] != change['after'], 'event_level')
        keys.append(change['key'])
    a.need(len(set(keys)) == len(keys), 'duplicate_event_key')


def payload(event, units):
    event_check(event, units)
    levels = {'ok': '正常', 'warning': '警告', 'critical': '重大'}
    when = a.dt.datetime.fromtimestamp(event['created'], a.dt.timezone(a.dt.timedelta(hours=9))).strftime('%Y-%m-%d %H:%M:%S JST')
    head = ['mx.mi-sys.jp：内部障害通知', when, '通知ID：'+event['id']]
    lines = []
    for c in event['changes']:
        line = label(c['key'], units)+'：'+levels[c['before']]+' → '+levels[c['after']]
        if c['after'] == 'ok':
            line += '（復旧）'
        # Keep the original event in private state; never silently split into many posts.
        if len('\n'.join(head+lines+[line])) > 1750:
            break
        lines.append(line)
    remaining = len(event['changes'])-len(lines)
    if remaining:
        lines.append('ほか'+str(remaining)+'項目。詳細は管理画面で確認してください。')
    return {'content': '\n'.join(head+lines), 'allowed_mentions': {'parse': [], 'replied_user': False}}


def initial():
    return {'version': 2, 'last_now': 0, 'events': [], 'submission_times': {c: [] for c in CHANNELS}}


def sync(state, detector_events, units, p):
    """Idempotent fanout. Does not alter the detector's evidence or sent history."""
    s = copy.deepcopy(state)
    a.need(s['version'] == 2 and type(detector_events) is list and len(detector_events) <= p['max_outbox_entries'], 'fanout_shape')
    known = {e['id']: e for e in s['events']}
    for event in detector_events:
        event_check(event, units)
        if any(key in event for key in ('state', 'attempts', 'smtp_code')):
            # Do not reinterpret a historical single-channel delivery as a new
            # pending notification for both channels during future integration.
            a.need(event.get('state') == 'pending' and type(event.get('attempts')) is int and
                   event['attempts'] == 0 and event.get('smtp_code') is None, 'historical_delivery_requires_review')
        public = {k: copy.deepcopy(event[k]) for k in ('id', 'created', 'changes')}
        if event['id'] in known:
            a.need(all(known[event['id']][k] == public[k] for k in public), 'event_changed')
            continue
        a.need(len(s['events']) < p['max_outbox_entries'], 'channel_outbox_full')
        public['deliveries'] = {c: {'state': 'pending', 'attempts': 0, 'next_at': event['created'],
                                    'code': None, 'reason': None, 'message_id': None} for c in CHANNELS}
        s['events'].append(public)
        known[event['id']] = public
    return s


def claim(state, channel, now, p):
    a.need(channel in CHANNELS, 'channel')
    s = copy.deepcopy(state)
    a.number(now)
    a.need(now >= s['last_now'], 'clock_moved_backwards')
    s['last_now'] = now
    times = [t for t in s['submission_times'][channel] if t > now-3600]
    s['submission_times'][channel] = times
    if times and (now-times[-1] < p['submission_min_interval_seconds'] or len(times) >= p['max_submissions_per_hour']):
        return s, None
    for event in s['events']:
        d = event['deliveries'][channel]
        if d['state'] in ('inflight', 'unknown', 'blocked'):
            return s, None
        if d['state'] == 'pending':
            if now < d['next_at']:
                return s, None
            d['state'] = 'inflight'
            d['attempts'] += 1
            s['submission_times'][channel].append(now)
            return s, {k: copy.deepcopy(event[k]) for k in ('id', 'created', 'changes')}
    return s, None


def finish(state, event_id, channel, result, now, p):
    a.need(channel in CHANNELS, 'channel')
    s = copy.deepcopy(state)
    a.number(now)
    a.need(now >= s['last_now'], 'clock_moved_backwards')
    s['last_now'] = now
    event, = [e for e in s['events'] if e['id'] == event_id]
    d = event['deliveries'][channel]
    a.need(d['state'] == 'inflight', 'unclaimed_channel_result')
    outcome, code = result['outcome'], result['code']
    a.need(outcome in ('accepted', 'retry', 'blocked', 'unknown'), 'outcome')
    a.need(code is None or (type(code) is int and 100 <= code <= 599), 'result_code')
    reason = result['reason']
    a.need(reason in REASONS, 'result_reason')
    a.need(outcome != 'accepted' or code == (250 if channel == 'email' else 200), 'acceptance_code')
    a.need(outcome != 'retry' or code is None or (channel == 'email' and 400 <= code < 500) or (channel == 'discord' and code == 429), 'unsafe_retry')
    delay = result.get('retry_after_seconds')
    a.need(delay is None or (type(delay) is int and 1 <= delay <= 86400), 'retry_after')
    message_id = result.get('message_id')
    a.need(message_id is None or (channel == 'discord' and outcome == 'accepted' and type(message_id) is str and re.fullmatch('[1-9][0-9]{0,19}', message_id)), 'message_id')
    if channel == 'discord' and outcome == 'accepted':
        a.need(message_id is not None, 'message_confirmation_required')
    d.update(state=outcome, code=code, reason=reason, message_id=message_id)
    if outcome == 'retry':
        if d['attempts'] >= p['max_attempts']:
            d['state'] = 'blocked'
        else:
            d['state'] = 'pending'
            d['next_at'] = now+max(delay or 0, p['retry_seconds'][d['attempts']-1])
    return s


def interrupted(state):
    """On restart, an unfinished per-channel submission becomes unknown, never pending."""
    s = copy.deepcopy(state)
    for event in s['events']:
        for d in event['deliveries'].values():
            if d['state'] == 'inflight':
                d.update(state='unknown', reason='worker_interrupted')
    return s


def email_result(result):
    """Adapt the already verified SMTP result without rerunning prior SMTP tests."""
    a.need(type(result) is dict and set(result) == {'outcome', 'code', 'phase'}, 'smtp_result')
    a.need(result['outcome'] in ('accepted', 'retry', 'blocked', 'unknown') and
           result['phase'] in ('connecting', 'ehlo', 'mail', 'rcpt', 'data', 'data_command', 'data_end'), 'smtp_projection')
    return {'outcome': result['outcome'], 'code': result['code'], 'reason': 'smtp_'+result['outcome'],
            'retry_after_seconds': None, 'message_id': None}
