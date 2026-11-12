"""Crash-safe orchestration around the previously validated alert libraries.

No endpoint, credential or network access here. Store.save must atomically persist
and read back the whole document before any injected adapter may execute.
"""
import copy
import re
import alerts as a
import channel_delivery as delivery

UNITS = tuple(delivery.UNIT_NAMES)


def initial():
    return {'version': 1, 'detector': a.initial_state(), 'delivery': delivery.initial(), 'archived': 0}


def validate(value, p):
    a.need(type(value) is dict and set(value) == {'version', 'detector', 'delivery', 'archived'} and type(value['version']) is int and value['version'] == 1, 'state_wrapper')
    a.number(value['archived'], 0, 4096)
    detector = value['detector']
    a.need(type(detector) is dict and set(detector) == {'version', 'last_now', 'incidents', 'outbox', 'submission_times'} and type(detector['version']) is int and detector['version'] == 1, 'detector_shape')
    a.number(detector['last_now'])
    a.need(detector['submission_times'] == [], 'detector_must_not_submit')
    a.need(type(detector['incidents']) is dict and len(detector['incidents']) <= 512, 'incident_bound')
    for key, v in detector['incidents'].items():
        a.need(type(key) is str, 'incident_key')
        delivery.label(key, UNITS)
        a.need(type(v) is dict and set(v) == {'pending', 'count', 'current', 'token'}, 'incident_shape')
        a.need(v['pending'] in a.LEVELS and v['current'] in a.LEVELS, 'incident_level')
        a.number(v['count'], 0, 1000)
        a.number(v['token'], -1)
    a.need(type(detector['outbox']) is list and len(detector['outbox']) <= p['max_outbox_entries'], 'detector_outbox')
    events = {}
    for event in detector['outbox']:
        delivery.event_check(event, UNITS)
        a.need(set(event) == {'id', 'created', 'changes', 'state', 'attempts', 'next_at', 'smtp_code'} and event['id'] not in events, 'detector_event_shape')
        a.need(event['state'] == 'pending' and type(event['attempts']) is int and event['attempts'] == 0 and event['smtp_code'] is None, 'detector_delivery_state')
        a.number(event['next_at'])
        a.need(event['created'] <= detector['last_now'], 'detector_event_future')
        events[event['id']] = event
    ledger = value['delivery']
    a.need(type(ledger) is dict and set(ledger) == {'version', 'last_now', 'events', 'submission_times'} and type(ledger['version']) is int and ledger['version'] == 2, 'delivery_shape')
    a.number(ledger['last_now'])
    a.need(type(ledger['events']) is list and len(ledger['events']) == len(events), 'delivery_event_count')
    a.need(type(ledger['submission_times']) is dict and set(ledger['submission_times']) == set(delivery.CHANNELS), 'channel_times')
    for times in ledger['submission_times'].values():
        a.need(type(times) is list and len(times) <= p['max_submissions_per_hour'], 'channel_time_bound')
        for t in times:
            a.number(t, 0, ledger['last_now'])
        a.need(times == sorted(times), 'channel_time_order')
    found = set()
    for event in ledger['events']:
        delivery.event_check(event, UNITS)
        a.need(set(event) == {'id', 'created', 'changes', 'deliveries'} and event['id'] in events and event['id'] not in found, 'delivery_event_identity')
        a.need(all(event[k] == events[event['id']][k] for k in ('id', 'created', 'changes')), 'delivery_event_drift')
        found.add(event['id'])
        a.need(type(event['deliveries']) is dict and set(event['deliveries']) == set(delivery.CHANNELS), 'event_channels')
        for channel, result in event['deliveries'].items():
            a.need(type(result) is dict and set(result) == {'state', 'attempts', 'next_at', 'code', 'reason', 'message_id'}, 'channel_result_shape')
            a.need(result['state'] in ('pending', 'inflight', 'accepted', 'unknown', 'blocked'), 'channel_result_state')
            a.number(result['attempts'], 0, p['max_attempts'])
            a.number(result['next_at'])
            a.need(result['code'] is None or type(result['code']) is int and 100 <= result['code'] <= 599, 'channel_result_code')
            a.need(result['reason'] is None or result['reason'] in delivery.REASONS, 'channel_result_reason')
            mid = result['message_id']
            a.need(mid is None or channel == 'discord' and type(mid) is str and re.fullmatch('[1-9][0-9]{0,19}', mid), 'channel_message_id')
            if result['state'] == 'accepted':
                a.need(result['code'] == (250 if channel == 'email' else 200) and result['attempts'] >= 1, 'accepted_state')
                a.need(channel != 'discord' or mid is not None, 'discord_message_identity')
                a.need(result['reason'] == ('smtp_accepted' if channel == 'email' else 'message_created'), 'accepted_reason')
            else:
                a.need(mid is None, 'unaccepted_message_id')
            if result['attempts'] == 0:
                a.need(result['state'] == 'pending' and result['code'] is None and result['reason'] is None, 'unattempted_state')
    return value


def cycle(store, observation, p, enabled, adapters, clock, archive=None):
    """One locked cycle. Each channel can fail without blocking the other.

    Only public outcome dictionaries survive adapter errors. The reserved state
    remains durable on unexpected exceptions; restart converts inflight to unknown.
    """
    a.need(set(enabled) == set(delivery.CHANNELS) and all(type(v) is bool for v in enabled.values()), 'enabled_channels')
    a.need(set(adapters) == {c for c in delivery.CHANNELS if enabled[c]}, 'enabled_adapters')
    state = store.load()
    state = initial() if state is None else validate(state, p)
    state['delivery'] = delivery.interrupted(state['delivery'])
    store.save(validate(state, p))  # Persist recovery before doing anything else.
    if len(state['detector']['outbox']) >= 64 and archive is not None:
        completed = [e for e in state['delivery']['events'] if all(d['state'] == 'accepted' for d in e['deliveries'].values())][:16]
        if completed:
            archived_ids = set()
            for event in completed:
                archive.commit(copy.deepcopy(event))  # Durable, idempotent archive first.
                archived_ids.add(event['id'])
            state['detector']['outbox'] = [e for e in state['detector']['outbox'] if e['id'] not in archived_ids]
            state['delivery']['events'] = [e for e in state['delivery']['events'] if e['id'] not in archived_ids]
            state['archived'] += len(archived_ids)
            store.save(validate(state, p))
    state['detector'] = a.advance(state['detector'], observation, clock(), p)
    state['delivery'] = delivery.sync(state['delivery'], state['detector']['outbox'], UNITS, p)
    store.save(validate(state, p))
    outcomes = {}
    faults = []
    for channel in delivery.CHANNELS:
        if not enabled[channel]:
            outcomes[channel] = 'disabled'
            continue
        state['delivery'], event = delivery.claim(state['delivery'], channel, clock(), p)
        if event is not None:
            item, = [e for e in state['delivery']['events'] if e['id'] == event['id']]
            item['deliveries'][channel].update(code=None, reason=None, message_id=None)
        store.save(validate(state, p))  # Claim must be durable before invoking adapter.
        if event is None:
            outcomes[channel] = 'no_submission'
            continue
        try:
            result = adapters[channel](copy.deepcopy(event))
            next_ledger = delivery.finish(state['delivery'], event['id'], channel, result, clock(), p)
        except Exception as exc:
            # No exception text/traceback/credential is persisted or returned.
            kind = type(exc).__name__
            faults.append({'channel': channel, 'stage': 'adapter_or_result_validation',
                           'error_class': kind if kind in ('OSError', 'TimeoutError', 'ValueError', 'TypeError', 'KeyError', 'ConnectionError', 'PermissionError', 'FileNotFoundError', 'JSONDecodeError') else 'other',
                           'errno': exc.errno if isinstance(exc, OSError) and type(exc.errno) is int else None})
            result = {'outcome': 'unknown', 'code': None,
                      'reason': 'smtp_unknown' if channel == 'email' else 'post_result_unknown'}
            next_ledger = delivery.finish(state['delivery'], event['id'], channel, result, clock(), p)
        state['delivery'] = next_ledger
        store.save(validate(state, p))
        outcomes[channel] = result['outcome']
    return state, outcomes, faults


def summary(state, now, enabled, outcomes):
    """Only aggregate state for a read-only management UI. No webhook or message IDs."""
    issues = {level: sum(v['current'] == level for v in state['detector']['incidents'].values()) for level in ('warning', 'critical')}
    channels = {}
    for channel in delivery.CHANNELS:
        rows = [e['deliveries'][channel] for e in state['delivery']['events']]
        counts = {name: sum(r['state'] == name for r in rows) for name in ('pending', 'inflight', 'accepted', 'unknown', 'blocked')}
        channels[channel] = {'enabled': enabled[channel], 'counts': counts,
                             'last_cycle': outcomes[channel]}
    return {'version': 1, 'observed_at': a.number(now), 'issues': issues, 'channels': channels, 'archived_events': state['archived'],
            'mailbox_delivery_verified': False, 'external_liveness_monitoring': False}
