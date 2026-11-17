"""Bounded systemd barrier for first adoption; never changes enablement.

The reviewed contract is an ordered subset of installed product units. A pending
or failed operation is not retried, including after a process interruption.
"""
import json
import re
import time
from pathlib import Path

from host_transaction import Commands, durable_json, regular

PROTECTED = {'mariadb.service', 'redis-server.service', 'ssh.service',
             'nginx.service', 'rspamd.service', 'mail-reputation-dns-v1.service'}
SYSTEM = {'postfix.service', 'dovecot.service', 'php8.4-fpm.service'}
FIELDS = 'LoadState,ActiveState,SubState,MainPID,Job,UnitFileState'


def validate_contract(value, installed):
    if set(value) != {'pause', 'drain', 'stop', 'start', 'protected'}:
        raise ValueError('adoption_service_contract_fields')
    allowed = set(installed) | SYSTEM | PROTECTED
    for field, names in value.items():
        if type(names) is not list or len(names) != len(set(names)):
            raise ValueError('adoption_service_contract_list')
        if any(type(n) is not str or not re.fullmatch(r'[a-zA-Z0-9_.@-]+\.(service|socket|timer)', n)
               or n not in allowed for n in names):
            raise ValueError('adoption_service_scope')
    if set(value['stop']) != set(value['start']):
        raise ValueError('adoption_service_order_inventory')
    mutated = set(value['pause'] + value['stop'])
    if (mutated & (PROTECTED | set(value['protected']))
            or any(n.startswith('mail-backup-') for n in mutated)
            or set(value['pause']) & set(value['stop'])
            or any(not n.endswith('.timer') for n in value['pause'])
            or any(not n.endswith('.service') for n in value['drain'])):
        raise ValueError('adoption_service_preservation')
    # Socket activation must be closed before its worker is stopped.
    for socket_name, worker in (
        ('mail-client-cert-gate.socket', 'mail-client-cert-gate.service'),
        ('mail-send-limits-v1.socket', 'mail-send-limits-v1.service'),
        ('mail-feature-admin-v1.socket', 'mail-feature-admin-v1.service')):
        if worker in value['stop'] and (socket_name not in value['stop']
                or value['stop'].index(socket_name) > value['stop'].index(worker)):
            raise ValueError('adoption_socket_stop_order')
    return value


class ServiceBarrier:
    def __init__(self, evidence, contract, installed, commands=None):
        self.path = Path(evidence)
        self.contract = validate_contract(contract, installed)
        self.commands = commands or Commands(self.path)
        self.commands.sequence = len(list(self.path.glob('[0-9][0-9][0-9][0-9]-*.json')))
        self.record = None

    def save(self):
        durable_json(self.path/'services.json', self.record)

    def load(self):
        raw, attr = regular(self.path/'services.json')
        if attr['uid'] != 0 or attr['mode'] != 0o600:
            raise ValueError('adoption_service_journal_trust')
        self.record = json.loads(raw)
        if self.record['contract'] != self.contract:
            raise ValueError('adoption_service_journal_contract')

    def state(self, name):
        raw = self.commands.run('unit_state', ['/usr/bin/systemctl', 'show', name, '-p', FIELDS])
        result = dict(line.split('=', 1) for line in raw.decode().splitlines())
        if name.endswith(('.socket', '.timer')):
            result.setdefault('MainPID', '0')
        if not set(FIELDS.split(',')) <= set(result) or result['LoadState'] != 'loaded':
            raise ValueError('adoption_unit_not_loaded')
        # Socket/timer SubState can change naturally without a new activation.
        # The raw observation remains in the command evidence.
        if result['ActiveState'] == 'active':
            if name.endswith('.socket') and result['SubState'] in ('running', 'listening'):
                result['SubState'] = 'listening'
            if name.endswith('.timer') and result['SubState'] in ('running', 'waiting'):
                result['SubState'] = 'waiting'
        return result

    def settled(self, name, seconds=30):
        deadline = time.monotonic()+seconds
        while True:
            value = self.state(name)
            if value['Job'] in ('', '0') and value['ActiveState'] in ('active', 'inactive'):
                return value
            if value['ActiveState'] == 'failed' or time.monotonic() >= deadline:
                raise ValueError('adoption_unit_not_settled')
            time.sleep(0.2)

    def snapshot(self):
        if (self.path/'services.json').exists():
            raise ValueError('adoption_service_journal_exists')
        names = sorted(set(sum(self.contract.values(), [])))
        states = {name:self.settled(name) for name in names}
        self.record = {'format':1, 'contract':self.contract, 'before':states,
                       'last':states.copy(), 'pending':None, 'phase':'prepared', 'operations':[]}
        self.save()
        return {'status':'PASS', 'units':len(states)}

    def guard(self):
        if self.record['pending']:
            raise ValueError('adoption_unfinished_service_operation')
        for name in self.contract['protected']:
            if self.settled(name) != self.record['before'][name]:
                raise ValueError('adoption_protected_service_changed')
        for name, before in self.record['before'].items():
            if self.state(name)['UnitFileState'] != before['UnitFileState']:
                raise ValueError('adoption_unit_enablement_changed')

    def operation(self, action, name):
        self.guard()
        current = self.settled(name)
        if current != self.record['last'][name]:
            # Previously closed sockets can make an inactive dependent stop too.
            if not (current['ActiveState'] == 'inactive' and current['MainPID'] == '0'
                    and current['UnitFileState'] == self.record['before'][name]['UnitFileState']):
                raise ValueError('adoption_unit_drift')
        desired = 'active' if action == 'start' else 'inactive'
        if current['ActiveState'] == desired:
            self.record['last'][name] = current
            self.save()
            return
        self.record['pending'] = {'action':action, 'unit':name, 'before':current}
        self.save()  # A crash or timeout leaves an explicit, non-retryable intent.
        self.commands.run('unit_'+action, ['/usr/bin/systemctl', action, '--quiet', name], timeout=120)
        result = self.settled(name)
        if result['ActiveState'] != desired or (action == 'stop' and result['MainPID'] != '0'):
            raise ValueError('adoption_unit_operation_incomplete')
        observed = {unit:self.settled(unit) for unit in self.contract['stop']}
        for unit, value in observed.items():
            previous = self.record['last'][unit]
            if unit == name or value == previous:
                continue
            if not ((action == 'stop' and value['ActiveState'] == 'inactive' and value['MainPID'] == '0')
                    or (action == 'start' and value['ActiveState'] == 'active'
                        and previous['ActiveState'] == 'inactive'
                        and self.record['before'][unit]['ActiveState'] == 'active')):
                raise ValueError('adoption_unexpected_unit_dependency_transition')
        self.record['operations'].append(dict(self.record['pending'], after=result, observed=observed))
        self.record['last'].update(observed)
        self.record['last'][name] = result
        self.record['pending'] = None
        self.save()

    def quiesce(self):
        self.load()
        if self.record['phase'] != 'prepared':
            raise ValueError('adoption_quiesce_phase')
        self.record['phase'] = 'quiescing'; self.save()
        for name in self.contract['pause']:
            self.operation('stop', name)
        for name in self.contract['drain']:
            deadline = time.monotonic()+120
            while True:
                state = self.settled(name)
                if state['ActiveState'] == 'inactive' and state['MainPID'] == '0':
                    self.record['last'][name] = state; self.save(); break
                if time.monotonic() >= deadline:
                    raise ValueError('adoption_worker_did_not_drain')
                time.sleep(0.25)
        for name in self.contract['stop']:
            self.operation('stop', name)
        self.guard()
        self.record['phase'] = 'quiesced'; self.save()
        return {'status':'PASS', 'operations':len(self.record['operations'])}

    def reload_definitions(self):
        self.guard()
        self.record['pending'] = {'action':'daemon-reload'}; self.save()
        self.commands.run('daemon_reload', ['/usr/bin/systemctl', 'daemon-reload'], timeout=60)
        self.record['pending'] = None; self.save()

    def resume(self, *, restored=False):
        self.load(); self.guard()
        if self.record['phase'] not in ('quiesced', 'quiescing'):
            raise ValueError('adoption_resume_phase')
        self.record['phase'] = 'resuming'; self.save()
        self.reload_definitions()
        # Only states saved before the barrier determine which units are started.
        for name in self.contract['start']+self.contract['pause']:
            if self.record['before'][name]['ActiveState'] == 'active':
                self.operation('start', name)
        self.record['phase'] = 'restored' if restored else 'resumed'; self.save()
        return self.verify()

    def verify(self):
        self.load(); self.guard()
        for name in self.contract['pause']+self.contract['stop']:
            actual = self.settled(name)
            before = self.record['before'][name]
            if actual['ActiveState'] != before['ActiveState'] or actual['UnitFileState'] != before['UnitFileState']:
                raise ValueError('adoption_resumed_state_mismatch')
            self.record['last'][name] = actual
        self.save()
        return {'status':'PASS', 'phase':self.record['phase'], 'enablement_preserved':True}

    def recovery_preflight(self, record):
        self.load(); self.guard()
        if self.record['phase'] not in ('quiesced', 'quiescing'):
            raise ValueError('adoption_service_recovery_phase')
        return {'status':'PASS'}
