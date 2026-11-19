"""Signed common update for both ordinary and enrolled generation installations."""
import json
import os
from pathlib import Path

from code_update import CodeUpdate, PREFIXES, contract as maintenance_contract
from generation_update import GenerationUpdate
from host_transaction import regular, durable_json
from release import canonical, sha
from update_sources import select as select_source
from availability_plan import select as select_components

DESCRIPTOR = 'blueprint/migrations/adaptive-update-v1.json'
CONTRACT = {'format': 1, 'ordinary': 'code', 'enrolled': 'generation-with-maintenance',
            'registration': 'pin-installed', 'native': 'signed-package-migration'}
REGISTRATION = '/etc/mail-platform/site-generations.json'


def engine_for(payload, root='/'):
    value = json.loads((Path(payload)/DESCRIPTOR).read_bytes())
    if value != CONTRACT:
        raise ValueError('adaptive_update_descriptor')
    path = Path(root)/'etc/mail-platform/availability.json'
    if os.path.lexists(path):
        return HybridGenerationUpdate
    return CodeUpdate


class HybridGenerationUpdate(GenerationUpdate):
    def next_generation(self, version):
        # Retain failed generations as evidence. A new transaction must not
        # collide with those immutable trees when retrying the same release.
        return super().next_generation(version)+'t'+sha(str(self.directory).encode())[:12]

    def new_path_allowed(self, target, config):
        return target.lstrip('/').startswith(PREFIXES) and '..' not in Path(target).parts

    def update_contract(self, receipt, config, changes=None):
        offered = json.loads((self.payload/'blueprint/update-contract.json').read_bytes())
        selected = select_source(offered, receipt['version'])
        names = sorted(config['components'])
        if changes is not None:
            names = sorted({name for name,c in config['components'].items()
                if any(any(p.startswith(r+'/') for r in c['roots']) for p in changes)})
            units = {config['components'][n]['unit'] for n in names}
            names = sorted(n for n,c in config['components'].items() if c['unit'] in units)
        return {'format':2,'from_version':selected['from_version'],'to_version':selected['to_version'],
                'components':names,'configuration_sha256':sha(canonical(config))}

    def select_changes(self, contract, config, changes):
        return select_components(contract,config,changes,shared_closure=True,allow_empty=True)

    def partition_changes(self, changes, config):
        roots = [r for c in config['components'].values() for r in c['roots']]
        self.pending_static = {p:c for p,c in changes.items() if not any(p.startswith(r+'/') for r in roots)}
        return {p:c for p,c in changes.items() if p not in self.pending_static}

    def plan(self):
        result = super().plan()
        offered = json.loads((self.payload/'blueprint/update-contract.json').read_bytes())
        for name in offered.get('optional_units', []):
            if (name not in self.record['old_receipt']['unit_files']
                    and os.path.lexists(self.files.target('/etc/systemd/system/'+name))):
                raise ValueError('update_unregistered_optional_unit:'+name)
        allowed = {'php8.4-fpm.service'}
        maintenance = maintenance_contract(offered,self.record['old_receipt'],allowed)
        # Enrolled web pools own PHP requests. The legacy FPM process is not
        # stopped, restarted or required active by this generation update.
        for action in ('stop','start','reload','health'):
            maintenance[action] = [n for n in maintenance[action] if n != 'php8.4-fpm.service']
        names = set().union(*(set(maintenance[k]) for k in ('pause','stop','start','reload','health')))
        states = {n:self.unit(n) for n in sorted(names)}
        registration = None
        if os.path.lexists(self.files.target(REGISTRATION)):
            raw, meta = self.live(REGISTRATION)
            if meta['uid'] != 0 or meta['mode'] != 0o600:
                raise ValueError('hybrid_registration_trust')
            value = json.loads(raw)
            if value['configuration_sha256'] != self.record['contract']['configuration_sha256']:
                raise ValueError('hybrid_registration_configuration')
            for p,expected in value['static_files'].items():
                if self.live(p)[1] != expected:
                    raise ValueError('hybrid_registered_static_drift:'+p)
            registration = {'value':value,'before':meta}
        self.record.update(static_changes=self.pending_static,maintenance=maintenance,
            before_units=states,last_units=dict(states),operation_started=None,
            maintenance_started=False,maintenance_resumed=False,registration=registration)
        self.save()
        return dict(result,static_files=len(self.pending_static))

    def stage(self):
        result = super().stage()
        bound = self.render(self.record['old_receipt'])
        for p,c in self.record['static_changes'].items():
            raw = bound[c['source']]
            if sha(raw) != c['sha256']:
                raise ValueError('hybrid_static_source_drift')
            path = self.directory/'static-stage'/p.lstrip('/')
            path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            path.write_bytes(raw)
            if path.suffix == '.py':compile(raw,p,'exec')
            if path.suffix in ('.php','.inc'):
                self.commands.run('static_PHP_lint',['/usr/bin/php8.4','-n','-l',str(path)])
        self.record['static_staged']=True;self.save()
        return result

    def quiet(self):
        self.record['maintenance_started']=True;self.save()
        for n in self.record['maintenance']['pause']+self.record['maintenance']['stop']:
            current=self.unit(n)
            if current['ActiveState']=='active':self.operation('stop',n)
            elif self.quiet_state(n,current):
                self.record['last_units'][n]=current;self.save()
            else:raise ValueError('hybrid_actor_not_quiet:'+n)

    def resume(self):
        value=self.record['maintenance']
        for n in value['start']+value['pause']:
            if self.record['before_units'][n]['ActiveState']=='active':self.operation('start',n)
        self.record['maintenance_resumed']=True;self.save()

    def activate(self):
        self.load()
        if self.record['phase']!='staged' or not self.record.get('static_staged'):
            raise ValueError('hybrid_activation_order')
        self.quiet()
        for p,c in self.record['static_changes'].items():
            actual=self.live(p)[1] if os.path.lexists(self.files.target(p)) else None
            if actual!=c['before']:raise ValueError('hybrid_static_CAS:'+p)
            raw=regular(self.directory/'static-stage'/p.lstrip('/'))[0]
            if sha(raw)!=c['sha256']:raise ValueError('hybrid_static_staging_drift')
            m=c['attributes'];self.files.write(p,raw,m['mode'],m['uid'],m['gid'],expected_before=c['before'])
        registered=self.record['registration']
        if registered:
            if self.live(REGISTRATION)[1]!=registered['before']:raise ValueError('hybrid_registration_CAS')
            value=dict(registered['value'],static_files=dict(registered['value']['static_files']))
            for p in value['static_files']:
                if p in self.record['static_changes']:value['static_files'][p]=self.live(p)[1]
            self.files.write(REGISTRATION,canonical(value),0o600)
        result=super().activate()
        self.resume()
        return result

    def updated_generation_receipt(self):
        receipt=super().updated_generation_receipt()
        for p,c in self.record['static_changes'].items():
            current=self.live(p)[1]
            expected=dict(c['attributes'],sha256=c['sha256'])
            if current!=expected:raise ValueError('hybrid_static_health_drift')
            receipt['code'][p]=current
        return receipt

    def health(self):
        self.load()
        for n in self.record['maintenance']['health']:
            if self.record['before_units'][n]['ActiveState']=='active':
                self.commands.run('static_health',['/usr/bin/systemctl','is-active','--quiet',n])
            elif not self.quiet_state(n,self.unit(n)):
                raise ValueError('hybrid_inactive_health_unit_changed')
        return super().health()

    def rollback(self):
        if not self.record_path.exists():return {'phase':'rolled_back','operations':0}
        self.load()
        if self.record.get('operation_started'):raise ValueError('hybrid_service_outcome_unknown')
        for e in self.files.entries:
            if self.files.mark_unapplied(e) or e['phase']=='restored':continue
            if e['phase']!='written' or self.live(e['path'])[1]!=e['after']:
                raise ValueError('hybrid_rollback_unknown_file')
        if self.record.get('maintenance_started'):
            for n,expected in self.record['last_units'].items():
                if self.unit(n)!=expected:raise ValueError('hybrid_rollback_unit_drift')
            self.quiet()
        result=super().rollback()
        if self.record.get('maintenance_started'):self.resume()
        return result
