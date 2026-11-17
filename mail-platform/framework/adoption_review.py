"""Read-only production dependency/protection contract for initial adoption."""
import json
from pathlib import Path
from host_transaction import regular
from release import canonical, sha

STOP_EDGES = ('RequiredBy','RequisiteOf','BoundBy','ConsistsOf','PropagatesStopTo')
DEPENDENCIES = (*STOP_EDGES,'Requires','BindsTo','PartOf','Triggers','TriggeredBy','Conflicts')
STABLE = ('LoadState','ActiveState','SubState','UnitFileState','MainPID')
CORE = {'mariadb.service','redis-server.service','nginx.service','rspamd.service',
        'mail-reputation-dns-v1.service','ssh.service','postsrsd.service','fail2ban.service',
        'mail-client-cert-network.service','mail-client-cert-coordination.service'}

def require(condition, reason):
    if not condition:raise ValueError(reason)

def compile_contract(snapshot, tested):
    require(snapshot['status']=='PASS' and snapshot['host']=='mx.mi-sys.jp','adoption_review_host')
    units=snapshot['units'];loaded={n:r for n,r in units.items() if r['LoadState']=='loaded'}
    stop=[n for n in tested['stop'] if n in loaded]
    start=[n for n in tested['start'] if n in loaded]
    pause=sorted(n for n in loaded if n.endswith('.timer') and not n.startswith('mail-backup-'))
    drain=[]
    for name in pause:
        for worker in loaded[name].get('Triggers','').split():
            require(worker in loaded,'adoption_timer_worker_unknown')
            if loaded[worker].get('Type')=='oneshot':drain.append(worker)
            else:require(worker in stop,'adoption_timer_daemon_uncontrolled')
    drain=sorted(set(drain))
    mutated=set(stop+pause)
    require(not mutated&CORE and not any(n.startswith('mail-backup-') for n in mutated),'adoption_protected_mutation')
    require(set(stop)==set(start),'adoption_review_start_inventory')
    for name in stop:
        for trigger in loaded[name].get('TriggeredBy','').split():
            if trigger.endswith('.socket'):
                require(trigger in stop and stop.index(trigger)<stop.index(name),'adoption_review_socket_order')
    closure=set(mutated);pending=list(mutated)
    while pending:
        name=pending.pop()
        require(name in units,'adoption_stop_dependency_unknown')
        for field in STOP_EDGES:
            for other in units[name].get(field,'').split():
                if other not in closure:closure.add(other);pending.append(other)
    implicit=sorted(closure-mutated)
    for name in implicit:
        require(units[name]['ActiveState']=='inactive' and units[name].get('MainPID','0')=='0'
                and units[name].get('Job','')=='','adoption_implicit_dependency_active')
        require(name in ('postfix@-.service','mail-client-certificates.target'),'adoption_implicit_dependency_scope')
    protections={}
    for name,row in loaded.items():
        if name in mutated or name in drain:continue
        mode='natural' if row.get('Type')=='oneshot' or name.endswith('.timer') else 'stable'
        protections[name]={'mode':mode,'before':{k:row.get(k,'0' if k=='MainPID' else '') for k in STABLE}}
    for name in CORE:require(name in protections,'adoption_core_protection_missing')
    protected=[n for n,r in protections.items() if r['mode']=='stable' and n.endswith(('.service','.socket'))]
    services={'stop':stop,'start':start,'pause':pause,'drain':drain,'protected':sorted(protected)}
    definitions={}
    for name in protections:
        row=loaded[name]
        for path in [row.get('FragmentPath',''),*row.get('DropInPaths','').split()]:
            if path:definitions[path]=snapshot['files'][path]
    dependencies={n:{k:sorted(row.get(k,'').split()) for k in DEPENDENCIES} for n,row in units.items()}
    return {'format':1,'host':snapshot['host'],'services':services,'protections':protections,
            'definition_guards':definitions,'dependency_guards':dependencies,
            'implicit_inactive':implicit,'observed_at':snapshot['finished'],
            'definition_sha256':sha(canonical(snapshot['files']))}

def check_protections(contract, observations):
    require(set(observations)==set(contract['protections']),'adoption_protection_inventory')
    for name,policy in contract['protections'].items():
        value=observations[name];before=policy['before']
        require(value['LoadState']==before['LoadState'] and value['UnitFileState']==before['UnitFileState'],'adoption_protection_registration_changed')
        if policy['mode']=='stable':
            require(all(value.get(k,'0' if k=='MainPID' else '')==v for k,v in before.items()),'adoption_protected_identity_changed')
        elif name.endswith('.timer'):
            require(value['ActiveState']==before['ActiveState'] and value['SubState'] in ('waiting','running','dead'),'adoption_protected_timer_changed')
        else:
            require(value['ActiveState'] in ('inactive','active','activating','deactivating'),'adoption_protected_worker_failed')
    return {'status':'PASS','protected':len(observations)}

def check_dependencies(contract, observations):
    require(set(observations)==set(contract['dependency_guards']),'adoption_dependency_inventory')
    for name,expected in contract['dependency_guards'].items():
        require({k:sorted(observations[name].get(k,'').split()) for k in DEPENDENCIES}==expected,'adoption_dependency_drift')
    return {'status':'PASS'}

class Protection:
    """No mutations. Called at each host transaction boundary, including recovery."""
    def __init__(self, contract, commands):self.contract=contract;self.commands=commands
    def __call__(self, stage):
        if stage in ('preflight','quiesced'):
            raw=self.commands.run('dynamic_units_'+stage,['/usr/bin/systemctl','list-units','--all','--plain','--no-legend','mail-pop-*','mail-residual-pop-*'])
            discovered={line.split()[0] for line in raw.decode().splitlines() if line.strip()}
            require(discovered <= set(self.contract['dependency_guards']),'adoption_new_POP_worker')
        names=sorted(self.contract['protections'])
        fields='Id,'+','.join(STABLE)
        raw=self.commands.run('protection_'+stage,['/usr/bin/systemctl','show',*names,'-p',fields])
        observed={}
        for block in raw.decode().strip().split('\n\n'):
            row=dict(line.split('=',1) for line in block.splitlines())
            require(row['Id'] not in observed,'adoption_duplicate_protection');observed[row['Id']]=row
        result=check_protections(self.contract,observed)
        for name,expected in self.contract['definition_guards'].items():
            path=Path(name);require(str(path.resolve(strict=True))==expected['realpath'],'adoption_definition_alias_changed')
            _,metadata=regular(path.resolve(strict=True))
            require(metadata=={k:expected[k] for k in ('sha256','uid','gid','mode')},'adoption_protected_definition_changed')
        if stage=='preflight':
            names=sorted(self.contract['dependency_guards'])
            raw=self.commands.run('dependency_preflight',['/usr/bin/systemctl','show',*names,'-p','Id,'+','.join(DEPENDENCIES)])
            rows={}
            for block in raw.decode().strip().split('\n\n'):
                row=dict(line.split('=',1) for line in block.splitlines())
                require(row['Id'] not in rows,'adoption_duplicate_dependency');rows[row['Id']]=row
            check_dependencies(self.contract,rows)
        return result
