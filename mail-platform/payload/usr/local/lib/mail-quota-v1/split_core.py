"""Separate private readiness from fresh public observations. No I/O or native calls."""
import copy
import math
from collector_core import inventory,integer
from scale_core import fresh_records,rotate,finish,need,BATCH,FAIR,TTL

PERIOD=12
WARM_BUDGET=9
COLD_BUDGET=30
MAX_RECONNECT=2


def binding(row):return {'email':row['email'],'quota_bytes':row['quota_bytes']}


def reconcile(rows,snapshot,state,readiness,generation,now):
    current=inventory(rows)
    need(len({r['email']for r in current.values()})==len(current),'duplicate_email')
    need(all(not r['email'].startswith('-')and r['quota_bytes']%1024==0 for r in current.values()),'identity_or_alignment')
    need(state.get('version')==1 and state.get('deployment_hash')==generation and type(state.get('applied'))is dict,'state_generation')
    if readiness is None:
        # Only an actual, correctly bound previous observation can seed readiness. initial_applied alone cannot.
        seeds={}
        if snapshot.get('version')==1 and snapshot.get('deployment_hash')==generation and snapshot.get('enforcement_verified')is True:
            for key,record in snapshot.get('records',{}).items():
                row=current.get(key)
                if row and type(record)is dict and state['applied'].get(key)==binding(row)and record.get('id')==key and record.get('email')==row['email']and type(record.get('configured_bytes'))is int and record['configured_bytes']==row['quota_bytes']and type(record.get('effective_bytes'))is int and record['effective_bytes']==row['quota_bytes']and type(record.get('observed_at'))is int and 0<=record['observed_at']<=now and type(record.get('used_bytes_upper_bound'))is int and 0<=record['used_bytes_upper_bound']<=2**63-1:
                    seeds[key]=binding(row)
        readiness={'version':1,'deployment_hash':generation,'ready':seeds,'retry':{},'cursor':'0'}
    need(readiness.get('version')==1 and readiness.get('deployment_hash')==generation and type(readiness.get('ready'))is dict and type(readiness.get('retry'))is dict,'readiness_generation')
    ready={key:binding(row)for key,row in current.items()if readiness['ready'].get(key)==binding(row)}
    retry={key:dict(value)for key,value in readiness['retry'].items()if key in current and type(value)is dict and value.get('binding')==binding(current[key])and type(value.get('at'))is int and type(value.get('attempts'))is int and 1<=value['attempts']<=1000000}
    return current,{'version':1,'deployment_hash':generation,'ready':ready,'retry':retry,'cursor':str(integer(readiness['cursor']))}


def accept_preparation(current,state,readiness,proof,generation,config_hashes,now):
    updated=copy.deepcopy(readiness)
    need(type(proof)is dict and proof['generation']==generation and proof['config_hashes']==config_hashes,'preparation_context')
    rows=inventory([{**r,'active':1,'domain_active':1}for r in proof['rows']])
    need(0<len(rows)<=BATCH and type(proof['ready'])is list and len(proof['ready'])==len(set(proof['ready']))and set(proof['ready'])<=set(rows)and set(proof['previous'])==set(rows),'preparation_scope')
    accepted=0
    for key,requested in rows.items():
        updated['cursor']=key
        row=current.get(key)
        if row is None or row!=requested or state['applied'].get(key)!=proof['previous'][key]:continue
        if key in proof['ready']:
            updated['ready'][key]=binding(row);updated['retry'].pop(key,None);accepted+=1
        else:
            updated['ready'].pop(key,None)
            count=min(1000000,updated['retry'].get(key,{}).get('attempts',0)+1)
            updated['retry'][key]={'binding':binding(row),'attempts':count,'at':now+min(900,30*2**min(count-1,5))}
    return updated,accepted


def plan(current,snapshot,state,readiness,generation,now):
    records=fresh_records(current,snapshot,generation,now)
    eligible=set(readiness['ready'])
    for key in set(records)-eligible:records.pop(key)
    ordered=rotate(eligible,state.get('cursor','0'));fair=ordered[:FAIR]
    priority=sorted([k for k in ordered if k not in set(fair)],key=lambda k:(records.get(k,{}).get('observed_at',-1),int(k)))[:BATCH-len(fair)]
    warm=fair+priority
    cold=[];reconnect=0
    for key in rotate(set(current)-eligible,readiness['cursor']):
        if readiness['retry'].get(key,{}).get('at',0)>now:continue
        needs=state['applied'].get(key)!=binding(current[key])
        if needs and reconnect>=MAX_RECONNECT:continue
        cold.append(key);reconnect+=int(needs)
        if len(cold)==BATCH:break
    return {'current':current,'records':records,'applied':{k:v for k,v in state['applied'].items()if k in current},'selected':warm,'rebind':[],
            'cursor':fair[-1]if fair else state.get('cursor','0'),'pending_cursor':'0','pending_count':len(current)-len(eligible),
            'started_at':now,'generation':generation,'cold':cold}


def publish(plan_value,readiness,observations,errors,observed_at,finished_at):
    out=finish(plan_value,observations,errors,observed_at,finished_at)
    readiness=copy.deepcopy(readiness)
    # A slow/bad warm group goes to the preparation queue; it never poisons the remaining warm groups.
    for key in set(plan_value['selected'])-set(out['snapshot']['records']):
        readiness['ready'].pop(key,None)
    out['readiness']=readiness
    count=len(plan_value['current']);pending=count-len(readiness['ready'])
    forecast=math.ceil(len(readiness['ready'])/FAIR)*PERIOD+WARM_BUDGET if count else 0
    report=out['report'];report.update(bootstrap_pending=pending,ready_accounts=len(readiness['ready']),period_seconds=PERIOD,
        forecast_refresh_bound_seconds=forecast,capacity_within_expiry=(pending==0 and forecast<TTL and report['complete']and report['status']=='ok'),
        freshness_assumption='valid bound readiness; warm cycles <=9s and start interval <=12s; failures remain unverified')
    report.pop('rebind_backlog_seconds_at_budget',None);report.pop('projected_sweep_seconds_at_budget',None)
    return out
