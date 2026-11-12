"""Batched observation policy. Preserve the installed 120-second expiry and exact identity/limit binding."""
import math
import re
from collector_core import inventory, integer
from binding import quota_tab

TTL=120
BATCH=128
FAIR=112
REBIND=2
SUCCESSFUL_CYCLE_SECONDS=10


def need(ok,reason):
    if not ok:raise ValueError(reason)


def fresh_records(current,old,generation,now):
    need(type(old)is dict,'snapshot_shape')
    if old.get('version')!=1 or old.get('deployment_hash')!=generation or old.get('enforcement_verified')is not True:return {}
    records=old.get('records');need(type(records)is dict and len(records)<=10000,'snapshot_records')
    out={}
    for key,r in records.items():
        row=current.get(key)
        if row is None or type(r)is not dict:continue
        if any(r.get(a)!=b for a,b in [('id',key),('email',row['email']),('configured_bytes',row['quota_bytes']),('effective_bytes',row['quota_bytes'])]):continue
        if type(r.get('observed_at'))is not int or not now-TTL<r['observed_at']<=now:continue
        if type(r.get('used_bytes_upper_bound'))is not int or not 0<=r['used_bytes_upper_bound']<=2**63-1:continue
        out[key]=dict(r)
    return out


def rotate(keys,cursor):
    cursor=integer(cursor)
    keys=sorted(keys,key=int)
    return [k for k in keys if int(k)>cursor]+[k for k in keys if int(k)<=cursor]


def prepare(rows,old,state,generation,now):
    now=integer(now);need(type(generation)is str and re.fullmatch('[a-f0-9]{64}',generation)is not None,'generation')
    current=inventory(rows)
    need(all(not x['email'].startswith('-')for x in current.values()),'email_option_prefix')
    need(len({x['email']for x in current.values()})==len(current),'duplicate_email')
    need(all(x['quota_bytes']%1024==0 for x in current.values()),'limit_alignment')
    need(type(state)is dict and type(state.get('applied'))is dict,'state_applied')
    need(state.get('version')==1 and state.get('deployment_hash')==generation,'state_generation')
    records=fresh_records(current,old,generation,now)
    applied={k:v for k,v in state['applied'].items()if k in current}
    pending={k for k,row in current.items()if applied.get(k)!={'email':row['email'],'quota_bytes':row['quota_bytes']}}
    # A changed/unknown identity never keeps an editable observation, even while awaiting reconnect.
    for key in pending:records.pop(key,None)
    pending_order=rotate(pending,state.get('pending_cursor','0'))
    rebind=pending_order[:REBIND]
    ordered=rotate(set(current)-pending,state.get('cursor','0'))
    fair=ordered[:FAIR]
    remaining=[k for k in ordered if k not in set(fair)]
    priority=sorted(remaining,key=lambda k:(records.get(k,{}).get('observed_at',-1),int(k)))[:BATCH-len(rebind)-len(fair)]
    selected=fair+priority+rebind
    need(len(selected)==len(set(selected))and len(selected)<=BATCH,'selection_bound')
    return {'current':current,'records':records,'applied':applied,'selected':selected,'rebind':rebind,
        'cursor':fair[-1]if fair else str(integer(state.get('cursor','0'))),
        'pending_cursor':rebind[-1]if rebind else str(integer(state.get('pending_cursor','0'))),
        'pending_count':len(pending),'started_at':now,'generation':generation}


def user_list(rows):
    need(type(rows)is list and 1<=len(rows)<=BATCH,'batch_rows')
    current=inventory([{**r,'active':1,'domain_active':1}for r in rows])
    need(len(current)==len(rows)and len({r['email']for r in rows})==len(rows),'batch_identity')
    need(all(not row['email'].startswith('-')for row in rows),'email_option_prefix')
    data=''.join(row['email']+'\n'for row in rows).encode('ascii')
    need(len(data)<=32768,'batch_input_bound')
    return data


def parse_batch(raw,rows):
    need(type(raw)is bytes and len(raw)<=131072,'batch_output_bound')
    expected={r['email']:r for r in rows};need(len(expected)==len(rows)and 0<len(rows)<=BATCH,'batch_identity')
    lines=raw.decode('utf-8','strict').splitlines()
    need(lines and lines[0]=='Username\tQuota name\tType\tValue\tLimit\t%','batch_formatter')
    need(len(lines)<=1+len(rows)*4,'batch_line_bound')
    grouped={email:[]for email in expected}
    for line in lines[1:]:
        fields=line.split('\t');need(len(fields)==6,'batch_width')
        need(fields[0]in expected,'unexpected_user')
        grouped[fields[0]].append(fields[1:])
    ok={};errors={}
    for email,row in expected.items():
        values=grouped[email];key=row['id']
        try:
            need(len(values)==2,'batch_resources')
            # Reuse the exact installed KiB upper-bound/limit validator, not a new unit interpretation.
            resources={v[1]:v for v in values}
            need(set(resources)=={'STORAGE','MESSAGE'},'batch_resources')
            message=resources['MESSAGE']
            need(re.fullmatch('0|[1-9][0-9]{0,18}',message[2])is not None and message[3]=='-'and message[4]=='0','batch_message_shape')
            single=('Quota name\tType\tValue\tLimit\t%\n'+'\n'.join('\t'.join(v)for v in values)+'\n').encode()
            ok[key]=quota_tab(single,row['quota_bytes'])
            ok[key]={k:v for k,v in ok[key].items()if k in ('effective_bytes','used_bytes_upper_bound')}
        except (ValueError,TypeError):errors[key]='quota_row_unverified'
    return {'ok':ok,'errors':errors}


def combine(main,backend):
    ok={};errors={**main['errors'],**backend['errors']}
    for key in set(main['ok'])&set(backend['ok']):
        a,b=main['ok'][key],backend['ok'][key]
        if a['effective_bytes']!=b['effective_bytes']:errors[key]='instance_limit_mismatch';continue
        ok[key]={'effective_bytes':a['effective_bytes'],'used_bytes_upper_bound':max(a['used_bytes_upper_bound'],b['used_bytes_upper_bound'])}
    return {'ok':ok,'errors':errors}


def finish(plan,observations,errors,observed_at,finished_at,*,rebound=()):
    need(type(observations)is dict and type(errors)is dict,'observation_map')
    observed_at=integer(observed_at);finished_at=integer(finished_at)
    need(plan['started_at']<=observed_at<=finished_at,'observation_clock')
    selected=set(plan['selected']);need(set(observations)<=selected and set(errors)<=selected,'observation_identity')
    need(set(rebound)<=set(plan['rebind']),'rebind_identity')
    records=plan['records'];applied=plan['applied'];failed={}
    for key in selected:
        records.pop(key,None);row=plan['current'][key];r=observations.get(key)
        if key in errors or (key in plan['rebind']and key not in rebound)or type(r)is not dict or set(r)!={'effective_bytes','used_bytes_upper_bound'}:
            failed[key]='measurement_unverified';continue
        if type(r['effective_bytes'])is not int or r['effective_bytes']!=row['quota_bytes']or type(r['used_bytes_upper_bound'])is not int or not 0<=r['used_bytes_upper_bound']<=2**63-1:
            failed[key]='measurement_unverified';continue
        if finished_at-observed_at>=TTL:failed[key]='batch_stale';continue
        records[key]={'id':key,'email':row['email'],'configured_bytes':row['quota_bytes'],'effective_bytes':r['effective_bytes'],
            'used_bytes_upper_bound':r['used_bytes_upper_bound'],'observed_at':observed_at}
        applied[key]={'email':row['email'],'quota_bytes':row['quota_bytes']}
    records={k:r for k,r in records.items()if finished_at-TTL<r['observed_at']<=finished_at}
    count=len(plan['current']);ages=[finished_at-r['observed_at']for r in records.values()]
    projected=math.ceil(count/FAIR)*SUCCESSFUL_CYCLE_SECONDS
    return {'snapshot':{'version':1,'deployment_hash':plan['generation'],'enforcement_verified':True,'records':records},
        'state':{'version':1,'deployment_hash':plan['generation'],'cursor':plan['cursor'],'pending_cursor':plan['pending_cursor'],'applied':applied},
        'report':{'status':'ok'if len(records)==count and not failed else'incomplete','active':count,'attempted':len(selected),
            'updated':len(selected)-len(failed),'measured':len(records),'complete':len(records)==count,'failures':len(failed),
            'pending_rebind':sum(applied.get(k)!={'email':r['email'],'quota_bytes':r['quota_bytes']}for k,r in plan['current'].items()),
            'oldest_age_seconds':max(ages)if ages else None,'projected_sweep_seconds_at_budget':projected,
            'rebind_backlog_seconds_at_budget':math.ceil(plan['pending_count']/REBIND)*SUCCESSFUL_CYCLE_SECONDS,
            'capacity_within_expiry':projected<TTL and plan['pending_count']<=REBIND,
            'freshness_assumption':'stable applied inventory; successful cycles <=10s; real load requires validation'}}
