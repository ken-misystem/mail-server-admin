"""Bounded collection policy only. Native/DB/publication adapters are separate."""
import re

def integer(v,positive=False):
    if type(v)is str and re.fullmatch(r'0|[1-9][0-9]{0,18}',v):v=int(v)
    if type(v)is not int or v< (1 if positive else 0) or v>2**63-1:raise ValueError('integer_shape')
    return v

def inventory(rows):
    if type(rows)is not list or len(rows)>10000:raise ValueError('inventory_bound')
    out={}
    for r in rows:
        if type(r)is not dict or set(r)!={'id','email','quota_bytes','active','domain_active'}:raise ValueError('inventory_shape')
        key=str(integer(r['id'],True))
        if key in out:raise ValueError('duplicate_id')
        if type(r['email'])is not str or len(r['email'])>254 or not re.fullmatch(r'[A-Za-z0-9._+\-]+@[A-Za-z0-9.\-]+',r['email']):raise ValueError('email_shape')
        a=integer(r['active']);d=integer(r['domain_active'])
        if a not in(0,1)or d not in(0,1):raise ValueError('active_shape')
        q=integer(r['quota_bytes'])
        if a==d==1:out[key]={'id':key,'email':r['email'],'quota_bytes':q}
    return out

def cycle(rows,old,cursor,deployment_hash,read_usage,wall,monotonic,*,batch=5,budget=15,per_user=3,enforcement_attested=False):
    if enforcement_attested is not True:raise ValueError('enforcement_not_attested')
    if type(batch)is not int or not 1<=batch<=10 or type(budget)is not int or not 1<=budget<=30 or type(per_user)is not int or not 1<=per_user<=5:raise ValueError('cycle_limits')
    if type(deployment_hash)is not str or not re.fullmatch('[a-f0-9]{64}',deployment_hash):raise ValueError('deployment_pin')
    cursor=integer(cursor);current=inventory(rows);now=integer(wall())
    start=monotonic();deadline=start+budget;records={};failures=[]
    if type(old)is not dict:raise ValueError('old_snapshot_shape')
    if old.get('version')==1 and old.get('deployment_hash')==deployment_hash and old.get('enforcement_verified')is True:
        if type(old.get('records'))is not dict or len(old['records'])>10000:raise ValueError('old_records_bound')
        for key,r in old['records'].items():
            row=current.get(key)
            if row is None or type(r)is not dict:continue
            if r.get('id')!=key or r.get('email')!=row['email']or r.get('configured_bytes')!=row['quota_bytes']or r.get('effective_bytes')!=row['quota_bytes']:continue
            if type(r.get('observed_at'))is not int or not now-120<r['observed_at']<=now:continue
            if type(r.get('used_bytes_upper_bound'))is not int or not 0<=r['used_bytes_upper_bound']<=2**63-1:continue
            records[key]=dict(r)
    ordered=sorted(current,key=int);ordered=[k for k in ordered if int(k)>cursor]+[k for k in ordered if int(k)<=cursor]
    attempted=[]
    for key in ordered[:batch]:
        tick=monotonic()
        if tick<start:raise ValueError('monotonic_clock_reversed')
        remaining=deadline-tick
        if remaining<=0:break
        row=current[key];attempted.append(key);cursor=int(key)
        try:
            allowance=min(per_user,remaining)
            obs=read_usage(dict(row),allowance)
            done=monotonic();observed=integer(wall())
            if done<tick or done-tick>allowance or done>deadline or observed<now:raise ValueError('clock_or_deadline')
            if type(obs)is not dict or set(obs)!={'effective_bytes','used_bytes_upper_bound'}:raise ValueError('observation_shape')
            effective=integer(obs['effective_bytes']);used=integer(obs['used_bytes_upper_bound'])
            if effective!=row['quota_bytes']:raise ValueError('effective_mismatch')
            records[key]={'id':key,'email':row['email'],'configured_bytes':row['quota_bytes'],'effective_bytes':effective,'used_bytes_upper_bound':used,'observed_at':observed}
        except Exception as e:
            records.pop(key,None)
            failures.append({'id':key,'class':type(e).__name__,'errno':getattr(e,'errno',None),
                'reason':str(e)if type(e)is ValueError and str(e)in('integer_shape','clock_or_deadline','observation_shape','effective_mismatch')else'measurement_failed'})
    finished=integer(wall())
    if finished<now:raise ValueError('wall_clock_reversed')
    records={k:r for k,r in records.items()if finished-120<r['observed_at']<=finished}
    return {'snapshot':{'version':1,'deployment_hash':deployment_hash,'enforcement_verified':True,'records':records},
        'next_cursor':str(cursor),'attempted':attempted,'failures':failures,'active_count':len(current),
        'complete_population_measured':len(records)==len(current),'adapters_and_native_timeout_verified':False}
