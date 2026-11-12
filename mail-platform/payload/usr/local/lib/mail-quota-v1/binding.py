"""Pure candidate builder. Never reads live configuration or changes credentials."""
import hashlib
import re

QUERY="SELECT CONCAT(quota_bytes, 'B') AS quota_storage_size FROM mailserver.virtual_users WHERE email = '%{user}'"
CHAIN='''userdb quota_limit {
  driver = sql
  skip = notfound
  result_success = return-ok
  result_failure = return-fail
  result_internalfail = return-fail
  userdb_sql_query = QUERY_PLACEHOLDER
}
'''.replace('QUERY_PLACEHOLDER',QUERY)

def require(value,reason):
    if not value:raise ValueError(reason)

def delivery_result(code,reason,before,after,expected):
    require(type(code)is int and type(reason)is bytes and type(before)is int and type(after)is int,'delivery_result_shape')
    if expected=='saved':require(code==250 and after==before+1,'delivery_not_saved')
    elif expected=='quota':require(code//100 in (4,5)and re.search(rb'\b[45]\.2\.[23]\b',reason)is not None and after==before,'delivery_not_quota')
    elif expected=='temporary':require(code//100==4 and after==before,'delivery_not_temporary')
    else:raise ValueError('delivery_expectation')

def augment_static(raw,expected_sha256):
    require(hashlib.sha256(raw).hexdigest()==expected_sha256,'source_pin')
    text=raw.decode('utf-8','strict');lines=text.splitlines(keepends=True)
    starts=[i for i,s in enumerate(lines)if re.fullmatch(r'\s*userdb static\s*\{\s*\n?',s)]
    require(len(starts)==1,'static_block_count');start=starts[0];depth=0;end=None
    for i in range(start,len(lines)):
        s=re.sub(r'%\{[^}]*\}','VARIABLE',lines[i])
        s=re.sub(r'"[^"\n]*"|\x27[^\x27\n]*\x27','VALUE',s).split('#',1)[0]
        depth+=s.count('{')-s.count('}')
        require(depth>=0,'static_brace_shape')
        if depth==0:end=i;break
    require(end is not None,'static_unclosed')
    body=lines[start+1:end];fields=[]
    for s in body:
        v=s.strip()
        if not v or v.startswith('#')or v in ('fields {','}'):continue
        m=re.fullmatch(r'(uid|gid|home)\s*=\s*(.+)',v)
        require(m is not None,'static_extra_setting');fields.append(m[1])
    require(sorted(fields)==['gid','home','uid'],'static_fields')
    require('userdb quota_limit'not in text,'already_augmented')
    # Keep every original field byte. Stop on not-found; an internal failure leaves
    # existence unestablished and the SQL stage is skipped, retaining failure.
    insert='  result_success = continue-ok\n  result_failure = return-fail\n  result_internalfail = return-fail\n'
    out=''.join(lines[:start+1])+insert+''.join(body)+lines[end]+CHAIN+''.join(lines[end+1:])
    require(out.replace(insert,'',1).replace(CHAIN,'',1)==text,'unrelated_bytes_changed')
    return out.encode()

def quota_tab(raw,expected_limit_bytes):
    require(type(expected_limit_bytes)is int and 0<=expected_limit_bytes<=2**63-1,'limit_type')
    require(len(raw)<=8192,'quota_output_bound')
    lines=raw.decode('utf-8','strict').splitlines()
    require(len(lines)==3 and lines[0]=='Quota name\tType\tValue\tLimit\t%','quota_formatter')
    rows=[x.split('\t')for x in lines[1:]]
    require(all(len(x)==5 and x[0]=='User quota'for x in rows),'quota_root')
    storage=[x for x in rows if x[1]=='STORAGE'];messages=[x for x in rows if x[1]=='MESSAGE']
    require(len(storage)==len(messages)==1,'quota_resources');x=storage[0]
    require(re.fullmatch(r'0|[1-9][0-9]{0,15}',x[2])is not None,'quota_used_type')
    require((x[3]=='-'if expected_limit_bytes==0 else x[3]==str(expected_limit_bytes//1024)),'quota_limit_mismatch')
    upper=(int(x[2])+1)*1024;require(upper<=2**63-1,'quota_usage_overflow')
    return {'used_bytes_upper_bound':upper,'effective_bytes':expected_limit_bytes,'native_unit':'KiB'}

def snapshot(records,deployment_hash,now):
    require(type(records)is list and len(records)<=10000 and re.fullmatch('[a-f0-9]{64}',deployment_hash)is not None,'snapshot_shape')
    out={}
    for x in records:
        require(set(x)=={'id','email','configured_bytes','effective_bytes','used_bytes_upper_bound','observed_at'},'record_shape')
        require(type(x['id'])is str and re.fullmatch('[1-9][0-9]{0,18}',x['id'])is not None and x['id']not in out,'record_id')
        require(type(x['email'])is str and re.fullmatch(r'[A-Za-z0-9._+\-]+@[A-Za-z0-9.\-]+',x['email'])is not None,'record_email')
        require(all(type(x[k])is int and 0<=x[k]<=2**63-1 for k in ('configured_bytes','effective_bytes','used_bytes_upper_bound','observed_at')),'record_integer')
        require(x['configured_bytes']==x['effective_bytes'],'effective_mismatch')
        require(now-120<x['observed_at']<=now,'record_stale')
        out[x['id']]=x.copy()
    return {'version':1,'deployment_hash':deployment_hash,'enforcement_verified':True,'records':out}
