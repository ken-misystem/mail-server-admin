"""Inline expiring scripts, compiled together; no changing include dependencies."""
import datetime as dt,hashlib
from forwarding import need,address
from forward_runtime import mailbox_filename,resolve_graph,destination_failures

def script(targets,now,*,enabled,healthy,lifetime=120):
    need(type(now)is int and 0<=now<=4102444680 and type(lifetime)is int and 30<=lifetime<=120,'forward_generation_time')
    need(type(targets)is list and len(targets)<=10 and type(enabled)is bool and type(healthy)is bool,'forward_generation_fields')
    values=[address(value)for value in targets];need(len(set(values))==len(values),'forward_duplicate_target')
    # No explicit keep: later personal fileinto/discard must retain its old meaning.
    if not enabled or not healthy or not values:return b'require ["copy"];\n'
    stamp=lambda value:dt.datetime.fromtimestamp(value,dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    # Each binary carries its own expiry. The next personal script still runs when stale.
    raw='require ["copy", "date", "relational"];\n'
    raw+='if allof (currentdate :zone "+0000" :comparator "i;octet" :value "ge" "iso8601" "'+stamp(max(0,now-5))+'",\n'
    raw+='           currentdate :zone "+0000" :comparator "i;octet" :value "lt" "iso8601" "'+stamp(now+lifetime)+'") {\n'
    raw+=''.join('  redirect :copy "'+value+'";\n'for value in sorted(values))+'}\n'
    return raw.encode('ascii')

def plan(routes,domains,domain_aliases,users,aliases,events,health_state,now_us):
    """Pure plan. A new configuration revision explicitly resets its failure history."""
    need(type(now_us)is int and 0<=now_us<=4102444680000000 and type(health_state)is dict and len(health_state)<=10000,'forward_generation_inventory')
    now=now_us//1000000;projected=resolve_graph(routes,domains,domain_aliases,users,aliases);originals={row['source']:row['destinations']for row in routes};files={};observations=[];next_state={}
    for row in projected:
        source=row['source'];previous=health_state.get(source)
        if previous is not None:need(type(previous)is dict and set(previous)=={'revision','since_us','held'}and type(previous['revision'])is int and type(previous['since_us'])is int and 0<=previous['since_us']<=now_us and type(previous['held'])is bool,'forward_saved_health_state')
        state=previous.copy()if previous is not None and previous['revision']==row['revision']else{'revision':row['revision'],'since_us':now_us,'held':False}
        external=[value for value in row['destinations']if value.split('@')[1]not in domains]
        failures=destination_failures(events,external,state['since_us'])
        if any(count>=3 for count in failures['counts'].values()):state['held']=True
        # Resolve aliases for graph validation/health attribution only. SMTP still
        # receives the configured envelope target, preserving Postfix's active
        # flags, domain routing, alias changes and recipient-extension handling.
        next_state[source]=state;healthy=not state['held'];raw=script(originals[source],now,enabled=row['enabled'],healthy=healthy);name=mailbox_filename(source)
        need(name not in files,'duplicate_generation_name');files[name]=raw
        observations.append({'source':source,'revision':row['revision'],'configured':row['enabled'],'forwarding_held':row['enabled']and not healthy,'failure_counts':failures['counts'],
            'failure_attribution':failures['attribution'],'sha256':hashlib.sha256(raw).hexdigest()})
    need(sum(map(len,files.values()))<=8*1024*1024,'forward_generation_byte_bound')
    return {'files':files,'observations':observations,'health_state':next_state,'generated_at':now,'expires_at':now+120,'maximum_scripts':10000,'automatic_resend':False}

def summary(generation):
    rows=generation['observations'];return {'generated_at':generation['generated_at'],'expires_at':generation['expires_at'],'configured':sum(row['configured']for row in rows),
        'held':sum(row['forwarding_held']for row in rows),'scripts':len(rows),'automatic_resend':False,'native_compilation_required':True}
