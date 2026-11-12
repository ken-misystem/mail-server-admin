"""Preserve local delivery and gate ONLY external copies; bounded loop detection."""
import re
from collections import defaultdict

def need(ok,reason):
    if not ok:raise ValueError(reason)
def domain(value):
    need(type(value)is str and value==value.lower() and 1<=len(value)<=253 and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in value.split('.')) and '.' in value,'domain')
    return value
def address(value):
    need(type(value)is str and value==value.lower() and len(value)<=254 and value.count('@')==1,'address')
    local,host=value.split('@');domain(host)
    need(1<=len(local)<=64 and re.fullmatch(r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*",local)is not None,'local_part')
    return value
def validate(routes,local_domains):
    need(type(routes)is list and len(routes)<=10000 and type(local_domains)is set,'forward_inventory')
    domains={domain(v) for v in local_domains};graph=defaultdict(list);result=[];seen=set()
    for row in routes:
        need(type(row)is dict and set(row)=={'source','destinations','enabled','revision'},'forward_fields')
        source=address(row['source']);need(source not in seen and source.split('@')[1] in domains,'forward_source');seen.add(source)
        targets=row['destinations'];need(type(targets)is list and 1<=len(targets)<=10 and len(set(targets))==len(targets),'forward_targets')
        targets=[address(x) for x in targets];need(source not in targets,'forward_self')
        need(type(row['enabled'])is bool and type(row['revision'])is int and row['revision']>=0,'forward_state')
        result.append(dict(row,destinations=sorted(targets)))
        # Even disabled routes are checked; enabling one later must not reveal a loop.
        graph[source]=targets
    state={}
    def visit(start):
        stack=[(start,False)]
        while stack:
            node,done=stack.pop()
            if done:state[node]=2;continue
            need(state.get(node)!=1,'forward_cycle')
            if state.get(node)==2:continue
            state[node]=1;stack.append((node,True))
            for target in reversed(graph.get(node,[])):
                need(state.get(target)!=1,'forward_cycle')
                if target in graph and state.get(target)!=2:stack.append((target,False))
    for node in graph:
        if state.get(node)!=2:visit(node)
    return result

def sieve_fragment(destinations):
    """For a proven non-Junk stage. The caller must preserve existing Sieve order."""
    need(type(destinations)is list and 1<=len(destinations)<=10,'forward_targets')
    targets=[address(x) for x in destinations]
    # Standard Sieve copy does not cancel implicit keep; no discard/stop/delete.
    return 'require ["copy"];\n'+''.join('redirect :copy "'+value+'";\n' for value in targets)

def destinations_for(row,health,now):
    need(type(health)is dict and set(health)=={'state','at','revision'} and type(now)is int,'forward_health')
    need(health['state'] in ('ok','failed','unknown') and type(health['at'])is int and health['at']<=now+5
         and type(health['revision'])is int,'forward_health_shape')
    enabled=row['enabled'] and health['state']=='ok' and 0<=now-health['at']<=120 and health['revision']==row['revision']
    return {'keep':True,'destinations':list(row['destinations']) if enabled else [],'forwarding_held':row['enabled'] and not enabled}

def transition(previous,failures,now,manual_resume=False):
    need(type(previous)is dict and type(failures)is int and failures>=0 and type(now)is int,'forward_state')
    state=previous.get('state');need(state in ('ok','failed','unknown'),'forward_state')
    # No automated resend or auto-resume of a failing external destination.
    if failures>=3:return dict(previous,state='failed',at=now)
    if manual_resume is True and failures==0:return dict(previous,state='ok',at=now)
    return dict(previous,at=now)
