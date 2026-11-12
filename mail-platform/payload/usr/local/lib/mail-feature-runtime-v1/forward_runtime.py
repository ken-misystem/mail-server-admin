"""Managed copy scripts and complete local alias/forward graph; never executes old code."""
import datetime as dt
import re
from forwarding import address,domain,need,validate

HEALTH_NAME='mailadmin-forward-health-v1'
TOKEN=re.compile(r'\s+|\#[^\r\n]*(?:\r?\n|$)|/\*.*?\*/|"(?:\\.|[^"\\])*"|:[A-Za-z][A-Za-z0-9_-]*|[A-Za-z][A-Za-z0-9_-]*|[\[\]{}(),;]',re.S)

def script_tokens(raw):
    need(type(raw)is bytes and len(raw)<=65536,'sieve_source_bound');text=raw.decode('utf-8','strict');tokens=[];at=0
    while at<len(text):
        m=TOKEN.match(text,at);need(m is not None,'sieve_unrecognized_token');word=m[0];at=m.end()
        if word.isspace() or word.startswith(('#','/*')):continue
        tokens.append(word if word.startswith('"') else word.lower())
    return tokens

def legacy_class(raw,destination):
    address(destination)
    if raw is None:return 'absent'
    try:tokens=script_tokens(raw)
    except (ValueError,UnicodeError):return 'unrecognized_preserve'
    if tokens in ([],['keep',';']):return 'empty_or_keep'
    expected=script_tokens(('require ["copy"]; redirect :copy "'+destination+'";').encode())
    return 'canonical_copy' if tokens in (expected,expected+['keep',';']) else 'unrecognized_preserve'

def mailbox_filename(mailbox):
    address(mailbox);local,host=mailbox.split('@')
    need(re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,63}',local)is not None and not local.endswith('.') and '..'not in local,'managed_mailbox_path')
    return mailbox+'.sieve'

def health_script(now,lifetime=120):
    need(type(now)is int and 0<=now<=4102444800 and type(lifetime)is int and 30<=lifetime<=120,'forward_heartbeat_time')
    stamp=lambda value:dt.datetime.fromtimestamp(value,dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    # RFC 5260 iso8601 requires uppercase Z for UTC; :zone itself uses +hhmm.
    begin=stamp(max(0,now-5));end=stamp(now+lifetime)
    return ('require ["date", "relational", "include"];\n'
        'if not allof (currentdate :zone "+0000" :comparator "i;octet" :value "ge" "iso8601" "'+begin+'",\n'
        '              currentdate :zone "+0000" :comparator "i;octet" :value "lt" "iso8601" "'+end+'") { stop; }\n').encode('ascii')

def managed_script(destinations,enabled=True,healthy=True):
    need(type(destinations)is list and 0<=len(destinations)<=10 and type(enabled)is bool and type(healthy)is bool,'managed_forward_fields')
    targets=[address(x) for x in destinations];need(len(set(targets))==len(targets),'forward_duplicate_target')
    if not enabled or not healthy or not targets:return b'keep;\n'
    # No variables extension: ${...} in a literal address must remain a literal.
    body='require ["copy", "include"];\ninclude :global "'+HEALTH_NAME+'";\n'
    return (body+''.join('redirect :copy "'+target+'";\n' for target in sorted(targets))).encode('ascii')

def namespace_key(value,primary,domain_aliases):
    value=address(value);local,host=value.split('@');host=domain_aliases.get(host,host)
    if host not in primary:return value
    return local.split('+',1)[0].replace('.','')+'@'+host

def resolve_graph(routes,domains,domain_aliases,users,aliases):
    """Complete bounded inventory; normalize local aliases before detecting cycles."""
    need(type(domains)is set and type(domain_aliases)is dict and len(domain_aliases)<=1000 and type(users)is list and len(users)<=10000 and type(aliases)is list and len(aliases)<=10000,'forward_graph_bound')
    primary={domain(x) for x in domains}
    for alias,target in domain_aliases.items():domain(alias);need(domain(target)in primary and alias not in primary,'forward_domain_alias')
    key=lambda value:namespace_key(value,primary,domain_aliases)
    mailboxes={}
    for user in users:
        address(user);need(user.split('@')[1]in primary and key(user)not in mailboxes,'forward_mailbox_inventory');mailboxes[key(user)]=user
    mapping={}
    for source,targets in aliases:
        address(source);need(source.split('@')[1]in primary|set(domain_aliases) and key(source)not in mapping and key(source)not in mailboxes,'forward_alias_inventory')
        need(type(targets)is list and 1<=len(targets)<=10,'forward_alias_targets');mapping[key(source)]=[address(x) for x in targets]
    def resolve(value):
        leaves=set();pending=[(value,())];steps=0
        while pending:
            value,trail=pending.pop();steps+=1;need(steps<=10000 and len(trail)<=64,'forward_alias_depth')
            host=value.split('@')[1]
            if host not in primary|set(domain_aliases):leaves.add(value);continue
            k=key(value);need(k not in trail,'forward_alias_cycle')
            if k in mailboxes:leaves.add(mailboxes[k]);continue
            need(k in mapping,'forward_local_destination_missing')
            pending.extend((target,trail+(k,)) for target in mapping[k])
        need(len(leaves)<=10,'resolved_forward_target_bound');return sorted(leaves)
    projected=[];seen=set()
    for row in routes:
        need(type(row)is dict and set(row)=={'source','destinations','enabled','revision'},'forward_fields');source=address(row['source'])
        need(source not in seen,'forward_duplicate_source');seen.add(source)
        need(key(source)in mailboxes and mailboxes[key(source)]==source,'forward_source_binding')
        need(type(row['enabled'])is bool and type(row['revision'])is int and row['revision']>=0,'forward_state')
        need(type(row['destinations'])is list and 0<=len(row['destinations'])<=10 and (row['destinations'] or not row['enabled']),'forward_targets')
        targets=sorted({target for original in row['destinations'] for target in resolve(address(original))})
        need(len(targets)<=10,'resolved_forward_target_bound');projected.append(dict(row,destinations=targets))
    validate([row for row in projected if row['destinations']],primary)
    return projected

def destination_failures(events,targets,after_us):
    need(type(events)is list and len(events)<=20000 and type(targets)is list and len(targets)<=10 and type(after_us)is int,'forward_failure_inventory')
    targets={address(x) for x in targets};seen={x:set() for x in targets};unknown=0
    for event in events:
        if type(event)is not dict:unknown+=1;continue
        if event.get('category')!='smtp_out' or event.get('outcome')not in ('deferred','failed'):continue
        stamp=event.get('ts');recipient=event.get('recipient');queue=event.get('queue')
        if type(stamp)is not int or stamp<after_us or recipient not in targets:continue
        if type(queue)is not str or re.fullmatch('[A-Za-z0-9]{5,32}',queue)is None:unknown+=1;continue
        seen[recipient].add(queue)
    return {'counts':{target:len(queues) for target,queues in sorted(seen.items())},'unclassified':unknown,
        'attribution':'destination_failures_not_proven_to_be_forward_generated','automatic_resend':False}
