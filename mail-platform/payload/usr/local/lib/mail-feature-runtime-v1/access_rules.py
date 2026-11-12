"""Additional administrative blocks/exceptions, never authentication/relay bypass."""
import ipaddress
from forwarding import address,domain,need

def validate(rows,now):
    need(type(rows)is list and len(rows)<=10000 and type(now)is int and now>=0,'rule_inventory')
    output=[];seen={}
    for row in rows:
        need(type(row)is dict and set(row)=={'kind','scope','value','effect','expires','domain_id'},'rule_fields')
        kind=row['kind'];scope=row['scope'];value=row['value']
        need(kind in ('ip','address','domain') and scope in ('client','sender','recipient','spam') and row['effect'] in ('allow','deny'),'rule_scope')
        need(type(row['domain_id'])is int and row['domain_id']>=0 and type(row['expires'])is int and row['expires']>=0,'rule_expiry')
        if kind=='ip':
            need(scope in ('client','spam') and row['domain_id']==0,'global_client_rule')
            need(type(value)is str and '%' not in value,'IP_rule');network=ipaddress.ip_network(value,strict=True);need(str(network)==value,'canonical_network')
        elif kind=='address':need(scope in ('sender','recipient','spam'),'address_scope');address(value)
        else:need(scope in ('sender','recipient','spam'),'domain_scope');domain(value)
        key=(kind,scope,value,row['domain_id']);need(key not in seen,'duplicate_or_conflicting_rule');seen[key]=row['effect']
        output.append(dict(row))
    return output

def evaluate(rows,scope,identity,now,domain_id=0):
    rows=validate(rows,now);need(scope in ('client','sender','recipient','spam'),'rule_scope')
    matches=[]
    for row in rows:
        if row['scope']!=scope or row['domain_id'] not in (0,domain_id) or row['expires'] and row['expires']<=now:continue
        kind=row['kind'];specificity=0;matched=False
        if kind=='ip':
            try:network=ipaddress.ip_network(row['value']);matched=ipaddress.ip_address(identity) in network;specificity=network.prefixlen
            except ValueError:continue
        elif kind=='address':matched=identity==row['value'];specificity=1000
        elif kind=='domain':
            host=identity.rsplit('@',1)[-1];matched=host==row['value'] or host.endswith('.'+row['value']);specificity=len(row['value'].split('.'))
        if matched:matches.append((specificity,row['effect']))
    if not matches:return {'additional_block':False,'matched':False,'bypass_auth_TLS_relay':False}
    most=max(x[0] for x in matches);effects={effect for specificity,effect in matches if specificity==most}
    return {'additional_block':'deny' in effects,'matched':True,'conflict':len(effects)>1,'bypass_auth_TLS_relay':False}
