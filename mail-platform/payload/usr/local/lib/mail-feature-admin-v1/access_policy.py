"""Only additional RCPT denial. A matching exception returns DUNNO, never OK."""
import ipaddress,json,re
import access_rules
from forwarding import need,address,domain
from access_index import RuleIndex

def snapshot(payload,domain_ids,domain_aliases,revision,observed_at):
    need(type(payload)is dict and set(payload)=={'rules'}and type(payload['rules'])is list,'access_payload')
    rows=[]
    for row in payload['rules']:
        need(type(row)is dict and set(row)=={'kind','scope','value','effect','expires','domain_id','reason'}and row['reason']in ('abuse','malware','operator','migration'),'access_rule_reason')
        rows.append({key:value for key,value in row.items()if key!='reason'})
    access_rules.validate(rows,observed_at)
    need(type(domain_ids)is dict and len(domain_ids)<=10000 and type(domain_aliases)is dict and len(domain_aliases)<=1000,'access_domains')
    for name,identity in domain_ids.items():domain(name);need(type(identity)is int and 0<identity<2**32,'access_domain_identity')
    for alias,target in domain_aliases.items():domain(alias);need(target in domain_ids and alias not in domain_ids,'access_domain_alias')
    need(type(revision)is int and revision>=0 and type(observed_at)is int and observed_at>=0,'access_revision')
    return {'version':1,'revision':revision,'observed_at':observed_at,'expires_at':observed_at+120,'rules':rows,'domain_ids':domain_ids,'domain_aliases':domain_aliases}

def decide(value,request,now,index=None):
    need(type(value)is dict and set(value)=={'version','revision','observed_at','expires_at','rules','domain_ids','domain_aliases'}and value['version']==1 and type(now)is int,'access_snapshot_shape')
    need(type(value['observed_at'])is int and type(value['expires_at'])is int and value['observed_at']-5<=now<value['expires_at']<=value['observed_at']+120,'access_snapshot_stale')
    need(type(request)is dict and request.get('request')=='smtpd_access_policy'and request.get('protocol_state')=='RCPT','access_RCPT_only')
    sender=request.get('sender','').lower();recipient=request.get('recipient','').lower();client=request.get('client_address','');ipaddress.ip_address(client)
    need(all(type(request.get(key,''))is str and len(request.get(key,''))<=320 for key in ('sender','recipient','client_address')),'access_request_values')
    need(not any('\n'in value or '\r'in value or '\x00'in value for value in (sender,recipient,client)),'access_request_control_character')
    domains=value['domain_ids'];aliases=value['domain_aliases']
    index=index or RuleIndex(value['rules'])
    def identity(email):
        host=email.rsplit('@',1)[-1];return domains.get(aliases.get(host,host),0)
    for scope,target in (('client',client),('sender',sender),('recipient',recipient)):
        if index.denies(scope,target,now,identity(target)):return '550 5.7.1 Rejected by administrative access rule'
    # "spam" rules add denial only. Their allow rows cannot bypass other filters.
    for target in (client,sender,recipient):
        if index.denies('spam',target,now,identity(recipient)):return '550 5.7.1 Rejected by administrative spam rule'
    return 'DUNNO'

def reply(value,request,now):
    try:return decide(value,request,now)
    except Exception:return '451 4.3.0 Administrative policy temporarily unavailable'
