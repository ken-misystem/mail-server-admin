"""Threshold-only rules below the two verified legacy exceptions; no check disabling."""
import hashlib,json,math,re
from forwarding import domain,need

PREFIX='mailadmin_threshold_'
def parse_owned_fragment(raw):
    need(type(raw)is bytes and 0<len(raw)<=2097152,'spam_owned_fragment_bound');text=raw.decode('ascii');rules={}
    if raw==b'\n':return rules
    for line in text.splitlines():
        name,sep,value=line.partition(' = ');need(sep and value.endswith(';'),'spam_owned_fragment_line');key=json.loads(name);row=json.loads(value[:-1])
        need(type(key)is str and re.fullmatch(PREFIX+r'[0-9]{4}',key)is not None and key not in rules and type(row)is dict,'spam_owned_fragment_rule');rules[key]=row
    canonical=('\n'.join(json.dumps(name)+' = '+json.dumps(row,sort_keys=True,separators=(',',':'))+';'for name,row in rules.items())+'\n').encode()
    need(canonical==raw,'spam_owned_fragment_canonical');return rules

def profiles(payload):
    need(type(payload)is dict and set(payload)=={'profiles'}and type(payload['profiles'])is list and 1<=len(payload['profiles'])<=1001,'spam_profile_bound');output={}
    for row in payload['profiles']:
        need(type(row)is dict and set(row)=={'domain_id','greylist','add_header','reject'},'spam_profile_shape');identity=row['domain_id']
        need(type(identity)is int and 0<=identity<2**32 and identity not in output,'spam_profile_domain')
        for key in ('greylist','add_header','reject'):need(type(row[key])in (int,float)and math.isfinite(row[key])and 0<=row[key]<=100,'spam_profile_threshold')
        need(row['greylist']<row['add_header']<row['reject'],'spam_threshold_order');output[identity]=(row['reject'],row['add_header'],row['greylist'])
    need(0 in output,'spam_default_required');return output

def render(payload,domain_ids,domain_aliases):
    configured=profiles(payload);need(type(domain_ids)is dict and 1<=len(domain_ids)<=10000 and type(domain_aliases)is dict and len(domain_aliases)<=1000,'spam_domain_catalog')
    need(set(configured)-{0}<=set(domain_ids.values()),'spam_unknown_domain');groups={}
    for host,identity in domain_ids.items():
        domain(host);need(type(identity)is int and 0<identity<2**32,'spam_domain_identity');groups.setdefault(configured.get(identity,configured[0]),[]).append(host)
    for alias,target in domain_aliases.items():
        domain(alias);need(target in domain_ids and alias not in domain_ids,'spam_domain_alias');identity=domain_ids[target];groups.setdefault(configured.get(identity,configured[0]),[]).append(alias)
    rules={};earlier=[];size=0
    # One message has one action. Lowest reject threshold wins across SMTP recipients;
    # ties use add-header, greylist, then the stable generated rule order.
    for index,((reject,header,grey),hosts)in enumerate(sorted(groups.items())):
        rule={'priority':2,'rcpt':['@'+host for host in sorted(set(hosts))],
            'apply':{'actions':{'reject':reject,'add header':header,'greylist':grey}}}
        if earlier:
            # 3.12 iterates every matching rule at the same priority. Exclude any
            # recipient in an earlier (stricter) group, so no second apply/log
            # warning occurs for a multi-domain message. All pattern bytes derive
            # from validated ASCII domain labels; no quotes/backslash escapes.
            pattern='(?:^|,)(?:'+'|'.join(host.replace('.','[.]')for host in sorted(earlier))+')(?:,|$)'
            rule['selector']="rcpts('smtp'):domain.lower.join(',').regexp('"+pattern+"')"
            rule['expression']='rcpt && !selector:1'
        name=PREFIX+str(index).zfill(4);size+=len(json.dumps(name))+len(json.dumps(rule,sort_keys=True,separators=(',',':')))+4
        need(size<=2097152,'spam_fragment_bound');rules[name]=rule;earlier.extend(sorted(set(hosts)))
    raw=('\n'.join(json.dumps(name)+' = '+json.dumps(value,sort_keys=True,separators=(',',':'))+';'for name,value in rules.items())+'\n').encode()
    need(len(raw)<=2097152,'spam_fragment_bound');return raw,rules

def legacy_rules(value):
    """Require the measured exception profiles; never silently replace arbitrary rules."""
    need(type(value)is dict,'legacy_settings_object');legacy={name:row for name,row in value.items()if not name.startswith(PREFIX)}
    need(len(legacy)==2 and all(type(name)is str and type(row)is dict for name,row in legacy.items()),'legacy_settings_inventory')
    auth=[];header=[]
    for name,row in legacy.items():
        if set(row)=={'priority','authenticated','apply'}and row['priority']=='high'and row['authenticated']is True:
            need(type(row['apply'])is dict and set(row['apply'])=={'actions'}and type(row['apply']['actions'])is dict,'legacy_authenticated_actions');auth.append(name)
        elif set(row)=={'priority','request_header','apply'}and row['priority']==4:
            need(type(row['request_header'])is dict and type(row['apply'])is dict and set(row['apply'])=={'plugins','symbols_disabled'}and row['apply']['symbols_disabled']==['DKIM_SIGNED','ARC_SIGNED'],'legacy_ingress_header_exception');header.append(name)
        else:raise ValueError('legacy_settings_unknown_shape')
    need(len(auth)==1 and len(header)==1,'legacy_settings_exception_count')
    return {'rules':legacy,'canonical_sha256':hashlib.sha256(json.dumps(legacy,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'authenticated_priority':3,'ingress_priority':4,'managed_priority':2}

def verify_effective(actual,expected,legacy_pin):
    old=legacy_rules(actual);need(old['canonical_sha256']==legacy_pin,'legacy_settings_changed')
    managed={name:row for name,row in actual.items()if name.startswith(PREFIX)}
    need(managed==expected,'managed_settings_effective_mismatch');return {'state':'file_validated','legacy_rules_preserved':2,'managed_rules':len(managed),'actual_message_matching_proven':False}
