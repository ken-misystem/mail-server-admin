"""Prepared additional-rule lookup; validation once, bounded prefix probes per RCPT."""
import ipaddress
from access_rules import validate
from forwarding import need

class RuleIndex:
    def __init__(self,rows):
        validate(rows,0);self.exact={};self.hosts={};self.networks={}
        for row in rows:
            key=(row['scope'],row['domain_id']);value=(row['effect'],row['expires'])
            if row['kind']=='address':self.exact.setdefault(key,{})[row['value']]=value
            elif row['kind']=='domain':self.hosts.setdefault(key,{})[row['value']]=value
            else:
                network=ipaddress.ip_network(row['value'],strict=True);self.networks.setdefault((row['scope'],network.version),{}).setdefault(network.prefixlen,{})[int(network.network_address)]=value
    def denies(self,scope,identity,now,domain_id=0):
        need(scope in ('client','sender','recipient','spam')and type(identity)is str and type(now)is int and type(domain_id)is int,'rule_lookup_input');matches=[]
        def consider(value,level):
            if value is not None and (value[1]==0 or value[1]>now):matches.append((level,value[0]))
        for context in {0,domain_id}:
            key=(scope,context);consider(self.exact.get(key,{}).get(identity),1000)
            host=identity.rsplit('@',1)[-1];labels=host.split('.')
            for at in range(len(labels)):consider(self.hosts.get(key,{}).get('.'.join(labels[at:])),len(labels)-at)
        try:ip=ipaddress.ip_address(identity)
        except ValueError:ip=None
        if ip is not None:
            bits=ip.max_prefixlen;number=int(ip)
            for prefix,networks in self.networks.get((scope,ip.version),{}).items():
                mask=0 if prefix==0 else((1<<bits)-1)^((1<<(bits-prefix))-1);consider(networks.get(number&mask),prefix)
        if not matches:return False
        most=max(level for level,_ in matches);return any(level==most and effect=='deny'for level,effect in matches)
