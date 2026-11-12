"""Public DNS view only. Fixed verified HTTPS resolvers; never AWS or routing writes."""
import ipaddress,json,re,urllib.parse,urllib.request
from forwarding import domain,need

PROVIDERS={'google':'https://dns.google/resolve','cloudflare':'https://cloudflare-dns.com/dns-query'}
TYPES={'MX':15,'TXT':16,'A':1,'AAAA':28,'PTR':12}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kw):raise ValueError('DNS_redirect_refused')

def query(provider,name,kind,opener=None):
    need(provider in PROVIDERS and kind in TYPES and type(name)is str and len(name)<=253
         and re.fullmatch(r'[A-Za-z0-9_.-]+',name)is not None,'DNS_query_scope')
    url=PROVIDERS[provider]+'?'+urllib.parse.urlencode({'name':name,'type':kind})
    request=urllib.request.Request(url,headers={'Accept':'application/dns-json','User-Agent':'MailServerAdmin-public-view/1'})
    client=opener or urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    with client.open(request,timeout=8) as stream:raw=stream.read(262145)
    need(len(raw)<=262144,'DNS_response_bound');data=json.loads(raw)
    need(type(data)is dict and type(data.get('Status'))is int and 0<=data['Status']<=15,'DNS_status')
    answers=[]
    for row in data.get('Answer',[]):
        need(type(row)is dict and type(row.get('type'))is int and type(row.get('TTL'))is int and 0<=row['TTL']<2**31
             and type(row.get('data'))is str and len(row['data'])<=8192,'DNS_record')
        if row['type']==TYPES[kind]:answers.append({'value':row['data'],'TTL':row['TTL']})
        need(len(answers)<=100,'DNS_answer_bound')
    return {'provider':provider,'name':name,'type':kind,'DNS_status':data['Status'],'answers':answers,'DNS_changed':False}

def tasks(host,selector=None,public_ip=None):
    domain(host);result=[(host,'MX'),(host,'TXT'),('_dmarc.'+host,'TXT')]
    if selector is not None:
        need(type(selector)is str and re.fullmatch('[A-Za-z0-9_-]{1,63}',selector)is not None,'DKIM_selector')
        result.append((selector+'._domainkey.'+host,'TXT'))
    if public_ip is not None:
        ip=ipaddress.ip_address(public_ip);need(ip.is_global,'public_PTR_only');result.append((ip.reverse_pointer,'PTR'))
    return result

def compare(left,right):
    need(left['name']==right['name'] and left['type']==right['type'],'DNS_same_question')
    values=lambda v:sorted(set(x['value'] for x in v['answers']))
    equal=left['DNS_status']==right['DNS_status'] and values(left)==values(right)
    state='unavailable'if left['DNS_status']not in (0,3)or right['DNS_status']not in (0,3)else'consistent'if equal else'resolver_disagreement'
    return {'state':state,'results':[left,right],'routing_changed':False}
