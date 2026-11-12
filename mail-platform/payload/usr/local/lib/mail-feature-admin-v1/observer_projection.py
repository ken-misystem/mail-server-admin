"""Safe projections from fixed native outputs; source text never enters status.json."""
import collections,ipaddress,json,re
from forwarding import domain,need
import public_dns_view as dns

AUTH_CATEGORIES={'access','smtp_in','smtp_out','web','security','system'}
BACKUP_SHA='c706e251b051cf83f69362add6f9f0db62741b8eebb0139a9e8f347d321f852c'
BACKUP_BYTES=52540479

def authentication(rows,now_us,*,truncated):
    need(type(rows)is list and len(rows)<=200000 and type(now_us)is int and type(truncated)is bool,'authentication_observation_input')
    counts=collections.Counter();ips=collections.Counter();minimum=max(0,now_us-86400000000)
    for stamp,raw in rows:
        need(type(stamp)is int and minimum<=stamp<=now_us and type(raw)is str and len(raw)<=131072,'authentication_row_bound')
        value=json.loads(raw);need(type(value)is dict and value.get('ts')==stamp,'authentication_event_binding')
        if value.get('outcome')!='auth_failed':continue
        category=value.get('category');need(category in AUTH_CATEGORIES,'authentication_unknown_category')
        counts[(stamp//600000000*600,category)]+=1
        ip=value.get('ip','')
        if ip:
            need(type(ip)is str,'authentication_IP_type');ips[str(ipaddress.ip_address(ip))]+=1
    need(len(counts)<=1008,'authentication_bucket_bound')
    return {'state':'incomplete'if truncated else'ok','requested_seconds':86400,'full_period_coverage_proven':False,
        'totals':[{'at':stamp,'category':kind,'count':count}for(stamp,kind),count in sorted(counts.items())],
        'top_IPs':[{'ip':ip,'count':count}for ip,count in sorted(ips.items(),key=lambda row:(-row[1],row[0]))[:100]]}

def backup(receipt):
    need(type(receipt)is dict and receipt.get('verified')is True and receipt.get('contains_plaintext')is False
        and receipt.get('sha256')==BACKUP_SHA and receipt.get('bytes')==BACKUP_BYTES,'historical_backup_receipt')
    return {'state':'ok','sha256':BACKUP_SHA,'bytes':BACKUP_BYTES,'restore_test':False,'complete_mail_archive':False,'external_copy_currently_accessible':False}

def scanner(native,*,engine_present,daemon_running,attachment_rules_configured=False):
    need(type(native)is dict and type(engine_present)is bool and type(daemon_running)is bool and type(attachment_rules_configured)is bool,'scanner_observation_shape')
    configured=bool(native)
    need(not daemon_running or engine_present,'scanner_daemon_without_engine')
    return {'state':'unverified'if configured or engine_present else'not_configured','engine_present':engine_present,
        'configured':configured,'daemon_running':daemon_running,'detection_verified':False,'attachment_rules_configured':attachment_rules_configured}

def upstream(relay,relay_maps,sasl_maps):
    for raw in (relay,relay_maps,sasl_maps):need(type(raw)is bytes and len(raw)<=65536 and b'\x00'not in raw,'upstream_output_bound')
    configured=bool(relay.strip()or relay_maps.strip())
    return {'state':'unverified'if configured else'not_configured','relay_configured':configured,
        'credentials_configured':bool(sasl_maps.strip()),'direct_MX':not configured}

def configuration(report):
    need(type(report)is dict and report.get('state')in ('ok','incomplete')and type(report.get('desired'))is dict and type(report.get('applied'))is dict,'configuration_observation')
    out={'state':report['state']}
    for kind in ('access','spam'):
        wanted=report['desired'][kind];applied=report['applied'][kind]
        need(type(wanted)is int and type(applied)is int and 0<=applied<=wanted,'configuration_observation_revision')
        out[kind]={'desired_revision':wanted,'applied_revision':applied}
    return out

def dns_domain(host,now,*,selector=None,public_ip=None,query=dns.query):
    domain(host);need(type(now)is int and now>=0,'DNS_observation_clock');records=[]
    questions=dns.tasks(host,selector,public_ip)
    labels=['MX','SPF','DMARC']+(['DKIM']if selector is not None else[])+(['PTR']if public_ip is not None else[])
    for(name,kind),label in zip(questions,labels,strict=True):
        try:
            pair=[query(provider,name,kind)for provider in ('google','cloudflare')];compared=dns.compare(*pair)
            values=sorted({row['value']for answer in pair for row in answer['answers']})
            if label=='SPF':values=[value for value in values if value.lstrip('"').lower().startswith('v=spf1')]
            records.append({'type':label,'state':compared['state'],'values':values})
        except Exception:records.append({'type':label,'state':'unavailable','values':[]})
    if selector is None:records.append({'type':'DKIM','state':'selector_unknown','values':[]})
    return {'domain':host,'observed_at':now,'records':records,'DNS_changed':False}

def unavailable_status(now):
    return {'version':1,'observed_at':now,'authentication':{'state':'unavailable'},'backup':{'state':'unavailable'},
        'scanner':dict(scanner({},engine_present=False,daemon_running=False),state='unavailable'),
        'upstream':dict(upstream(b'',b'',b''),state='unavailable'),
        'forwarding':{'state':'unavailable','configured':0,'held':0,'scripts':0},
        'configuration':{'state':'unavailable','access':{'desired_revision':0,'applied_revision':0},'spam':{'desired_revision':0,'applied_revision':0}},'domains':[]}
