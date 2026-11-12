"""Bounded root observer: safe status and fixed public DNS, never delivery changes."""
import concurrent.futures,hashlib,json,os,re,shutil,stat,time,traceback
from pathlib import Path
from observer_events import collect
from observer_projection import unavailable_status,backup,scanner,upstream,configuration,dns_domain
from runtime_files import read,write,encoded
from configuration_service import STATE,EVENTS,PrivateFile,private_capture,unique
from configuration_commands import run as native
from forwarding import domain,need
from process_lease import ProcessLease

PUBLIC=Path('/run/mail-feature-health-v1')
PUBLIC_IPV4='162.43.6.80' # Pinned production diagnostic; verify allocation in deployment.
CACHE_SECONDS=180
DNS_BATCH=32

def output(path,value,group):
    pin=None
    if os.path.lexists(path):pin=read(path,mode=0o640,group=group)[1]['sha256']
    return write(path,encoded(value),group=group,mode=0o640,prior_pin=pin,absent=pin is None)

def cache_value(name,now,fn):
    need(name in ('authentication','native'),'observer_cache_scope');path=STATE/('observer-'+name+'.json');pin=None
    if os.path.lexists(path):
        raw,meta=read(path,mode=0o600,group=0);pin=meta['sha256'];value=json.loads(raw,object_pairs_hook=unique)
        need(type(value)is dict and set(value)=={'collected_at','data'}and type(value['collected_at'])is int and 0<=value['collected_at']<=now+5,'observer_cache_schema')
        if now-value['collected_at']<CACHE_SECONDS:return value
    value={'collected_at':now,'data':fn()};write(path,encoded(value),group=0,mode=0o600,prior_pin=pin,absent=pin is None);return value

def native_projection():
    # Raw configdump stays in fixed root-only diagnostic slots. Only this reduced
    # projection is cached or exported; no selector expressions or credentials.
    antivirus=json.loads(native('antivirus',private_capture));mime=json.loads(native('mime_types',private_capture))
    need(type(antivirus)is dict and type(mime)is dict,'observer_Rspamd_output')
    clamd=native('clamd_state',private_capture).decode('ascii');states={}
    for line in clamd.splitlines():
        key,sep,value=line.partition('=');need(sep and key in ('LoadState','ActiveState')and key not in states,'observer_clamd_state');states[key]=value
    need(set(states)=={'LoadState','ActiveState'},'observer_clamd_state_missing')
    engine=shutil.which('clamd',path='/usr/sbin:/usr/bin:/sbin:/bin')is not None or shutil.which('clamscan',path='/usr/sbin:/usr/bin:/sbin:/bin')is not None
    scan=scanner(antivirus,engine_present=engine,daemon_running=states['LoadState']=='loaded'and states['ActiveState']=='active',attachment_rules_configured=bool(mime.get('bad_extensions')))
    relay=upstream(native('relayhost',private_capture),native('relay_maps',private_capture),native('sasl_maps',private_capture))
    dkim=json.loads(native('dkim',private_capture));need(type(dkim)is dict,'observer_DKIM_output');selectors={};global_selector=None
    value=dkim.get('selector')
    if type(value)is str and re.fullmatch('[A-Za-z0-9_-]{1,63}',value):global_selector=value
    configured=dkim.get('domain',{})
    if type(configured)is dict:
        for host,row in configured.items():
            if type(host)is str and type(row)is dict and type(row.get('selector'))is str and re.fullmatch('[A-Za-z0-9_-]{1,63}',row['selector']):
                try:domain(host)
                except ValueError:continue
                selectors[host]=row['selector']
    return {'scanner':scan,'upstream':relay,'global_selector':global_selector,'selectors':selectors}

def main():
    import pwd
    need(os.geteuid()==0,'observer_root_required');lease=ProcessLease(STATE/'observer.lock');now=int(time.time());status=unavailable_status(now);stamps=[now];errors={};group=pwd.getpwnam('mailadmin').pw_gid
    try:
        try:
            cached=cache_value('authentication',now,lambda:collect(EVENTS,time.time_ns()//1000));status['authentication']=cached['data'];stamps.append(cached['collected_at'])
        except Exception as error:errors['authentication']=type(error).__name__;private_capture({'command':'runtime_exception','component':'authentication','class':type(error).__name__},err=traceback.format_exc().encode()[:131072])
        try:
            receipt=json.loads(read(STATE/'backup-receipt.json',mode=0o600,group=0)[0]);status['backup']=backup(receipt)
        except Exception as error:errors['backup']=type(error).__name__
        try:
            cached=cache_value('native',now,native_projection);status.update({key:cached['data'][key]for key in ('scanner','upstream')});stamps.append(cached['collected_at']);selectors=cached['data']['selectors'];global_selector=cached['data']['global_selector']
        except Exception as error:errors['native']=type(error).__name__;selectors={};global_selector=None
        report=None
        try:
            report=json.loads(read(STATE/'configuration-report.json',mode=0o600,group=0)[0],object_pairs_hook=unique)
            need(type(report.get('observed_at'))is int and now-120<=report['observed_at']<=now+5,'observer_configuration_report_stale');status['configuration']=configuration(report)
            if report.get('state')!='ok':errors['configuration_runtime']='ComponentPublicationIncomplete'
            forward=report['forwarding']
            if type(forward)is dict:
                fields={key:forward[key]for key in ('state','configured','held','scripts')};need(fields['state']in ('ok','incomplete')and all(type(fields[key])is int and 0<=fields[key]<=10000 for key in ('configured','held','scripts')),'observer_forward_summary');status['forwarding']=fields
            hosts=report['domains'];need(type(hosts)is list and len(hosts)<=10000 and len(set(hosts))==len(hosts),'observer_domain_inventory');status['domains']=sorted(domain(value)for value in hosts);stamps.append(report['observed_at'])
        except Exception as error:errors['configuration']=type(error).__name__
        # Publish the non-network observations before DNS waits. Oldest source age
        # is the public timestamp, so a reused cache never masquerades as fresh.
        status['observed_at']=min(stamps);output(PUBLIC/'status.json',status,group)
        scheduler=PrivateFile(STATE/'DNS-scheduler.json');value=scheduler.value
        need(type(value)is dict and set(value)=={'next_after'}and type(value['next_after'])is str,'observer_DNS_scheduler')
        hosts=status['domains'];start=next((i for i,host in enumerate(hosts)if host>value['next_after']),0)
        selected=hosts[start:start+DNS_BATCH]
        def observe(host):return host,dns_domain(host,int(time.time()),selector=selectors.get(host,global_selector),public_ip=PUBLIC_IPV4)
        if selected:
            with concurrent.futures.ThreadPoolExecutor(max_workers=DNS_BATCH,thread_name_prefix='public-DNS')as pool:
                for host,data in pool.map(observe,selected):output(PUBLIC/('dns-'+hashlib.sha256(host.encode()).hexdigest()+'.json'),data,group)
            scheduler.save({'next_after':selected[-1]if start+len(selected)<len(hosts)else''})
        print(json.dumps({'component':'feature_observer','state':'incomplete'if errors else'ok','failed_components':sorted(errors),'DNS_domains_queried':len(selected)}),flush=True)
        if errors:raise RuntimeError('observer_component_unavailable')
    finally:lease.close()
