"""Deployment-owned root publisher. No HTTP listener or request-selected path."""
import hashlib,json,os,signal,stat,time,traceback
from pathlib import Path
from configuration_cycle import cycle,validate_state
from runtime_directory import RuntimeDirectory
from published_events import failures
from runtime_files import read,write,encoded
from forwarding import need
from forward_publish import compile_generation
from spam_apply import apply as apply_spam_fragment
from configuration_commands import run as native
from load_credential import credential
from process_lease import ProcessLease
from generation_retention import Retention

STATE=Path('/var/lib/mail-feature-runtime-v1')
PUBLIC=Path('/run/mail-feature-policy-v1')
GENERATIONS=Path('/var/lib/mail-feature-public-v1/sieve')
FRAGMENT=Path('/var/lib/mail-feature-public-v1/rspamd-managed.conf')
EVENTS=Path('/var/lib/mail-management-log-viewer-v1/published')
CONFIG=Path('/etc/mail-feature-runtime-v1/deployment.json')

def unique(pairs):
    result={}
    for name,value in pairs:need(name not in result,'runtime_JSON_duplicate');result[name]=value
    return result

class PrivateFile:
    def __init__(self,path):
        self.path=path;raw,meta=read(path,mode=0o600,group=0);self.pin=meta['sha256'];self.value=json.loads(raw,object_pairs_hook=unique)
    def save(self,value):
        self.pin=write(self.path,encoded(value),group=0,mode=0o600,prior_pin=self.pin);self.value=json.loads(json.dumps(value))

def private_capture(row,out=b'',err=b''):
    """Fixed slots contain original bounded native streams; never printed/public."""
    name=row.get('command',row.get('stage','unknown'))
    need(name in ('settings','rspamd_check','rspamd_reload','sieve_compile','antivirus','dkim','mime_types','relayhost','relay_maps','sasl_maps','clamd_state','runtime_exception','component_access','component_forward_health','component_forwarding','component_spam'),'private_capture_scope')
    for suffix,raw in (('json',encoded(row)),('stdout',out),('stderr',err)):
        if not raw:raw=b'\n'
        if name.startswith('component_'):
            first=STATE/'diagnostics'/(name+'.first.'+suffix)
            if not os.path.lexists(first):write(first,raw,group=0,mode=0o600,absent=True)
        path=STATE/'diagnostics'/(name+'.'+suffix)
        if os.path.lexists(path):write(path,raw,group=0,mode=0o600)
        else:write(path,raw,group=0,mode=0o600,absent=True)

def component_failure(kind,error):
    need(kind in ('access','forward_health','forwarding','spam'),'component_failure_scope')
    private_capture({'command':'component_'+kind,'class':type(error).__name__,'errno':getattr(error,'errno',None),'sqlite_errorcode':getattr(error,'sqlite_errorcode',None),'sqlite_errorname':getattr(error,'sqlite_errorname',None)},err=traceback.format_exc().encode()[:131072])

def connect_factory(driver,secret):
    need(secret['user']=='mail_feature_reader'and type(secret['password'])is str and 16<=len(secret['password'])<=256,'runtime_DB_identity')
    def connect():return driver.connect(unix_socket='/run/mysqld/mysqld.sock',user=secret['user'],password=secret['password'],charset='utf8mb4',connect_timeout=2,read_timeout=3,write_timeout=3,autocommit=False,local_infile=False,client_flag=0)
    return connect

def load_configuration():
    raw,_=read(CONFIG,mode=0o600,group=0);value=json.loads(raw,object_pairs_hook=unique)
    need(type(value)is dict and set(value)=={'version','legacy_settings_sha256'}and value['version']==1 and type(value['legacy_settings_sha256'])is str and len(value['legacy_settings_sha256'])==64 and all(c in '0123456789abcdef'for c in value['legacy_settings_sha256']),'runtime_deployment_configuration')
    return value

def main(driver):
    import pwd
    need(os.geteuid()==0,'configuration_root_required');private=STATE.lstat();need(stat.S_ISDIR(private.st_mode)and private.st_uid==0 and stat.S_IMODE(private.st_mode)==0o700,'configuration_private_state')
    roles={name:pwd.getpwnam(name)for name in ('mailadmin','mailsendlimits','vmail')};config=load_configuration();state=PrivateFile(STATE/'configuration.json');fragment=PrivateFile(STATE/'spam-fragment.json')
    need(type(fragment.value)is dict and set(fragment.value)=={'sha256'}and type(fragment.value['sha256'])is str and len(fragment.value['sha256'])==64,'runtime_fragment_state')
    lease=ProcessLease(STATE/'configuration.lock');retention=Retention(GENERATIONS,roles['vmail'].pw_gid,PrivateFile(STATE/'generation-catalog.json'));stop=False
    def terminate(*_):
        nonlocal stop;stop=True
    signal.signal(signal.SIGTERM,terminate);signal.signal(signal.SIGINT,terminate)
    directory=RuntimeDirectory(connect_factory(driver,credential(os.environ['CREDENTIALS_DIRECTORY'])))
    failure_coverage={}
    def read_failure_window(stamp):
        failure_coverage.clear()
        return failures(EVENTS,stamp,capture_status=failure_coverage.update)
    access_pin=None;report_pin=None
    if os.path.lexists(PUBLIC/'access.json'):access_pin=read(PUBLIC/'access.json',mode=0o640,group=roles['mailsendlimits'].pw_gid)[1]['sha256']
    if os.path.lexists(STATE/'configuration-report.json'):report_pin=read(STATE/'configuration-report.json',mode=0o600,group=0)[1]['sha256']
    def publish_access(value):
        nonlocal access_pin
        access_pin=write(PUBLIC/'access.json',encoded(value),group=roles['mailsendlimits'].pw_gid,mode=0o640,prior_pin=access_pin,absent=access_pin is None)
    def publish_forward(generation):
        retention.validate_inventory()
        if os.path.lexists(GENERATIONS/'current'):retained=retention.collect(int(time.time()))
        else:
            need(not retention.state.value['generations'],'generation_current_missing_with_existing_catalog');retained={'removed_registered_generations':0}
        value=compile_generation(GENERATIONS,generation['files'],roles['vmail'].pw_gid,STATE/'compile.conf',private_capture,now=generation['generated_at'],before_publish=retention.register)
        result={key:value[key]for key in ('generation','previous_generation','scripts','compile_seconds','published')};result['retention']=retained;return result
    def spam(payload,domains,aliases):
        def history(metadata,old,new):
            # History is public thresholds only; fixed last transaction, durable.
            for name,raw in (('spam-last-before.conf',old),('spam-last-after.conf',new),('spam-last-change.json',encoded(metadata))):
                path=STATE/name;write(path,raw,group=0,mode=0o600,absent=not os.path.lexists(path))
        value=apply_spam_fragment(FRAGMENT,payload,domains,aliases,config['legacy_settings_sha256'],fragment.value['sha256'],private_capture,native,history)
        fragment.save({'sha256':value['fragment_sha256']});return value
    try:
        while not stop:
            started=time.monotonic();now_us=time.time_ns()//1000
            try:
                validate_state(state.value,now_us)
                inventory=directory.inventory();_,report=cycle(inventory,state.value,now_us,save_state=state.save,publish_access=publish_access,read_failures=read_failure_window,publish_forward=publish_forward,apply_spam=spam,capture_failure=component_failure)
                report['forward_health_coverage']=dict(failure_coverage)
                report['domains']=sorted(inventory['domains']|set(inventory['domain_aliases']))
                report_pin=write(STATE/'configuration-report.json',encoded(report),group=0,mode=0o600,prior_pin=report_pin,absent=report_pin is None)
                print(json.dumps({'component':'feature_configuration','state':report['state'],'failed_components':sorted(report['errors'])}),flush=True)
            except Exception as error:
                private_capture({'command':'runtime_exception','class':type(error).__name__},err=traceback.format_exc().encode()[:131072])
                print(json.dumps({'component':'feature_configuration','state':'unavailable','class':type(error).__name__}),flush=True)
            deadline=started+30
            while not stop and time.monotonic()<deadline:time.sleep(min(.25,deadline-time.monotonic()))
    finally:lease.close()
