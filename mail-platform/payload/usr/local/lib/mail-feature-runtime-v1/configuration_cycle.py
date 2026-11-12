"""Component-isolated publication. Durable decisions precede every public update.

Callbacks are deployment-owned adapters. No HTTP value selects a file or command.
"""
import hashlib,json
from access_policy import snapshot
from forward_generation import plan,summary
from forwarding import need

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def initial_state():
    # Only the deployment transaction may create this initial state.
    return {'version':1,'serial':0,'last_clock_us':0,'health':{},'access':{'revision':0,'published_at':0},
        'spam':{'revision':0,'fingerprint':None,'failed_fingerprint':None},'forward':{'published_at':0}}

def validate_state(state,now_us):
    need(type(state)is dict and set(state)=={'version','serial','last_clock_us','health','access','spam','forward'}and state['version']==1,'configuration_state_schema')
    need(type(now_us)is int and type(state['last_clock_us'])is int and 0<=state['last_clock_us']<=now_us and type(state['serial'])is int and 0<=state['serial']<2**63-1,'configuration_clock_or_serial')
    need(type(state['health'])is dict and len(state['health'])<=10000,'configuration_health_bound')
    for kind,keys in (('access',{'revision','published_at'}),('spam',{'revision','fingerprint','failed_fingerprint'}),('forward',{'published_at'})):
        need(type(state[kind])is dict and set(state[kind])==keys,'configuration_component_state')
        for key,value in state[kind].items():
            if 'fingerprint'in key:need(value is None or type(value)is str and len(value)==64 and all(c in '0123456789abcdef'for c in value),'configuration_fingerprint')
            elif key=='published_at':need(type(value)is int and 0<=value<=now_us,'configuration_component_integer')
            else:need(type(value)is int and 0<=value<2**63,'configuration_component_integer')
    return state

def cycle(inventory,state,now_us,*,save_state,publish_access,read_failures,publish_forward,apply_spam,capture_failure=None):
    """All exceptions remain explicit per component; successes do not mask failures."""
    validate_state(state,now_us);state=json.loads(json.dumps(state));state['last_clock_us']=now_us;save_state(state)
    now=now_us//1000000;settings=inventory['settings'];report={'observed_at':now,'errors':{},'access':None,'spam':None,'forwarding':None}
    access=settings.get('access',{'revision':0,'payload':{'rules':[]}});spam=settings.get('spam',{'revision':0,'payload':{'profiles':[{'domain_id':0,'greylist':4,'add_header':6,'reject':20}]}})
    report['desired']={'access':access['revision'],'spam':spam['revision']}
    try:
        need(access['revision']>=state['access']['revision'],'access_configuration_revision_rollback')
        state['serial']+=1;save_state(state) # A failed publication consumes its serial too.
        public=snapshot(access['payload'],inventory['domain_ids'],inventory['domain_aliases'],state['serial'],now)
        publish_access(public);state['access']={'revision':access['revision'],'published_at':now_us};save_state(state)
        report['access']={'state':'ok','revision':access['revision'],'serial':state['serial']}
    except Exception as error:capture_failure('access',error) if capture_failure is not None else None;report['errors']['access']=type(error).__name__
    try:
        failure_rows=read_failures(now_us);health_known=True
    except Exception as error:
        failure_rows=[];health_known=False;capture_failure('forward_health',error) if capture_failure is not None else None;report['errors']['forward_health']=type(error).__name__
    try:
        generation=plan(inventory['routes'],inventory['domains'],inventory['domain_aliases'],inventory['users'],inventory['aliases'],failure_rows,state['health'],now_us)
        state['health']=generation['health_state'];save_state(state)
        if not health_known:
            # An unreadable/truncated log does not create or clear a persistent hold.
            # Its temporary script preserves local delivery and later personal Sieve.
            generation['files']={name:b'require ["copy"];\n'for name in generation['files']}
        published=publish_forward(generation);state['forward']={'published_at':now_us};save_state(state)
        report['forwarding']=dict(summary(generation),state='ok'if health_known else'incomplete',published=published)
    except Exception as error:capture_failure('forwarding',error) if capture_failure is not None else None;report['errors']['forwarding']=type(error).__name__
    try:
        need(spam['revision']>=state['spam']['revision'],'spam_configuration_revision_rollback')
        fingerprint=digest({'setting':spam,'domains':inventory['domain_ids'],'aliases':inventory['domain_aliases']})
        if fingerprint==state['spam']['failed_fingerprint']:
            report['errors']['spam']='PreviousPublicationFailed'
        elif fingerprint!=state['spam']['fingerprint']:
            # Record the attempted exact configuration before a reload. A crash or
            # partial native failure requires a new revision/supervised recovery.
            state['spam']['failed_fingerprint']=fingerprint;save_state(state)
            applied=apply_spam(spam['payload'],inventory['domain_ids'],inventory['domain_aliases'])
            state['spam']={'revision':spam['revision'],'fingerprint':fingerprint,'failed_fingerprint':None};save_state(state)
            report['spam']=applied
        else:report['spam']={'state':'file_validated','reload_requested':False}
    except Exception as error:capture_failure('spam',error) if capture_failure is not None else None;report['errors']['spam']=type(error).__name__
    report['applied']={kind:state[kind]['revision']for kind in ('access','spam')}
    report['state']='ok'if not report['errors']else'incomplete'
    return state,report
