"""First activation of previously absent updater units; no host defaults reset."""
import json,os
from pathlib import Path
from host_transaction import regular,durable_json
from release import canonical,sha

UNITS=('mail-platform-update-ui.socket','mail-platform-update-ui.service',
       'mail-platform-update.timer','mail-platform-update.service')
ENABLED=('mail-platform-update-ui.socket','mail-platform-update.timer')
LINKS={'mail-platform-update-ui.socket':'/etc/systemd/system/sockets.target.wants/mail-platform-update-ui.socket',
       'mail-platform-update.timer':'/etc/systemd/system/timers.target.wants/mail-platform-update.timer'}
DROPIN='/etc/systemd/system/mail-platform-update.timer.d/60-initial-adoption.conf'
DELAY=b'[Timer]\nOnBootSec=\nOnActiveSec=15min\n'
KEY_PIN='6adf5e38d694aa4b16c74c28e50bb197e4d617035b39e03aaad8e7d39e973e5e'

def require(ok,reason):
    if not ok:raise ValueError(reason)

def resources(public_key,allowed_uid):
    require(sha(public_key)==KEY_PIN,'enrollment_key_pin')
    require(type(allowed_uid)is int and allowed_uid>0,'enrollment_peer_uid')
    return {'/etc/mail-platform/update-source.json':(canonical({'repository':'ken-misystem/mail-server-admin'}),0o600),
            '/etc/mail-platform/update-ui.json':(canonical({'allowed_uid':allowed_uid}),0o600),
            '/etc/mail-platform/release-public.pem':(public_key,0o644),
            '/etc/mail-platform/private/github-token':(b'',0o600),DROPIN:(DELAY,0o644)}

class Enrollment:
    def __init__(self,evidence,contract,commands,probe):
        self.path=Path(evidence)/'updater-enrollment.json';self.contract=contract;self.commands=commands;self.probe=probe
        require(set(contract)=={'format','units','files','policy','enable'},'enrollment_contract')
        require(contract['format']==1 and tuple(contract['units'])==UNITS and tuple(contract['enable'])==ENABLED
                and contract['policy']=={'revision':0,'mode':'manual'},'enrollment_contract_values')
        required={f'/etc/systemd/system/{n}' for n in UNITS}|{DROPIN,
            '/etc/mail-platform/update-source.json','/etc/mail-platform/update-ui.json',
            '/etc/mail-platform/release-public.pem','/etc/mail-platform/private/github-token'}
        require(set(contract['files'])==required,'enrollment_file_inventory')
        self.record=None
    def state(self,name):
        raw=self.commands.run('new_unit_state',['/usr/bin/systemctl','show',name,'-p','LoadState,ActiveState,SubState,MainPID,UnitFileState,Job'])
        row=dict(line.split('=',1) for line in raw.decode().splitlines());row.setdefault('MainPID','0');return row
    def save(self):durable_json(self.path,self.record)
    def preflight(self):
        require(not self.path.exists(),'enrollment_previous_journal')
        require(not os.path.lexists('/var/lib/mail-platform-update/manual-request.json'),'enrollment_manual_request_exists')
        require(all(self.state(n)['LoadState']=='not-found' for n in UNITS),'enrollment_unit_exists')
        require(not os.path.lexists('/run/mail-platform-update/ui.sock'),'enrollment_socket_exists')
        for name in self.contract['files']:require(not os.path.lexists(name),'enrollment_file_exists')
        for name in LINKS.values():require(not os.path.lexists(name),'enrollment_enable_link_exists')
        self.record={'contract_sha256':sha(canonical(self.contract)),'phase':'prepared','pending':None,'operations':[]};self.save()
        return {'status':'PASS'}
    def guard(self):
        require(self.record is not None and self.record['pending'] is None,'enrollment_pending_operation')
        for name,expected in self.contract['files'].items():require(regular(name)[1]==expected,'enrollment_file_drift')
        policy_raw,policy_attr=regular('/var/lib/mail-platform-update/policy.json')
        require(policy_attr['uid']==policy_attr['gid']==0 and policy_attr['mode']==0o600
                and json.loads(policy_raw)==self.contract['policy'],'enrollment_policy_drift')
        require(not os.path.lexists('/var/lib/mail-platform-update/manual-request.json'),'enrollment_manual_request_exists')
        for unit,name in LINKS.items():
            enabled=any(row['action']=='enable' and row['unit']==unit for row in self.record['operations'])
            if enabled:require(Path(name).is_symlink() and str(Path(name).resolve())=='/etc/systemd/system/'+unit,'enrollment_enable_link_drift')
            else:require(not os.path.lexists(name),'enrollment_unexpected_enable_link')
    def operation(self,action,name):
        self.guard();before=self.state(name)
        require(before['LoadState']=='loaded' and before.get('Job','') in ('','0'),'enrollment_unsettled')
        require(before['ActiveState']=='inactive' and before['MainPID']=='0','enrollment_unexpected_activation')
        if action=='enable':require(before['UnitFileState']=='disabled','enrollment_unexpected_enablement')
        else:require(before['UnitFileState']=='enabled','enrollment_not_enabled')
        self.record['pending']={'action':action,'unit':name,'before':before};self.save()
        args=['/usr/bin/systemctl',action,'--quiet']
        self.commands.run('enrollment_'+action,args+[name],timeout=60)
        after=self.state(name)
        require(after['UnitFileState']=='enabled','enrollment_enable_incomplete')
        if action=='start':require(after['ActiveState']=='active','enrollment_start_incomplete')
        self.record['operations'].append(dict(self.record['pending'],after=after));self.record['pending']=None;self.save()
    def activate(self):
        require(self.record is not None and self.record['phase']=='prepared','enrollment_not_prepared')
        self.guard();self.record['phase']='activating';self.save()
        for name in ENABLED:self.operation('enable',name)
        self.operation('start',ENABLED[0])
        # Probe must use the real permitted UID; it may start only the UI broker.
        require(self.probe().get('status')=='PASS','enrollment_UI_probe')
        require(self.state('mail-platform-update.service')['ActiveState']=='inactive','enrollment_worker_started_early')
        self.operation('start',ENABLED[1]);self.record['phase']='active';self.save()
        return self.verify()
    def verify(self):
        self.guard();require(self.record['phase']=='active','enrollment_not_active')
        for name in ENABLED:
            actual=self.state(name);require(actual['UnitFileState']=='enabled' and actual['ActiveState']=='active','enrollment_not_persistent')
        return {'status':'PASS','mode':'manual','first_check_delay_seconds':900,'retry':False}

def probe_status(commands,uid,gid,version):
    require(type(uid)is int and uid>0 and type(gid)is int and gid>0,'enrollment_probe_identity')
    code='''import os,socket,json,sys
os.setgroups([]);os.setgid(int(sys.argv[2]));os.setuid(int(sys.argv[1]))
s=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect('/run/mail-platform-update/ui.sock')
s.sendall(b'{"operation":"status"}\\n');raw=bytearray()
while not raw.endswith(b'\\n') and len(raw)<4096:
 chunk=s.recv(4096-len(raw))
 if not chunk:break
 raw.extend(chunk)
s.close();value=json.loads(raw)
assert value['status']=='ok' and value['mode']=='manual' and value['revision']==0 and value['installed_version']==sys.argv[3]
print(json.dumps({'status':'PASS','uid':os.getuid(),'gid':os.getgid(),'installed_version':value['installed_version']}))
'''
    raw=commands.run('enrollment_UI_status',['/usr/bin/python3','-I','-S','-B','-c',code,str(uid),str(gid),version],timeout=10)
    result=json.loads(raw);require(result.get('status')=='PASS','enrollment_UI_status');return result
