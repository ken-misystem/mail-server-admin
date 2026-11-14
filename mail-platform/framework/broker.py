"""Constrained local UI protocol; no URLs, commands, paths or keys accepted from PHP."""
import json,os,re,socket,struct,time
from pathlib import Path
from updater import load,save,policy
from release import require,version
ROOT=Path('/var/lib/mail-platform-update')

def status(root=ROOT):
 p=load(root/'policy.json',{'revision':0,'mode':'manual'});i=load(root/'installed.json',{'version':'0.0.0'});a=load(root/'available.json',{});t=load(root/'transaction.json',{})
 offered=a.get('version')
 available=offered if offered and version(offered)>version(i['version']) else None
 pending=[]
 identifier=t.get('id')
 if isinstance(identifier,str) and re.fullmatch('[0-9]{1,30}',identifier):
  generation=load(root/('transaction-'+identifier)/'generation-update.json',{})
  pending=generation.get('retirement_pending',[])
  require(type(pending)is list and all(type(name)is str and re.fullmatch('[a-z][a-z0-9-]{0,30}',name) for name in pending),'retirement_status')
 return {'status':'ok','revision':p['revision'],'mode':p['mode'],'installed_version':i['version'],'available_version':available,'phase':t.get('phase','idle'),'impact':a.get('impact') if available else None,'retirement_pending':pending}

def operation(req,root=ROOT):
 require(isinstance(req,dict),'request')
 if req.get('operation')=='status':require(set(req)=={'operation'},'fields');return status(root)
 require(set(req)=={'operation','mode','revision','actor','request_id'},'fields')
 require(req['operation']in('settings','apply')and req['mode']in('manual','automatic'),'operation')
 require(type(req['revision'])is int and req['revision']>=0,'revision');require(isinstance(req['actor'],str)and re.fullmatch(r'[1-9][0-9]{0,19}',req['actor']),'actor')
 require(isinstance(req['request_id'],str)and re.fullmatch(r'[a-f0-9]{32}',req['request_id']),'request_id')
 current=load(root/'policy.json',{'revision':0,'mode':'manual'});require(current['revision']==req['revision'],'revision_conflict')
 requests=root/'requests';requests.mkdir(mode=0o700,exist_ok=True);receipt=requests/(req['request_id']+'.json')
 require(not receipt.exists(),'request_replay')
 record={'at':time.time(),'request':req,'phase':'received'};save(receipt,record)
 if req['operation']=='settings':save(root/'policy.json',policy(current,req['mode'],req['revision']))
 else:
  require(not(root/'manual-request.json').exists(),'request_pending');save(root/'manual-request.json',{'request_id':req['request_id'],'actor':req['actor']})
 record['phase']='accepted';save(receipt,record);return {'status':'ok','request_id':req['request_id']}

def serve():
 require(os.geteuid()==0,'root_required');os.umask(0o077)
 cfg=load('/etc/mail-platform/update-ui.json');uid=cfg['allowed_uid'];require(type(uid)is int and uid>0,'peer_uid')
 # Socket activation only; the root-only systemd definition chooses the path/group.
 require(os.environ.get('LISTEN_PID')==str(os.getpid())and os.environ.get('LISTEN_FDS')=='1','socket_activation')
 server=socket.socket(fileno=3)
 while True:
  conn,_=server.accept()
  with conn:
   conn.settimeout(3)
   try:
    _,peer,_=struct.unpack('3i',conn.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));require(peer==uid,'peer_rejected')
    raw=bytearray()
    while len(raw)<4097 and not raw.endswith(b'\n'):
     b=conn.recv(min(1024,4097-len(raw)))
     if not b:break
     raw.extend(b)
    require(len(raw)<=4096 and raw.endswith(b'\n')and raw.count(b'\n')==1,'packet')
    reply=operation(json.loads(raw))
   except Exception:reply={'status':'refused'}
   conn.sendall(json.dumps(reply).encode()+b'\n')
if __name__=='__main__':serve()
