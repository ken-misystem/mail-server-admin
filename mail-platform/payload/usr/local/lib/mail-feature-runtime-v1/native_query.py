"""Finite read-only Rspamd RPC. Only root callers and fixed commands, bounded frames."""
import base64,hashlib,json,os,re,selectors,socket,stat,struct,subprocess,time
SOCKET='/run/mail-feature-rspamd-native-v1/query.sock'
MAX_STREAM=2097152;MAX_REPLY=4194304
COMMANDS={'settings':('configdump','settings','-j'),'antivirus':('configdump','antivirus','-j'),'dkim':('configdump','dkim_signing','-j'),'mime_types':('configdump','mime_types','-j'),'rspamd_check':('configtest',),'managed_symbols':('configdump','-d','-j')}
def need(ok,why):
 if not ok:raise ValueError(why)
def unique(pairs):
 result={}
 for k,v in pairs:need(k not in result,'duplicate_RPC_key');result[k]=v
 return result
def frame(channel,limit):
 raw=bytearray();deadline=time.monotonic()+30
 while b'\n'not in raw:
  need(time.monotonic()<deadline and len(raw)<limit,'RPC_bound');chunk=channel.recv(min(65536,limit-len(raw)));need(bool(chunk),'RPC_EOF');raw.extend(chunk)
 need(raw.endswith(b'\n')and raw.count(b'\n')==1,'RPC_frame');return json.loads(raw,object_pairs_hook=unique)
def execute(name):
 need(name in COMMANDS,'native_query_scope');start=time.monotonic();buffers=[bytearray(),bytearray()];p=None;row={'command':name,'exit':None,'timeout':False,'overflow':False,'exception_class':None,'errno':None}
 try:
  p=subprocess.Popen(['/usr/bin/rspamadm',*COMMANDS[name]],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
  with selectors.DefaultSelector()as sel:
   for i,stream in enumerate((p.stdout,p.stderr)):sel.register(stream,selectors.EVENT_READ,i)
   while sel.get_map():
    if time.monotonic()-start>20:row['timeout']=True;break
    for key,_ in sel.select(.05):
     chunk=os.read(key.fileobj.fileno(),8192)
     if not chunk:sel.unregister(key.fileobj);continue
     left=MAX_STREAM-sum(map(len,buffers));buffers[key.data].extend(chunk[:max(0,left)])
     if len(chunk)>left:row['overflow']=True;break
    if row['overflow']:break
  if row['timeout']or row['overflow']:p.kill()
  row['exit']=p.wait(timeout=3)
 except Exception as error:
  row['exception_class']=type(error).__name__;row['errno']=getattr(error,'errno',None)
  import traceback
  detail=traceback.format_exc().encode()[:65536];left=MAX_STREAM-sum(map(len,buffers));buffers[1].extend(detail[:max(0,left)])
 finally:
  if p is not None:
   if p.poll()is None:p.kill();p.wait(timeout=3)
   p.stdout.close();p.stderr.close()
 row['seconds']=time.monotonic()-start
 for i,key in enumerate(('stdout','stderr')):row[key+'_bytes']=len(buffers[i]);row[key+'_sha256']=hashlib.sha256(buffers[i]).hexdigest()
 return row,bytes(buffers[0]),bytes(buffers[1])
def handle(request,peer_uid,runner=execute):
 need(peer_uid==0,'root_query_peer');need(type(request)is dict and set(request)=={'command','nonce'}and request['command']in COMMANDS and type(request['nonce'])is str and re.fullmatch('[a-f0-9]{32}',request['nonce']),'query_request')
 row,out,err=runner(request['command']);need(len(out)+len(err)<=MAX_STREAM,'query_output_bound')
 return {'status':'ok','nonce':request['nonce'],'metadata':row,'stdout':base64.b64encode(out).decode(),'stderr':base64.b64encode(err).decode()}
def query(name):
 import secrets
 need(os.geteuid()==0 and name in COMMANDS,'root_query_caller');parts=SOCKET.split('/');fds=[os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)]
 try:
  for part in parts[1:-1]:
   fds.append(os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fds[-1]));s=os.fstat(fds[-1]);need(s.st_uid==0 and not s.st_mode&0o022,'RPC_parent')
  before=os.stat(parts[-1],dir_fd=fds[-1],follow_symlinks=False);need(stat.S_ISSOCK(before.st_mode)and before.st_uid==0 and stat.S_IMODE(before.st_mode)==0o600,'RPC_socket');nonce=secrets.token_hex(16)
  with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)as ch:
   ch.settimeout(30);ch.connect(SOCKET);pid,uid,gid=struct.unpack('3i',ch.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));need(pid>0 and uid==0,'RPC_listener_identity');after=os.stat(parts[-1],dir_fd=fds[-1],follow_symlinks=False);need((before.st_dev,before.st_ino,before.st_uid,before.st_gid,before.st_mode)==(after.st_dev,after.st_ino,after.st_uid,after.st_gid,after.st_mode),'RPC_socket_changed');ch.sendall((json.dumps({'command':name,'nonce':nonce})+'\n').encode());r=frame(ch,MAX_REPLY)
  need(r.get('status')=='ok'and r.get('nonce')==nonce,'query_reply');out=base64.b64decode(r['stdout'],validate=True);err=base64.b64decode(r['stderr'],validate=True);row=r['metadata'];need(row['command']==name and len(out)+len(err)<=MAX_STREAM and all(len(b)==row[n+'_bytes']and hashlib.sha256(b).hexdigest()==row[n+'_sha256']for n,b in(('stdout',out),('stderr',err))),'query_reply_integrity');return row,out,err
 finally:
  for fd in reversed(fds):os.close(fd)
def main(runner=execute,max_requests=None,profile='/etc/mail-feature-runtime-v1/rspamd-context.json'):
 from runtime_files import read
 expected=json.loads(read(profile,mode=0o644,group=0,limit=1024)[0]);need(set(expected)=={'uid','gid','groups'}and expected['uid']>0 and expected['gid']>0,'native_role_profile');f=dict(line.split(':',1)for line in open('/proc/self/status').read().splitlines()if':'in line)
 need(f['Uid'].split()==[str(expected['uid'])]*4 and f['Gid'].split()==[str(expected['gid'])]*4 and sorted(int(x)for x in f['Groups'].split())==expected['groups']and f['NoNewPrivs'].strip()=='1'and all(int(f[k].strip(),16)==0 for k in('CapInh','CapPrm','CapEff','CapAmb')),'query_worker_identity');need(os.environ.get('LISTEN_PID')==str(os.getpid())and os.environ.get('LISTEN_FDS')=='1','query_activation')
 listener=socket.socket(fileno=3);need(listener.family==socket.AF_UNIX and listener.getsockname()==SOCKET and listener.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN)==1,'query_activation_socket');listener.set_inheritable(False)
 handled=0
 while max_requests is None or handled<max_requests:
  ch,_=listener.accept();handled+=1
  try:
   ch.settimeout(30);_,uid,_=struct.unpack('3i',ch.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));need(uid==0,'root_query_peer');reply=handle(frame(ch,2048),uid,runner)
  except Exception as error:reply={'status':'error','reason':type(error).__name__}
  try:ch.sendall(json.dumps(reply,separators=(',',':')).encode()+b'\n')
  except OSError:pass
  finally:ch.close()
if __name__=='__main__':
 import sys
 from pathlib import Path
 sys.path.insert(0,str(Path(__file__).resolve().parent))
 main()
