"""Fixed native publication actions; no frontend-supplied paths or argv."""
import base64,hashlib,json,os,pathlib,secrets,socket,stat,sys,time,traceback
import read_support as support
from apply_adapter import TARGETS,digest
from rspamd_diagnostics import cache_diagnostics
STATE=pathlib.Path("/var/lib/mail-protection-admin-v1")
AVSTATE=pathlib.Path("/var/lib/mail-antivirus-v1")
COORD=pathlib.Path("/run/mail-client-certificates-v1/coordination")
BACKEND="mail-client-cert-postfix-backend.service"
def need(v,label):
 if not v:raise ValueError(label)
def keys(value,out=None,depth=0):
 out=set()if out is None else out
 need(depth<20 and len(out)<100000,"symbol_dump_bound")
 if type(value)is dict:
  out.update(value)
  for child in value.values():
   if type(child)in(dict,list):keys(child,out,depth+1)
 elif type(value)is list:
  for child in value:
   if type(child)in(dict,list):keys(child,out,depth+1)
 return out

def require_symbols(value,antivirus):
 expected={"MAIL_ADMIN_PROTECTION_LOADED","MAIL_ADMIN_ATTACHMENT","MAIL_ADMIN_ATTACHMENT_FAIL"}
 if antivirus:expected|={"MAIL_ADMIN_VIRUS","MAIL_ADMIN_VIRUS_FAIL"}
 seen={}
 def visit(v,depth=0):
  need(depth<20,"symbol_dump_depth")
  if type(v)is dict:
   for name,item in v.items():
    if name in expected:
     need(type(item)is dict and item.get("type")=="virtual"and type(item.get("score"))in(int,float)and item["score"]==0 and item.get("disabled")is False,"managed_virtual_symbol_not_valid")
     need(name not in seen or seen[name]==item,"managed_symbol_duplicate_mismatch");seen[name]=item
    if type(item)in(dict,list):visit(item,depth+1)
  elif type(v)is list:
   for item in v:
    if type(item)in(dict,list):visit(item,depth+1)
 visit(value);need(set(seen)==expected,"managed_virtual_symbols_missing")
 return sorted(seen)

def engine_version():
 with socket.socket(socket.AF_UNIX)as channel:
  channel.settimeout(5);channel.connect("/run/clamav/clamd.ctl");channel.sendall(b"zVERSION\0");raw=channel.recv(4096)
 need(raw.startswith(b"ClamAV 1.4.6/")and raw.endswith(b"\0"),"managed_engine_version")
 return raw
class Runner:
 def __init__(self,context,save,connect,locked):
  self.context=context;self.save=save;self.connect=connect;self.locked=locked;self.r={"native":[]}
 def lock_held(self):return self.locked is True
 def native(self,args,seconds=45):
  out,err,row=support.command(self.r,"step_"+str(len(self.r["native"])),args,seconds=seconds,required=False,limit=2097152)
  need(row["exit"]==0 and not err and not row["timeout"]and not row["overflow"],"fixed_native_failed")
  return out
 def p12_clear(self):
  connection=self.connect()
  try:
   with connection.cursor()as q:
    q.execute("SET SESSION max_statement_time=5");q.execute("START TRANSACTION READ ONLY")
    q.execute("SELECT COUNT(*) FROM mail_management.mail_client_downloads WHERE state IN ('ready','consumed','unknown') AND expires_at>UTC_TIMESTAMP()")
    rows=q.fetchall();need(len(rows)==1 and rows[0][0]==0,"active_certificate_download_blocks_reload")
  finally:connection.rollback();connection.close()
 def prerequisites(self,kind,desired):
  need(kind in TARGETS and self.locked,"fixed_publication_scope")
  if kind=="upstream":self.p12_clear()
  if kind=="scanner"and desired["payload"]["antivirus"]:
   engine_version()
   path=AVSTATE/"definitions-status.json";s=path.lstat()
   need(stat.S_ISREG(s.st_mode)and s.st_uid==self.context["engine_uid"]and s.st_gid==111 and stat.S_IMODE(s.st_mode)==0o640 and s.st_nlink==1 and s.st_size<=16384,"definition_status_attributes")
   raw=path.read_bytes();after=path.lstat();need((s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),"definition_status_drift")
   value=json.loads(raw);need(value["status"]=="pass"and -3600<=time.time()-value["databases"]["daily"]["build_epoch"]<=172800,"official_definitions_stale")
 def review_candidate(self,kind,candidate):
  need(set(candidate)==set(TARGETS[kind]),"fixed_candidate_inventory")
  for index,(path,raw)in enumerate(candidate.items()):
   need(type(raw)is bytes and len(raw)<=2097152,"fixed_candidate_bound")
   support.write(support.WORK/("candidate-"+kind+"-"+str(index)+".data"),raw)
 def query(self,name):
  sys.path.insert(0,"/usr/local/lib/mail-feature-runtime-v1")
  from native_query import query
  row,out,err=query(name)
  self.save("query-"+str(len(self.r["native"]))+"-"+name+".json",row)
  support.write(support.WORK/("query-"+str(len(self.r["native"]))+"-"+name+".stdout"),out)
  support.write(support.WORK/("query-"+str(len(self.r["native"]))+"-"+name+".stderr"),err)
  need(row["exit"]==0 and not row["timeout"]and not row["overflow"]and row["exception_class"]is None,"Rspamd_native_failed")
  # Accept only the already-validated read-only hyperscan cache warnings.
  diagnostic=b"\n".join(line for line in err.splitlines()if line.strip()!=b"syntax OK")
  cache_diagnostics(diagnostic)
  if name=="rspamd_check"and b"syntax OK"in err and b"syntax OK"not in out:out+=b"\nsyntax OK\n"
  self.r["native"].append(dict(row,label="rspamd_"+name))
  return out
 def validate(self,kind):
  if kind=="scanner":
   out=self.query("rspamd_check");need(b"syntax OK"in out,"Rspamd_syntax_not_confirmed")
  else:
   for config in("/etc/postfix","/etc/mail-client-certificates-v1/postfix"):
    for arg in("-n","-M","-P"):self.native(["/usr/sbin/postconf","-c",config,arg])
 def children(self):
  raw=self.native(["/usr/bin/systemctl","show","--value","--property=MainPID","rspamd.service"]);pid=int(raw.strip());need(pid>1,"Rspamd_master")
  children=pathlib.Path("/proc/"+str(pid)+"/task/"+str(pid)+"/children").read_text().split();need(len(children)<=32,"Rspamd_children_bound")
  def birth(child):
   try:return pathlib.Path("/proc/"+child+"/stat").read_text().rsplit(")",1)[1].split()[19]
   except(FileNotFoundError,ProcessLookupError):return None
  return pid,{p:birth(p)for p in children},birth
 def settle(self):
  start=time.time();end=time.monotonic()+30;last=None;stamp=None;stable=0;samples=[]
  while True:
   raw=self.native(["/usr/bin/systemctl","show","--all","--no-pager","--property=Id,LoadState,ActiveState,SubState,MainPID,Job","postfix.service",BACKEND,"mail-client-cert-gate.service"])
   rows={v["Id"]:v for b in raw.decode().strip().split("\n\n")for v in[dict(x.split("=",1)for x in b.splitlines())]}
   ready=json.loads(support.protected(COORD/"ready.json")[0]);mounted=json.loads(support.protected(COORD/"mounted.json")[0])
   current=ready.get("observed_at");valid=(len(rows)==3 and all(x["LoadState"]=="loaded"and x["ActiveState"]=="active"and not x["Job"]for x in rows.values())and ready.get("valid")is True and ready.get("boot_id")==mounted.get("boot_id")==pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()and ready.get("private_namespace")==mounted.get("private_namespace")and start<=current<=time.time()and time.time()-current<=5)
   identity={n:(r["MainPID"],r["ActiveState"])for n,r in rows.items()}
   stable=stable+1 if valid and identity==last and current!=stamp else(1 if valid else 0);samples.append({"valid":valid,"stable":stable,"observed_at":current});last=identity;stamp=current
   if stable>=3:self.save("settlement-"+str(len(self.r["native"]))+".json",{"samples":samples,"actions_retried":False});return
   need(time.monotonic()<end,"socket_generation_settlement_timeout");time.sleep(1)
 def reload(self,kind):
  if kind=="scanner":
   master,children,birth=self.children();self.native(["/usr/bin/systemctl","reload","rspamd.service"])
   end=time.monotonic()+90
   while any(birth(p)==start for p,start in children.items()if start is not None):
    need(time.monotonic()<end,"Rspamd_old_workers_remain");time.sleep(.2)
   now,active,unused=self.children();need(now==master and bool(active),"Rspamd_reload_generation")
  else:self.native(["/usr/bin/systemctl","reload","postfix.service"]);self.settle()
 def verify_effective(self,kind,desired,candidates):
  for path,raw in candidates.items():need(support.protected(pathlib.Path(path))[1]["sha256"]==digest(raw),"installed_candidate_drift")
  if kind=="scanner":
   require_symbols(json.loads(self.query("managed_symbols")),desired["payload"]["antivirus"])
   if desired["payload"]["antivirus"]:engine_version()
 def verify_restored(self,kind):self.validate(kind)
 def capture_failure(self,kind,revision,error):
  support.write(support.WORK/("failure-"+str(time.time_ns())+".txt"),traceback.format_exc().encode()[:131072])
