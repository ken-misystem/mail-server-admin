"""One durable publication cycle under the same fixed deployment lock."""
import base64,fcntl,json,os,pathlib,sqlite3,stat,sys,time,uuid
ROOT=pathlib.Path(__file__).resolve().parent
sys.path[:0]=[str(ROOT/"runtime"),str(ROOT),"/usr/local/lib/mail-feature-admin-v1","/usr/local/lib/mail-feature-runtime-v1","/usr/local/lib/mail-send-limits-v1/pymysql-1.2.3-py3-none-any.whl"]
import read_support as support
from journal import Journal,atomic
from apply_adapter import PublicationAdapter,TARGETS
from publication import publish_one
from store import SettingsStore
from fixed_runner import Runner
STATE=pathlib.Path("/var/lib/mail-protection-admin-v1")
def need(v,label):
 if not v:raise ValueError(label)
def save_health(state):
 fields=dict(x.split(":",1)for x in pathlib.Path("/proc/self/status").read_text().splitlines()if":"in x)
 identity={k:fields[k].strip()for k in("Uid","Gid","Groups","NoNewPrivs","CapInh","CapBnd","CapPrm","CapEff","CapAmb")}
 need(identity["Uid"].split()==["0"]*4 and identity["NoNewPrivs"]=="1"and all(int(identity[k],16)==0 for k in("CapInh","CapBnd","CapPrm","CapEff","CapAmb")),"publisher_privileges")
 # Private metadata only; payload/credentials are absent.
 atomic(STATE/"health.json",(json.dumps({"status":"pass","phase":state,"observed_at":time.time(),"identity":identity},sort_keys=True)+"\n").encode(),0o600,0,0)
def main():
 need(os.geteuid()==0,"publisher_root")
 fd=os.open("/run/lock/mail-feature-activation-v1.lock",os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600);s=os.fstat(fd)
 need(s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600,"publication_lock_attributes")
 try:
  try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:save_health("deployment_locked");return
  context=json.loads(support.protected(STATE/"context.json")[0])
  path=pathlib.Path("/var/lib/mail-feature-admin-v1/controls.sqlite");s=path.lstat();need(stat.S_ISREG(s.st_mode)and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1,"existing_controls_database")
  db=sqlite3.connect(path.as_uri()+"?mode=rw",uri=True,timeout=1);db.execute("PRAGMA synchronous=FULL")
  try:
   store=SettingsStore(db,lambda *a:(_ for _ in()).throw(ValueError("publisher_no_frontend_actor")),time.time)
   import pymysql
   def connect():return pymysql.connect(unix_socket="/run/mysqld/mysqld.sock",user="root",charset="utf8mb4",autocommit=False,local_infile=False,connect_timeout=3,read_timeout=6,write_timeout=6)
   for kind in("scanner","upstream"):
    desired,secret=store.current(kind)
    if desired["phase"]=="applying":
     store.finish_apply(kind,desired["revision"],applied=False,restored=False);raise ValueError("interrupted_publication_held")
    if desired["phase"]!="pending":continue
    work=STATE/"transactions"/uuid.uuid4().hex;work.mkdir(mode=0o700);support.WORK=support.RUN=work
    save=lambda name,value:support.evidence(work/name,value)
    runner=Runner(context,save,connect,True);journal=Journal(work,expected=context["expected"][kind])
    adapter=PublicationAdapter(journal,lambda p:support.protected(p)[0],runner,{p:base64.b64decode(v,validate=True)for p,v in context["main_baselines"].items()},context["expected"],base64.b64decode(context["loader_base"],validate=True))
    outcome=publish_one(store,adapter,kind);save("outcome.json",outcome);save("native.json",runner.r)
    need(outcome["state"]=="applied","publication_failed_or_unknown")
    context["expected"][kind]={p:support.protected(pathlib.Path(p))[1]["sha256"]for p in TARGETS[kind]}
    atomic(STATE/"context.json",(json.dumps(context,sort_keys=True,indent=2)+"\n").encode(),0o600,0,0)
   save_health("idle")
  finally:db.close()
 finally:os.close(fd)
if __name__=="__main__":main()
