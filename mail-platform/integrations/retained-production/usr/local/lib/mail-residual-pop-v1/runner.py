from thresholds import for_recipient as spam_threshold_for_recipient
"""One coordinated residual POP cycle; invoked under a persistent failure latch."""
import ast,base64,csv,fcntl,hashlib,io,json,os,pwd,re,shutil,stat,subprocess,time,traceback,types
from pathlib import Path
import continuation_policy as policy
import header_inventory
import workflow
import read_support as support
WORK=Path("/root/mail-import-continuation-v2")
RECOVER=Path("/root/mail-import-continuation-recover-v2")
PROGRAM=Path("/usr/local/sbin/xmail-pop-migrate.py")
PROGRAM_SHA="b938a99830bdf69888b7425a40e86a25f15715d08ef94ca38672092ae172729a"
COMPAT=Path("/usr/local/lib/mail-pop-compat-v1/compat.py")
TIMER="mail-pop-general-dispatch.timer"
SERVICES=("postfix.service","dovecot.service","mariadb.service","rspamd.service","php8.4-fpm.service","mail-send-limits-v1.service")
SQL="SET SESSION max_statement_time=5; START TRANSACTION READ ONLY; SELECT u.id,u.email,u.active,(SELECT COUNT(*) FROM mail_management.mail_pop_accounts p WHERE p.user_id=u.id) FROM mailserver.virtual_users u WHERE u.id IN (3,4,5,7) ORDER BY u.id; COMMIT;"
def run(packet):
 mode=packet["mode"];support.need(mode=="run","mode")
 root=WORK if mode=="run"else RECOVER;support.WORK=support.RUN=root
 r={"status":"fail","phase":"guard","mode":mode,"native":[],"failures":[],"targets":[],"MX_changed":False,"port25_changed":False,"real_mail_test_sent":False,"other_VM_CT_operations":False,"history_reset":False,"credentials_changed":False,"DB_updated":False,"automatic_retry":False,"started_epoch":time.time()}
 created=paused=False;control=None;module=None;timer_before=None;current=None;stable=None;refs_before=None;checkpoint=None
 def durable_record(path,value):
  support.evidence(path,value)
  r.setdefault("artifact_sha256",{})[str(path.relative_to(root))]=support.protected(path,33554432)[1]["sha256"]
  fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
  try:os.fsync(fd)
  finally:os.close(fd)
 def native(label,args,seconds=30,required=True):
  index=len(r["native"]);start=time.time()
  support.evidence(root/"invocations"/(str(index).zfill(3)+"-"+label+".intent.json"),{"argv":args,"started_epoch":start})
  try:out,err,row=support.command(r,label,args,seconds=seconds,limit=16777216,required=False)
  finally:support.evidence(root/"invocations"/(str(index).zfill(3)+"-"+label+".completion.json"),{"start_epoch":start,"end_epoch":time.time(),"native":r["native"][index]if len(r["native"])>index else None})
  row["reason_classes"]=support.finite_native_reasons(err)
  if required:support.need(row["exit"]==0 and not err and not row["timeout"]and not row["overflow"],"native_"+label)
  return out,err,row
 def show(label,names):
  out,err,row=native(label,["/usr/bin/systemctl","show","--all","--no-pager","--property=Id,LoadState,ActiveState,SubState,MainPID,UnitFileState",*names])
  values=[dict(line.split("=",1)for line in block.splitlines())for block in out.decode().strip().split("\n\n")]
  support.need({v["Id"]for v in values}==set(names)and len(values)==len(names),"unit_inventory")
  return {v["Id"]:v for v in values}
 def refs():
  return {name:support.protected(Path(name))[1]for name in("/etc/postfix/main.cf","/etc/postfix/master.cf","/etc/dovecot/dovecot.conf",str(PROGRAM),str(COMPAT))}
 def identities():
  raw,err,row=native("target_identity_"+str(len(r["native"])),["/usr/bin/mariadb","--no-defaults","--protocol=socket","--socket=/run/mysqld/mysqld.sock","--user=root","--batch","--skip-column-names","--execute",SQL])
  wanted={x["user_id"]:x["folded_sha256"]for x in packet["targets"]};found={}
  for line in raw.decode().splitlines():
   uid,email,active,associated=line.split("\t");support.need(uid.isdigit(),"target_id")
   uid=int(uid)
   support.need(uid in wanted and uid not in found and active=="1"and associated=="0"and support.sha(email.casefold().encode())==wanted[uid],"target_identity_or_POP_changed")
   module._uidl_fetch_argv(email);found[uid]=email
  support.need(set(found)==set(policy.IDS),"four_fixed_targets")
  return found
 def account1():
  raw,meta=support.protected(Path("/etc/mail-pop/migration-state.json"),4096);value=json.loads(raw)
  support.need(value=={"version":1,"account_id":"1","phase":"idle","generation":value.get("generation")}and type(value["version"])is int and type(value["generation"])is int and 0<=value["generation"]<=1000000000,"account1_state")
  return value
 def histories():
  actor=pwd.getpwnam("mailpop");base=Path("/var/lib/mail-pop/accounts");out={}
  st=base.lstat();support.need(stat.S_ISDIR(st.st_mode)and st.st_uid==actor.pw_uid and stat.S_IMODE(st.st_mode)==0o700,"history_parent")
  entries=list(base.iterdir());support.need(len(entries)<=1000,"history_bound")
  for entry in entries:
   support.need(re.fullmatch("[1-9][0-9]{0,19}",entry.name)is not None,"history_name")
   st=entry.lstat();support.need(stat.S_ISDIR(st.st_mode)and st.st_uid==actor.pw_uid and stat.S_IMODE(st.st_mode)==0o700,"history_directory")
   if entry.name=="1":continue
   st=(entry/"fetchids").lstat()
   support.need(stat.S_ISREG(st.st_mode)and(st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode),st.st_nlink,st.st_size)==(actor.pw_uid,actor.pw_gid,0o600,1,0),"non_ken_history_nonempty")
   out[entry.name]=[st.st_dev,st.st_ino,st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode),st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns]
  return out
 def acquire_general(require_idle=True):
  actor=pwd.getpwnam("mailpop");path=Path("/var/lib/mail-pop/locks/migration-general.lock");st=path.parent.lstat()
  support.need(stat.S_ISDIR(st.st_mode)and st.st_uid==actor.pw_uid and stat.S_IMODE(st.st_mode)==0o700,"general_lock_parent")
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   st=os.fstat(fd);support.need(stat.S_ISREG(st.st_mode)and(st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode),st.st_nlink)==(actor.pw_uid,actor.pw_gid,0o600,1),"general_lock_metadata")
   fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   support.need((st.st_dev,st.st_ino)==(path.lstat().st_dev,path.lstat().st_ino),"general_lock_binding")
   if require_idle:support.need(module.general_barrier()["phase"]=="idle","general_not_idle")
   return fd
  except BaseException:os.close(fd);raise
 def release_known(saved,child_exited):
  fd=acquire_general(False)
  try:
   support.need(identities()==emails,"target_changed_before_release")
   support.need(refs()==refs_before,"configuration_changed_before_release")
   after=module.general_barrier()
   value=policy.release(saved["general"],after,saved["account1"],account1(),True,saved["histories"]==histories(),child_exited)
   if value is not None:module.general_write(value,after)
   support.need(module.general_barrier()["phase"]=="idle","release_did_not_finish")
   return {"status":"known_idle_restored","generation":module.general_barrier()["generation"]}
  finally:os.close(fd)
 def resume():
  nonlocal paused
  if paused:
   support.need(module.general_barrier()["phase"]=="idle"and account1()==initial_account1 and histories()==initial_histories,"unknown_state_no_timer_resume")
   support.need(identities()==emails and refs()==refs_before,"changed_context_no_timer_resume")
   if timer_before["ActiveState"]=="active":native("resume_original_timer",["/usr/bin/systemctl","start",TIMER])
   paused=False
 class Adapter:
  def __init__(self,uid,email):
   self.uid=uid;self.email=email;self.fd=None;self.saved=None;self.child_exited=True;self.import_called=False;self.child_started_epoch=None
   local,domain=email.split("@");support.need(local not in(".","..")and re.fullmatch("[A-Za-z0-9_.+-]+",local)and re.fullmatch("[A-Za-z0-9.-]+",domain),"maildir_identity")
   self.maildir=Path("/var/vmail")/domain/local/"Maildir"
  def record(self,label,value):
   durable_record(root/("user-"+str(self.uid)+"-"+label+".json"),value)
  def begin(self):
   self.fd=acquire_general()
   self.saved={"general":module.general_barrier(),"account1":account1(),"histories":histories()}
   support.need(identities()==emails and self.saved["account1"]==initial_account1,"target_begin_context")
   self.record("coordinate-before",self.saved)
  def source_snapshot(self,label):
   pop=None
   try:
    pop=module.connect_pop("mail.mi-sys.jp",self.email,passwords[self.email.casefold()])
    count,size=pop.stat();rows=module.get_uidls(pop);value=policy.snapshot(count,size,rows);pop.quit();pop=None
    self.record("source-"+label,value)
    return value
   finally:
    if pop is not None:pop.close()
  def inventory(self):
   values,counts=header_inventory.scan(self.maildir,pwd.getpwnam("vmail").pw_uid)
   r.setdefault("header_inventories",[]).append({"user_id":self.uid,**counts})
   return values
  def import_once(self,before):
   support.need(not self.import_called and self.fd is not None,"single_import_attempt")
   self.import_called=True
   support.need(shutil.disk_usage("/var/vmail").free>=2*before["size"]+536870912,"mail_storage_free")
   self.uidl_before={p.name for p in module.LOGDIR.iterdir()if p.name.startswith("uidl-verifier-")}
   os.close(self.fd);self.fd=None;self.child_exited=False;self.child_started_epoch=time.time()
   try:
    out,err,row=native("import_user_"+str(self.uid),["/usr/bin/nice","-n","10",str(PROGRAM),"--email",self.email,"--source-host","mail.mi-sys.jp","--threshold",spam_threshold_for_recipient(self.email),"--expected-count",str(before["count"])],seconds=1800,required=False)
    self.child_exited=type(row["exit"])is int and row["exit"]>=0 and not row["timeout"]and not row["overflow"]and "capture_failure"not in row
    self.record("child-finished",{"known_exited":self.child_exited,"native":row,"started_epoch":self.child_started_epoch,"ended_epoch":time.time()})
    support.need(self.child_exited and row["exit"]==0 and not err,"importer_nonzero_or_unknown")
    self.fd=acquire_general(False)
    return out
   except BaseException:
    raise
  def local_UIDLs(self,reuse_importer):
   direct=None
   if not reuse_importer:
    self.uidl_before={p.name for p in module.LOGDIR.iterdir()if p.name.startswith("uidl-verifier-")}
    self.child_started_epoch=time.time()
    direct=module.local_pop_uidls(self.email,None)
   fresh=[p for p in module.LOGDIR.iterdir()if p.name.startswith("uidl-verifier-")and p.name not in self.uidl_before]
   support.need(len(fresh)<=32,"UIDL_receipt_bound")
   candidates=[]
   for p in fresh:
    support.need(re.fullmatch("uidl-verifier-[A-Za-z0-9_-]+",p.name)is not None,"UIDL_receipt_name")
    raw,meta=support.protected(p/"result.json",65536);v=json.loads(raw)
    if v.get("argv")==module._uidl_fetch_argv(self.email):candidates.append((p,v,meta))
   support.need(len(candidates)==1,"unique_importer_UIDL_receipt")
   folder,v,meta=candidates[0]
   support.need(v["exit"]==0 and v["failure"]is None and v["start_epoch"]>=self.child_started_epoch and v["stdin_bytes"]==18 and v["stdin_sha256"]=="7a1bbc341f9644c135685e60078d805928c8cb20b493d57eae1d8ad1d40f8a75","importer_UIDL_receipt_failed")
   out,om=support.protected(folder/"stdout",16777216);err,em=support.protected(folder/"stderr",16777216)
   support.need(support.sha(out)==v["stdout_sha256"]and support.sha(err)==v["stderr_sha256"],"importer_UIDL_receipt_changed")
   count,size,tokens=module._uidl_fetch_parse(out)
   support.need(module._uidl_logout_only(err,self.email,size),"UIDL_receipt_stderr")
   if direct is not None:support.need(direct==(count,size,tokens),"direct_UIDL_receipt_mismatch")
   self.record("final-UIDL-receipt",{"native_root_path":str(folder),"receipt_sha256":meta["sha256"],"count":count,"virtual_size":size,"UIDL_set_sha256":support.sha(("\n".join(sorted(tokens))+"\n").encode()),"importer_receipt_reused":reuse_importer})
   return tokens
  def finish(self):
   if self.fd is not None:os.close(self.fd);self.fd=None
   if self.saved is not None:
    result=release_known(self.saved,self.child_exited);self.record("coordination-finished",result)
 try:
  support.need(os.geteuid()==0 and not os.path.lexists(root),"root_or_prior_attempt")
  host=subprocess.run(["/usr/bin/hostname","-f"],capture_output=True,timeout=5)
  support.need(host.returncode==0 and not host.stderr and host.stdout.strip()==b"mx.mi-sys.jp","host")
  os.umask(0o077);root.mkdir(mode=0o700);created=True
  controlpath=(WORK/".control.lock")
  control=os.open(controlpath,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK|(os.O_CREAT|os.O_EXCL if mode=="run"else 0),0o600)
  info=os.fstat(control);named=controlpath.lstat()
  support.need(stat.S_ISREG(info.st_mode)and(info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode),info.st_nlink)==(0,0,0o600,1)and(info.st_dev,info.st_ino)==(named.st_dev,named.st_ino),"control_lock_metadata")
  fcntl.flock(control,fcntl.LOCK_EX|fcntl.LOCK_NB)
  support.need(packet["preparation"]["status"]=="pass"and packet["preparation"]["header_source_sha256"]==packet["files"]["header_inventory.py"]["sha256"],"preparation_proof")
  backup=packet["preparation"]["backup"]
  support.need(backup["status"]=="pass"and backup["closed_file_readback"]and backup["bytes"]==192853479 and backup["sha256"]=="7d3d831196a080688ec06b14dae7c7d9209ddffaa41dc7558fc222c08099bb5e","saved_external_backup_proof")
  source,program_meta=support.protected(PROGRAM);support.need(program_meta["sha256"]==PROGRAM_SHA and(program_meta["uid"],program_meta["gid"],program_meta["mode"])==(0,0,0o700),"program_drift")
  compat,cm=support.protected(COMPAT);support.need(cm["sha256"]=="2121a0f745d1f512a22b61681e4c0d4573d669355a43e3acd96f7aa6b1b7f291","compat_drift")
  proof,pm=support.protected(Path("/root/mail-uidl-verifier-active-v2/result.json"));support.need(pm["sha256"]=="8e6a9e1fb6b2ebe19cd5990c51c180f638e88bb69e74aefb9048a364ce8d0c95"and json.loads(proof)["status"]=="pass","UIDL_deployment_proof")
  module=types.ModuleType("pinned_importer");module.__file__=str(PROGRAM);exec(compile(source,str(PROGRAM),"exec"),module.__dict__)
  stable=show("services_before",SERVICES);support.need(all(x["ActiveState"]=="active"for x in stable.values()),"protected_service_not_active")
  refs_before=refs();emails=identities();initial_account1=account1();initial_histories=histories()
  timer_before=show("timer_before",(TIMER,))[TIMER];support.need(timer_before["LoadState"]=="loaded"and timer_before["ActiveState"]in("active","inactive"),"timer_before")
  durable_record(root/"before.json",{"services":stable,"references":refs_before,"emails":{str(uid):email for uid,email in emails.items()},"timer":timer_before,"account1":initial_account1,"histories":initial_histories})
  r["timer_before"]=timer_before
  if mode=="recover":
   original=json.loads(support.protected(WORK/"result.json")[0]);support.need(original["status"]=="fail","recover_requires_failed_result")
   original_before=json.loads(support.protected(WORK/"before.json")[0])
   support.need(original_before["references"]==refs_before and {int(k):v for k,v in original_before["emails"].items()}==emails and original_before["account1"]==initial_account1 and original_before["histories"]==initial_histories,"recovery_context_changed")
   timer_before=original_before["timer"];r["timer_before"]=timer_before;paused=True
   unfinished=original.get("unfinished_user")
   if unfinished is not None:
    support.need(unfinished in policy.IDS,"recovery_target")
    saved=json.loads(support.protected(WORK/("user-"+str(unfinished)+"-coordinate-before.json"))[0])
    finished=json.loads(support.protected(WORK/("user-"+str(unfinished)+"-child-finished.json"))[0])
    r["coordination_recovery"]=release_known(saved,finished["known_exited"])
   resume()
   r.update(status="pass",phase="recovered_known_coordination",imports_started=False)
  else:
   # Passwords remain only in this server process and the existing importer.
   csv_raw,csv_meta=support.protected(Path("/root/xmail-accounts.csv"),262144);support.need(csv_meta["mode"]==0o600,"credential_file_permissions")
   accounts=list(csv.DictReader(io.StringIO(csv_raw.decode("utf-8-sig"))));passwords={}
   for email in emails.values():
    matches=[x for x in accounts if x["Email"].strip().casefold()==email.casefold()]
    support.need(len(matches)==1 and bool(matches[0].get("Password")),"credential_target")
    passwords[email.casefold()]=matches[0]["Password"]
   original3=[];log_prefixes={}
   for uid,email in emails.items():
    path=module.LOGDIR/(re.sub("[^A-Za-z0-9_.-]","_",email)+".jsonl")
    if path.exists():log_prefixes[uid]=(path,support.protected(path,33554432)[0])
   if timer_before["ActiveState"]=="active":
    paused=True;native("pause_general_timer",["/usr/bin/systemctl","stop","--quiet",TIMER])
   deadline=time.monotonic()+420
   while True:
    active,err,row=native("drain_"+str(len(r["native"])),["/usr/bin/systemctl","list-units","--all","--type=service","--state=active,activating,deactivating","--plain","--no-legend","mail-pop-source@*.service","mail-pop-general-dispatch.service"])
    if not active.strip():break
    support.need(time.monotonic()<deadline,"drain_deadline");time.sleep(2)
   for uid in policy.IDS:
    r["phase"]="target_"+str(uid);r["unfinished_user"]=uid;current=Adapter(uid,emails[uid])
    result=workflow.execute_target(uid,current,original3);r["targets"].append(result);r.pop("unfinished_user",None);current=None
   for uid,(path,prefix)in log_prefixes.items():support.need(support.protected(path,33554432)[0].startswith(prefix),"previous_target_log_prefix_changed")
   r["all_existing_target_log_prefixes_preserved"]=True
   resume()
   r.update(status="pass",phase="complete",all_initial_snapshots_verified=True,latest_observed_UIDLs_complete=all(x["latest_observed_UIDLs_complete"]for x in r["targets"]),imports_started=any(x["decision"]["import_required"]for x in r["targets"]),cutover_ready=False)
 except BaseException as error:
  if isinstance(error,(KeyboardInterrupt,SystemExit)):raise
  r["failures"].append(support.safe_failure(error,r["phase"]))
  if created:support.write(root/"failure-private.txt",traceback.format_exc().encode()[:131072])
  try:
   if current is not None and current.fd is not None:os.close(current.fd);current.fd=None
   resume()
   r["coordination_recovery"]="known_context_restored_mail_and_history_retained"
  except Exception as recovery_error:
   r["timer_resume_held"]=paused;r["coordination_recovery"]="held_unknown_state";r["failures"].append(support.safe_failure(recovery_error,"recovery"))
 finally:
  if created:
   try:
    r["services_final"]=show("services_final",SERVICES)
    r["protected_PID_preserved"]=stable is not None and r["services_final"]==stable
    r["references_preserved"]=refs_before is not None and refs()==refs_before
    r["timer_final"]=show("timer_final",(TIMER,))[TIMER]
    r["timer_restored"]=timer_before is not None and all(r["timer_final"][k]==timer_before[k]for k in("ActiveState","UnitFileState"))
    if not all(r[k]for k in("protected_PID_preserved","references_preserved","timer_restored")):r["status"]="fail"
   except Exception as final_error:r["status"]="fail";r["failures"].append(support.safe_failure(final_error,"final_read"))
   r["ended_epoch"]=time.time();support.evidence(root/"result.json",r)
  if control is not None:os.close(control)
 return r
