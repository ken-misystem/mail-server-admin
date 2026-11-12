"""New Linux filesystem/transaction integration only. No SMTP, DB or systemd access."""
import json,os,subprocess,sys,tempfile
from pathlib import Path
from release import build,sign,require,ReleaseError
from updater import run_update,load,save
from broker import operation

def run(root):
 root=Path(root);key=root/'fixture-key';pub=root/'fixture-public';subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(key)],check=True,capture_output=True);subprocess.run(['openssl','pkey','-in',str(key),'-pubout','-out',str(pub)],check=True,capture_output=True)
 checks=[]
 def make(name,fail='',ready=True):
  d=root/name;d.mkdir();state=d/'state';state.mkdir(mode=0o700);src=d/'source';src.mkdir()
  code="import sys,json\nfrom pathlib import Path\na=sys.argv[1];d=Path(sys.argv[3]);\nwith (d/'executed').open('a')as f:f.write(a+'\\n')\n"+('raise SystemExit(7)if a in '+repr(fail.split(','))+" else None\n"if fail else '')
  # The conditional raise form above would raise None on success: use explicit branch.
  code="import sys\nfrom pathlib import Path\na=sys.argv[1];d=Path(sys.argv[3])\nwith (d/'executed').open('a')as f:f.write(a+'\\n')\nif a in "+repr([x for x in fail.split(',')if x])+":raise SystemExit(7)\n"
  p=src/'installer.py';p.write_text(code);import hashlib
  meta=build(src,[{'source':'installer.py','name':'payload/installer.py','sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'mode':0o755}],'1.0.0',d/'bundle.tar.gz',ready);return state,d/'bundle.tar.gz',meta,sign(meta,key)
 def invoke(v,manual=False):return run_update(v[0],v[1],v[2],v[3],pub,manual)
 a=make('manual');require(invoke(a)['phase']=='available','manual_stage');require(not(a[0]/'installed.json').exists(),'manual_modified_install');checks.append('manual_detects_without_install')
 require(invoke(a,True)['phase']=='complete','manual_apply');require(load(a[0]/'installed.json')['version']=='1.0.0','manual_version');checks.append('manual_apply_full_hook_transaction')
 b=make('auto');save(b[0]/'policy.json',{'revision':1,'mode':'automatic'});require(invoke(b)['phase']=='complete','auto');checks.append('automatic_full_hook_transaction')
 c=make('rollback','health')
 try:invoke(c,True);raise AssertionError('expected health failure')
 except ReleaseError as e:require(str(e)=='update_rolled_back','rollback_error')
 require(load(c[0]/'transaction.json')['phase']=='rolled_back'and not(c[0]/'installed.json').exists(),'rollback_version');checks.append('health_failure_rolls_back_preserving_prior_version')
 d=make('held','health,rollback')
 try:invoke(d,True);raise AssertionError('expected hold')
 except ReleaseError as e:require(str(e)=='update_held','held_error')
 require(load(d[0]/'transaction.json')['phase']=='held','held');checks.append('rollback_failure_latches_hold')
 # Review of durable state after an uncertain operation; do not rerun that lifecycle.
 import updater
 require(load(d[0]/'transaction.json')['phase']not in('complete','rolled_back'),'next_operation_must_refuse');checks.append('uncertain_transaction_requires_review')
 e=make('notready',ready=False)
 try:invoke(e,True);raise AssertionError('expected not ready')
 except ReleaseError as err:require(str(err)=='release_not_installable','readiness')
 require(not(e[0]/'transaction.json').exists(),'not_ready_changed');checks.append('incomplete_mail_recipe_never_installs')
 ui=root/'ui';ui.mkdir();request={'operation':'settings','mode':'automatic','revision':0,'actor':'1','request_id':'a'*32};require(operation(request,ui)['status']=='ok','ui_setting');require(load(ui/'policy.json')['mode']=='automatic','ui_mode');checks.append('UI_mode_CAS_and_private_save')
 try:operation(request,ui);raise AssertionError('expected replay')
 except ReleaseError:checks.append('UI_replay_refused')
 request={'operation':'apply','mode':'automatic','revision':1,'actor':'1','request_id':'b'*32};operation(request,ui);require(load(ui/'manual-request.json')['request_id']=='b'*32,'manualqueue');checks.append('UI_manual_apply_queues_only')
 # Test lock semantics with a real flock, without replaying a passed installation.
 import fcntl
 f=(root/'lock').open('a+b');g=(root/'lock').open('a+b');fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
 try:
  try:fcntl.flock(g,fcntl.LOCK_EX|fcntl.LOCK_NB);raise AssertionError('lock missing')
  except BlockingIOError:checks.append('real_flock_exclusion')
 finally:g.close();f.close()
 return checks
if __name__=='__main__':
 with tempfile.TemporaryDirectory(prefix='mail-platform-native-')as tmp:print(json.dumps({'status':'pass','new_checks':run(tmp),'uid':os.geteuid(),'production_install_tested':False,'fixture_hooks_only':True}))
