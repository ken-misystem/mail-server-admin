"""Durable update policy and verified release lifecycle; data directories stay outside releases."""
import datetime,json,os,subprocess,time
from pathlib import Path
from release import require,version,inspect,extract_verified,sha,canonical,ReleaseError

def save(path,value):
 p=Path(path);tmp=p.with_name(p.name+'.tmp');fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 try:
  with os.fdopen(fd,'wb')as f:f.write(canonical(value));f.flush();os.fsync(f.fileno())
  os.replace(tmp,p);d=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(d)
  finally:os.close(d)
 finally:
  if tmp.exists():tmp.unlink()
def load(p,default=None):return json.loads(Path(p).read_bytes())if Path(p).exists()else default

def policy(old,mode,expected_revision):
 require(mode in('manual','automatic'),'update_mode');require(old['revision']==expected_revision,'revision_conflict')
 return {'revision':old['revision']+1,'mode':mode}
def should_apply(settings,current,offered,manual=False):
 require(settings['mode']in('manual','automatic'),'update_mode')
 require(version(offered)>version(current),'not_newer')
 return bool(manual or settings['mode']=='automatic')

def hook(stage,action,transaction):
 path=Path(stage)/'payload/installer.py';require(path.is_file()and not path.is_symlink(),'installer_missing')
 p=subprocess.run(['/usr/bin/python3','-I','-S','-B',str(path),action,'--transaction',str(transaction)],capture_output=True,timeout=600)
 # Hook output may contain secrets: never return it through the UI/logging API.
 result={'action':action,'exit':p.returncode,'stdout_sha256':sha(p.stdout),'stderr_sha256':sha(p.stderr)}
 require(p.returncode==0,'hook_failed_'+action);return result

def run_update(root,archive,meta,signature,key,manual=False,openssl='openssl',hook_fn=hook):
 import fcntl
 root=Path(root);require(root.is_dir()and not root.is_symlink(),'state_root')
 with (root/'update.lock').open('a+b')as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:raise ReleaseError('update_busy')
  current=load(root/'installed.json',{'version':'0.0.0','release':None})
  settings=load(root/'policy.json',{'revision':0,'mode':'manual'})
  prior=load(root/'transaction.json')
  require(not prior or prior['phase']in('complete','rolled_back'),'previous_transaction_requires_review')
  require(not prior or prior['phase']!='rolled_back' or prior['version']!=meta['version'],'previous_release_failed_requires_review')
  m,files=inspect(archive,meta,signature,key,openssl)
  if not should_apply(settings,current['version'],m['version'],manual):
   save(root/'available.json',{'version':m['version'],'verified':True,'manual_approval_required':True});return {'phase':'available','version':m['version']}
  require(m.get('install_ready')is True,'release_not_installable')
  require('payload/installer.py'in files,'installer_missing')
  releases=root/'releases';releases.mkdir(mode=0o700,exist_ok=True)
  stage=releases/m['version'];extract_verified(files,stage)
  tx={'id':str(time.time_ns()),'phase':'prepared','old':current,'version':m['version'],'release':str(stage),'events':[]}
  txdir=root/('transaction-'+tx['id']);txdir.mkdir(mode=0o700);save(txdir/'journal.json',tx);save(root/'transaction.json',tx)
  try:
   for action in('plan','stage','activate','health'):
    tx['phase']=action+'_started';save(root/'transaction.json',tx);save(txdir/'journal.json',tx)
    event=hook_fn(stage,action,txdir);tx['events'].append(event);save(txdir/'journal.json',tx)
   save(root/'installed.json',{'version':m['version'],'release':str(stage),'previous':current['release']})
   tx['phase']='complete';save(root/'transaction.json',tx);save(txdir/'journal.json',tx)
  except Exception as failure:
   tx['failure']=type(failure).__name__+':'+str(failure);tx['phase']='rollback_started';save(root/'transaction.json',tx)
   try:tx['events'].append(hook_fn(stage,'rollback',txdir));tx['phase']='rolled_back'
   except Exception as rollback:tx['phase']='held';tx['rollback_failure']=type(rollback).__name__+':'+str(rollback)
   save(root/'transaction.json',tx);save(txdir/'journal.json',tx);raise ReleaseError('update_'+tx['phase'])from failure
  return {'phase':tx['phase'],'version':m['version']}
