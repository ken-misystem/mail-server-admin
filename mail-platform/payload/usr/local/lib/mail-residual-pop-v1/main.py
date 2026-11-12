"""Root-only periodic old-server collection; no retry after an uncertain cycle."""
import fcntl,hashlib,json,os,shutil,stat,sys,time,traceback
from pathlib import Path
CODE=Path('/usr/local/lib/mail-residual-pop-v1')
STATE=Path('/var/lib/mail-residual-pop-v1')
def need(ok,label):
 if not ok:raise RuntimeError(label)
def protected(path,directory=False):
 s=path.lstat()
 need((stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)) and s.st_uid==0 and s.st_gid==0 and not s.st_mode&0o022 and (directory or s.st_nlink==1),'unsafe_path')
 return s
def sync_directory(path):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
def write(path,value,exclusive=False):
 raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
 temp=path if exclusive else path.with_name(path.name+'.new')
 fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 if not exclusive:os.replace(temp,path)
 need(json.loads(path.read_bytes())==value,'readback')
 sync_directory(path.parent)
def outcome(result):
 return result.get('status')=='pass' and all(result.get(k)is True for k in ('protected_PID_preserved','references_preserved','timer_restored','all_existing_target_log_prefixes_preserved')) and {v['user_id'] for v in result.get('targets',[]) if v.get('snapshot_verified')}=={3,4,5,7}
def run_cycle(state,runner,packet,clock=time.time):
 latch=state/'in-progress.json'
 if latch.exists():return {'status':'held','reason':'previous_cycle_not_verified','import_started':False}
 need(shutil.disk_usage(state).free>=2147483648,'evidence_free_space')
 runs=state/'runs';protected(runs,True)
 need(len(list(runs.iterdir()))<10000,'evidence_run_limit')
 stamp=str(time.time_ns());root=runs/stamp
 intent={'started_epoch':clock(),'run':str(root),'targets':[3,4,5,7]}
 write(latch,intent,True)
 runner.WORK=root
 try:
  result=runner.run(packet)
  persisted=json.loads((root/'result.json').read_bytes())
  need(persisted==result,'runner_result_readback')
  summary={'status':'pass' if outcome(result) else 'fail','started_epoch':intent['started_epoch'],'finished_epoch':clock(),'run':str(root),'result_sha256':hashlib.sha256((root/'result.json').read_bytes()).hexdigest(),'targets':result.get('targets',[]),'failures':result.get('failures',[]),'timer_restored':result.get('timer_restored'),'protected_PID_preserved':result.get('protected_PID_preserved'),'references_preserved':result.get('references_preserved'),'known_coordination_only':True,'mail_deleted':False,'history_reset':False,'yukido_collected':False}
  write(state/'status.json',summary)
  if summary['status']=='pass':
   need(json.loads(latch.read_bytes())==intent,'latch_changed')
   latch.unlink()
  return summary
 except BaseException as exc:
  # Preserve latch on process interruption, unknown result or failed verification.
  failure={'status':'fail','class':type(exc).__name__,'run':str(root),'started_epoch':intent['started_epoch'],'finished_epoch':clock(),'reason':'private_cycle_failure'}
  with (state/('failure-'+stamp+'.txt')).open('x',encoding='utf-8')as f:f.write(traceback.format_exc())
  write(state/'status.json',failure)
  return failure
def main():
 os.umask(0o077);need(os.geteuid()==0,'root_required')
 for p in (CODE,STATE,STATE/'runs'):protected(p,True)
 fd=os.open(STATE/'control.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
 protected(STATE/'control.lock')
 try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 except BlockingIOError:return 75
 manifest=json.loads((CODE/'manifest.json').read_bytes())
 for name,digest in manifest.items():
  need(Path(name).name==name,'manifest_name');protected(CODE/name)
  need(hashlib.sha256((CODE/name).read_bytes()).hexdigest()==digest,'code_changed')
 sys.path.insert(0,str(CODE))
 import runner
 result=run_cycle(STATE,runner,json.loads((CODE/'packet.json').read_bytes()))
 print(json.dumps({k:result[k] for k in ('status','reason','run','timer_restored') if k in result}))
 return 0 if result['status']=='pass' else 1
if __name__=='__main__':raise SystemExit(main())
