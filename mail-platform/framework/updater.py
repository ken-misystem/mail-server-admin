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

class HookFailure(ReleaseError):
    def __init__(self, record):
        super().__init__('hook_failed_' + record['action'])
        self.record = record
        self.uncertain = record['timed_out']

def hook(stage,action,transaction):
    path = Path(stage)/'payload/installer.py'
    require(path.is_file() and not path.is_symlink(), 'installer_missing')
    directory = Path(transaction)
    sequence = len(list(directory.glob('hook-*.json'))) + 1
    prefix = 'hook-' + str(sequence).zfill(3) + '-' + action
    record = {'action': action, 'started': time.time(), 'exit': None,
              'timed_out': False, 'spawn_error': None}
    output = b''
    errors = b''
    try:
        process = subprocess.run(
            ['/usr/bin/python3', '-I', '-S', '-B', str(path), action, '--transaction', str(transaction)],
            capture_output=True, timeout=600)
        record['exit'] = process.returncode
        output = process.stdout
        errors = process.stderr
    except subprocess.TimeoutExpired as error:
        record['timed_out'] = True
        output = error.stdout or b''
        errors = error.stderr or b''
    except OSError as error:
        record['spawn_error'] = {'class': type(error).__name__, 'errno': error.errno}
    for suffix, raw in [('stdout', output), ('stderr', errors)]:
        descriptor = os.open(directory/(prefix+'.'+suffix), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        record[suffix+'_sha256'] = sha(raw)
    record['finished'] = time.time()
    save(directory/(prefix+'.json'), record)
    if record['exit'] != 0 or record['timed_out'] or record['spawn_error']:
        raise HookFailure(record)
    return record

def _retire_previous(root, prior, hook_fn):
    if not prior or prior['phase'] != 'complete':
        return []
    identifier = prior.get('id')
    require(type(identifier) is str and identifier.isdecimal(), 'retirement_transaction_id')
    directory = root / ('transaction-' + identifier)
    path = directory / 'generation-update.json'
    if not path.exists():
        return []
    from host_transaction import regular
    raw, attributes = regular(path)
    require(attributes['uid'] == 0 and attributes['mode'] == 384, 'retirement_record_permissions')
    generation = json.loads(raw)
    if not generation.get('retirement_pending'):
        return []
    stage = Path(prior['release'])
    require(stage == root / 'releases' / prior['version'] and (not stage.is_symlink()), 'retirement_release_scope')
    raw, attributes = regular(stage / 'payload/installer.py')
    require(attributes['uid'] == 0 and (not attributes['mode'] & 18) and (sha(raw) == prior.get('installer_sha256')), 'retirement_hook_changed')
    hook_fn(stage, 'retire', directory)
    return load(path).get('retirement_pending', [])

def retire_previous(root, hook_fn=hook):
    import fcntl
    root = Path(root)
    with (root / 'update.lock').open('a+b') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ReleaseError('update_busy')
        pending = _retire_previous(root, load(root / 'transaction.json'), hook_fn)
    return {'retirement_pending': pending}

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
  from native_requirements import check as check_native_requirements
  native_status=check_native_requirements(files,root)
  require(not _retire_previous(root,prior,hook_fn),'previous_generation_retirement_pending')
  if not should_apply(settings,current['version'],m['version'],manual):
   from availability_plan import release_impact
   effect=release_impact(files)
   save(root/'available.json',{'version':m['version'],'verified':True,'manual_approval_required':True,'impact':effect});return {'phase':'available','version':m['version'],'impact':effect}
  require(m.get('install_ready')is True,'release_not_installable')
  require('payload/installer.py'in files,'installer_missing')
  releases=root/'releases';releases.mkdir(mode=0o700,exist_ok=True)
  stage=releases/m['version'];extract_verified(files,stage)
  tx={'id':str(time.time_ns()),'phase':'prepared','old':current,'version':m['version'],'release':str(stage),'events':[],
      'installer_sha256':sha(files['payload/installer.py'][0]),'native_requirements':native_status}
  txdir=root/('transaction-'+tx['id']);txdir.mkdir(mode=0o700);save(txdir/'journal.json',tx);save(root/'transaction.json',tx)
  try:
   for action in('plan','stage','activate','health'):
    if action in ('activate','health'):check_native_requirements(files,root)
    tx['phase']=action+'_started';save(root/'transaction.json',tx);save(txdir/'journal.json',tx)
    event=hook_fn(stage,action,txdir);tx['events'].append(event);save(txdir/'journal.json',tx)
   save(root/'installed.json',{'version':m['version'],'release':str(stage),'previous':current['release']})
   tx['phase']='complete';save(root/'transaction.json',tx);save(txdir/'journal.json',tx)
  except Exception as failure:
   if hasattr(failure,'record'):tx['events'].append(failure.record)
   tx['failure']=type(failure).__name__+':'+str(failure);tx['phase']='rollback_started';save(root/'transaction.json',tx)
   try:
    require(not getattr(failure,'uncertain',False),'hook_timeout_requires_review')
    tx['events'].append(hook_fn(stage,'rollback',txdir))
    expected={'version':m['version'],'release':str(stage),'previous':current['release']}
    observed=load(root/'installed.json',current)
    require(observed in(current,expected),'installed_version_changed_during_recovery')
    if observed==expected:save(root/'installed.json',current)
    tx['phase']='rolled_back'
   except Exception as rollback:tx['phase']='held';tx['rollback_failure']=type(rollback).__name__+':'+str(rollback)
   save(root/'transaction.json',tx);save(txdir/'journal.json',tx);raise ReleaseError('update_'+tx['phase'])from failure
  return {'phase':tx['phase'],'version':m['version']}
