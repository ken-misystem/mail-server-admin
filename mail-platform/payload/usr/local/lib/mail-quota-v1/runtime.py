"""Root-only bounded quota collector. No mail submission, deletion or quota recalc."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
import traceback
from collector_core import cycle, inventory
from binding import quota_tab

ROOT = Path('/usr/local/lib/mail-quota-v1')
STATE = Path('/var/lib/mail-quota-v1')
BACKEND = '/etc/mail-client-certificates-v1/dovecot-backend.conf'
PHP_READER=['/usr/bin/php','-d','display_errors=0','-d','log_errors=0',
            '-d','zend.exception_ignore_args=1','-d','auto_prepend_file=',
            '-d','auto_append_file=','-d','opcache.enable_cli=0',str(ROOT/'read_accounts.php')]


class NativeFailure(Exception):
    def __init__(self, label, code, timeout, overflow, stdout, stderr):
        self.detail = {'label': label, 'exit': code, 'timeout': timeout, 'overflow': overflow,
                       'stdout_sha256': digest(stdout), 'stderr_sha256': digest(stderr)}
        self.stdout, self.stderr = stdout, stderr
        super().__init__(label)


def digest(raw): return hashlib.sha256(raw).hexdigest()


def need(value, reason):
    if not value: raise ValueError(reason)


def native(label, argv, seconds, body=b'', limit=262144):
    """No shell; bounded streams; kill only the process group created by this call."""
    need(re.fullmatch('[a-z0-9_]{1,64}', label) is not None, 'native_label')
    need(0 < seconds <= 30 and len(body) <= 4096 and 0 < limit <= 2097152, 'native_bounds')
    p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, start_new_session=True,
                         env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C',
                              'PYTHONDONTWRITEBYTECODE':'1'})
    buffers=[bytearray(),bytearray()]; expired=False; overflow=False
    deadline=time.monotonic()+seconds
    try:
        # Production inputs fit in the minimum Linux pipe capacity, including the SQL/config probes.
        p.stdin.write(body); p.stdin.close()
        with selectors.DefaultSelector() as selector:
            for i,s in enumerate((p.stdout,p.stderr)): selector.register(s,selectors.EVENT_READ,i)
            while selector.get_map():
                remaining=deadline-time.monotonic()
                if remaining<=0: expired=True; break
                for event,_ in selector.select(min(.05,remaining)):
                    chunk=os.read(event.fileobj.fileno(),8192)
                    if not chunk: selector.unregister(event.fileobj); continue
                    room=limit-sum(map(len,buffers)); buffers[event.data].extend(chunk[:max(0,room)])
                    if len(chunk)>room: overflow=True; break
                if overflow: break
        remaining=deadline-time.monotonic()
        if not expired and not overflow:
            try: p.wait(timeout=max(.001,remaining))
            except subprocess.TimeoutExpired: expired=True
    finally:
        if expired or overflow or p.poll() is None:
            # Includes descendants retaining a pipe after the original child exited.
            try: os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError: pass
        p.wait(timeout=3)
        for s in (p.stdin,p.stdout,p.stderr): s.close()
    out,err=map(bytes,buffers)
    if expired or overflow or p.returncode!=0 or err:
        raise NativeFailure(label,p.returncode,expired,overflow,out,err)
    return out


def read_json(path, bound=2097152, absent=None):
    try: fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    except FileNotFoundError:
        if absent is not None: return absent
        raise
    with os.fdopen(fd,'rb') as f:
        s=os.fstat(f.fileno())
        need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1
             and not s.st_mode&0o027 and s.st_size<=bound, 'state_file')
        raw=f.read(bound+1);need(len(raw)==s.st_size,'state_size')
        return json.loads(raw)


def atomic(path, value, mode=0o600):
    """The private 0700 staging directory prevents access before the final mode is set."""
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
    need(len(raw)<=2097152,'publication_bound')
    parent=path.parent; s=os.lstat(parent)
    need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'publication_parent')
    try:
        t=os.lstat(path);need(stat.S_ISREG(t.st_mode) and t.st_uid==0 and t.st_nlink==1
                              and not t.st_mode&0o022,'publication_existing')
    except FileNotFoundError: pass
    tmp=parent/('.'+path.name+'.'+str(os.getpid())+'.'+str(time.time_ns())+'.tmp')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno());os.fchmod(f.fileno(),mode)
    os.replace(tmp,path)
    fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def failure(exc, phase):
    detail={'phase':phase,'class':type(exc).__name__,'errno':getattr(exc,'errno',None),
            'frames':[{'source':Path(x.filename).name,'line':x.lineno,'function':x.name}
                      for x in traceback.extract_tb(exc.__traceback__)[-6:]]}
    if isinstance(exc,NativeFailure): detail.update(exc.detail)
    elif type(exc) is ValueError and re.fullmatch('[a-z0-9_]{1,80}',str(exc)):
        detail['reason']=str(exc)
    return detail


class Adapter:
    def __init__(self, applied, invoke=native): self.applied=applied;self.invoke=invoke;self.raw_failures=[]

    def observe(self,row,seconds):
        deadline=time.monotonic()+seconds; email=row['email'];key=row['id'];q=row['quota_bytes']
        need(type(email)is str and not email.startswith('-')and re.fullmatch(r'[A-Za-z0-9._+\-]+@[A-Za-z0-9.\-]+',email) is not None,'email_option_prefix')
        need(q%1024==0,'limit_alignment')
        def call(label,args):
            remaining=deadline-time.monotonic();need(remaining>0,'account_deadline')
            return self.invoke(label,args,remaining,limit=8192)
        try:
            old=self.applied.get(key)
            if old!={'email':email,'quota_bytes':q}:
                # Exact validated email; wildcard users and -A are never accepted by inventory().
                call('main_reconnect',['/usr/bin/doveadm','kick',email])
                call('backend_reconnect',['/usr/bin/doveadm','-c',BACKEND,'kick',email])
            main=quota_tab(call('main_quota',['/usr/bin/doveadm','-f','tab','quota','get','-u',email]),q)
            backend=quota_tab(call('backend_quota',['/usr/bin/doveadm','-c',BACKEND,'-f','tab','quota','get','-u',email]),q)
            self.applied[key]={'email':email,'quota_bytes':q}
            return {'effective_bytes':q,'used_bytes_upper_bound':max(main['used_bytes_upper_bound'],backend['used_bytes_upper_bound'])}
        except Exception as e:
            self.raw_failures.append((key,e));raise


@contextlib.contextmanager
def locked(path):
    fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1
                            and stat.S_IMODE(s.st_mode)==0o600,'lock_attributes')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
    finally: os.close(fd)


def collect():
    need(os.geteuid()==0,'root_required')
    for p in (STATE,STATE/'private'):
        s=os.lstat(p);need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'state_parent')
    os.umask(0o077);phase='lock'; started=time.monotonic();config=None
    with locked(STATE/'private/collector.lock'):
        try:
            phase='deployment';config=read_json(ROOT/'deployment.json')
            need(config['version']==1 and re.fullmatch('[a-f0-9]{64}',config['deployment_hash']), 'deployment_shape')
            for name,pin in config['artifact_pins'].items():
                need(re.fullmatch('[A-Za-z0-9_.-]+',name) is not None,'artifact_name')
                need(digest((ROOT/name).read_bytes())==pin,'artifact_drift')
            phase='effective_config'
            for i,args in enumerate((['/usr/bin/doveconf','-n'],['/usr/bin/doveconf','-c',BACKEND,'-n'])):
                need(digest(native('config_'+str(i),args,3,limit=2097152))==config['effective_hashes'][i], 'effective_config_drift')
            phase='inventory'
            raw=native('inventory',PHP_READER,4)
            rows=json.loads(raw);current=inventory(rows)
            need(all(not x['email'].startswith('-') for x in current.values()),'email_option_prefix')
            state=read_json(STATE/'private/state.json',absent={'version':1,'deployment_hash':config['deployment_hash'],'cursor':'0','applied':config['initial_applied']})
            need(state['version']==1 and state['deployment_hash']==config['deployment_hash'] and type(state['applied']) is dict,'generation_drift')
            applied={k:v for k,v in state['applied'].items() if k in current};adapter=Adapter(applied)
            phase='measurement'
            observed=cycle(rows,read_json(STATE/'snapshot.json',absent={}),state['cursor'],config['deployment_hash'],
                           adapter.observe,lambda:int(time.time()),time.monotonic,
                           batch=4,budget=22,per_user=5,enforcement_attested=True)
            phase='inventory_recheck'
            again=json.loads(native('inventory_after',PHP_READER,4))
            need(inventory(again)==current,'inventory_changed_during_cycle')
            phase='publication'
            atomic(STATE/'private/state.json',{'version':1,'deployment_hash':config['deployment_hash'],
                   'cursor':observed['next_cursor'],'applied':applied})
            atomic(STATE/'snapshot.json',observed['snapshot'],0o640)
            details=[failure(e,'account_'+key) for key,e in adapter.raw_failures]
            for index,(key,e) in enumerate(adapter.raw_failures):
                if isinstance(e,NativeFailure):
                    # Exact native bytes are private, bounded, and never printed to journald.
                    atomic(STATE/'private'/('native-'+str(index)+'.json'),
                           {'id':key,'stdout_base64':__import__('base64').b64encode(e.stdout).decode(),
                            'stderr_base64':__import__('base64').b64encode(e.stderr).decode()})
            report={'status':'ok' if not observed['failures'] else 'incomplete',
                    'attempted':len(observed['attempted']),'measured':len(observed['snapshot']['records']),
                    'active':len(current),'complete':observed['complete_population_measured'],
                    'failures':details,'elapsed_ms':round((time.monotonic()-started)*1000)}
            atomic(STATE/'private/last-result.json',report)
            print(json.dumps(report));return int(report['status']!='ok')
        except Exception as e:
            # A stale successful snapshot must never authorize edits after a failed attestation.
            detail=failure(e,phase)
            raw_trace=traceback.format_exc()
            def persist(path,value,mode=0o600):
                try:atomic(path,value,mode)
                except Exception as saving:detail.setdefault('evidence_failures',[]).append(failure(saving,'failure_persist'))
            persist(STATE/'snapshot.json',{'version':1,'deployment_hash':config['deployment_hash'] if config else '0'*64,
                                          'enforcement_verified':False,'records':{}},0o640)
            if isinstance(e,NativeFailure):
                persist(STATE/'private/failure-native.json',{'stdout_base64':__import__('base64').b64encode(e.stdout).decode(),
                       'stderr_base64':__import__('base64').b64encode(e.stderr).decode()})
            persist(STATE/'private/exception.json',{'traceback_private':raw_trace})
            persist(STATE/'private/last-result.json',{'status':'fail','failure':detail})
            print(json.dumps({'status':'fail','failure':detail}));return 1


def main():
    try:return collect()
    except BlockingIOError:print('{"status":"busy"}');return 0
    except Exception as e:print(json.dumps({'status':'fail','failure':failure(e,'collector_outer')}));return 1


if __name__=='__main__':raise SystemExit(main())
