"""Root-owned atomic control snapshot read by the existing nonroot SMTP policy."""
import hashlib,json,os,re,stat,threading
from pathlib import Path

PATH=Path('/run/mail-send-limits-v1/admin-stops/stops.json')
def need(ok,reason):
    if not ok:raise ValueError(reason)
def decode(raw):
    need(type(raw)is bytes and len(raw)<=2*1024*1024,'stop_snapshot_bound')
    def unique(pairs):
        d={}
        for key,value in pairs:need(key not in d,'stop_duplicate_key');d[key]=value
        return d
    value=json.loads(raw,object_pairs_hook=unique)
    need(type(value)is dict and set(value)=={'version','revision','owners'} and type(value['version'])is int and value['version']==1
         and type(value['revision'])is int and value['revision']>=1 and type(value['owners'])is dict and len(value['owners'])<=10000,'stop_snapshot_shape')
    for owner,row in value['owners'].items():
        need(re.fullmatch('[a-f0-9]{64}',owner)is not None and type(row)is dict and set(row)=={'until','revision'}
             and type(row['until'])is int and row['until']>=0 and type(row['revision'])is int and row['revision']>=1,'stop_owner_shape')
    return value

def read():
    # All names are fixed; never follow a request-selected path or symlink.
    fds=[os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)]
    try:
        for part in PATH.parts[1:-1]:
            fds.append(os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fds[-1]));info=os.fstat(fds[-1])
            need(not info.st_mode&0o022 and info.st_uid in (0,os.geteuid()),'stop_parent')
        fds.append(os.open(PATH.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fds[-1]));info=os.fstat(fds[-1])
        need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o640 and info.st_nlink==1 and 0<info.st_size<=2*1024*1024,'stop_file')
        raw=os.pread(fds[-1],info.st_size+1,0)
        after=os.fstat(fds[-1]);named=os.stat(PATH.name,dir_fd=fds[-2],follow_symlinks=False)
        key=lambda x:(x.st_dev,x.st_ino,x.st_uid,x.st_gid,x.st_mode,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
        need(len(raw)==info.st_size and key(info)==key(after)==key(named),'stop_file_changed')
        return decode(raw)
    finally:
        for fd in reversed(fds):os.close(fd)

_revision=0
_pin=None
_lock=threading.Lock()
def load_stop(owner):
    global _revision,_pin
    value=read();pin=hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    with _lock:
        need(value['revision']>=_revision,'stop_revision_rollback')
        need(value['revision']!=_revision or _pin is None or pin==_pin,'stop_same_revision_changed')
        _revision=value['revision'];_pin=pin
    return value['owners'].get(owner)
