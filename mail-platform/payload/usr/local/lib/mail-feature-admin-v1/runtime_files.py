"""Root-owned, bounded, atomic configuration/state writes with drift refusal."""
import hashlib,json,os,stat,uuid
from contextlib import contextmanager
from pathlib import Path
from forwarding import need

@contextmanager
def parent(path):
    path=Path(path);need(path.is_absolute()and '..'not in path.parts,'runtime_absolute_path')
    opened=[os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)]
    try:
        for part in path.parts[1:-1]:
            opened.append(os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=opened[-1]));info=os.fstat(opened[-1]);need(info.st_uid==0 and not info.st_mode&0o022,'runtime_private_parent')
        yield opened[-1],path.name
    finally:
        for fd in reversed(opened):os.close(fd)

def read_at(directory,name,*,mode,group=None,limit=2097152):
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
    try:
        info=os.fstat(fd);need(stat.S_ISREG(info.st_mode)and info.st_uid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==mode and(group is None or info.st_gid==group)and 0<info.st_size<=limit,'runtime_private_file')
        raw=os.pread(fd,info.st_size+1,0);key=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(len(raw)==info.st_size and key(info)==key(os.fstat(fd))==key(os.stat(name,dir_fd=directory,follow_symlinks=False)),'runtime_private_drift')
        return raw,{'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'uid':info.st_uid,'gid':info.st_gid,'mode':mode}
    finally:os.close(fd)

def read(path,*,mode,group=None,limit=2097152):
    with parent(path)as(directory,name):return read_at(directory,name,mode=mode,group=group,limit=limit)

def write(path,raw,*,group,mode,prior_pin=None,absent=False):
    need(type(raw)is bytes and 0<len(raw)<=2097152 and mode in (0o600,0o640,0o644)and type(group)is int and group>=0,'runtime_atomic_payload')
    with parent(path)as(directory,name):
        def check():
            try:_,meta=read_at(directory,name,mode=mode,group=group)
            except FileNotFoundError:need(absent,'runtime_required_file_missing');return
            need(not absent,'runtime_file_appeared')
            if prior_pin is not None:need(meta['sha256']==prior_pin,'runtime_manual_drift')
        check();temporary='.'+uuid.uuid4().hex;fd=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600,dir_fd=directory)
        try:
            with os.fdopen(fd,'wb',closefd=False)as stream:stream.write(raw);stream.flush();os.fsync(fd)
            os.fchown(fd,0,group);os.fchmod(fd,mode);os.fsync(fd)
        finally:os.close(fd)
        check();os.replace(temporary,name,src_dir_fd=directory,dst_dir_fd=directory);os.fsync(directory)
        pin=hashlib.sha256(raw).hexdigest();need(read_at(directory,name,mode=mode,group=group)[1]['sha256']==pin,'runtime_atomic_readback');return pin

def encoded(value):return(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
