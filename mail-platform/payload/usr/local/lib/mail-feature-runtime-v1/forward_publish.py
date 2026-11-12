"""Compile one immutable generation, then publish its root-owned link atomically."""
import hashlib,os,re,stat,time,uuid
from pathlib import Path
from forwarding import need
from forward_runtime import mailbox_filename
from feature_commands import compile_sieve

def identity(info):return(info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))
def directory(path,group):
    info=path.lstat();need(stat.S_ISDIR(info.st_mode)and info.st_uid==0 and info.st_gid==group and stat.S_IMODE(info.st_mode)==0o750,'forward_publish_directory');return identity(info)
def sync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def write(path,raw,group):
    need(type(raw)is bytes and 0<len(raw)<=65536,'forward_source_bound')
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_WRONLY,0o600)
    try:
        with os.fdopen(fd,'wb',closefd=False)as stream:stream.write(raw);stream.flush();os.fsync(fd)
        os.fchown(fd,0,group);os.fchmod(fd,0o640)
    finally:os.close(fd)
def compile_generation(root,files,group,config,private_capture,*,now,seconds=30,before_publish=None):
    """Arguments are deployment constants, never frontend-selected paths/commands."""
    need(type(files)is dict and len(files)<=10000 and type(group)is int and group>0 and type(now)is int,'forward_generation_input')
    before=directory(root,group);total=0
    for name,raw in files.items():
        need(type(name)is str and name.endswith('.sieve')and mailbox_filename(name[:-6])==name,'forward_script_name');need(type(raw)is bytes and len(raw)<=65536,'forward_script_bytes');total+=len(raw)
    need(total<=8*1024*1024,'forward_generation_bound')
    current=root/'current';previous=None
    if os.path.lexists(current):
        info=current.lstat();need(stat.S_ISLNK(info.st_mode)and info.st_uid==0,'forward_current_link');previous=os.readlink(current);need(re.fullmatch('generation-[a-f0-9]{32}',previous)is not None,'forward_current_target');directory(root/previous,group)
    name='generation-'+uuid.uuid4().hex;staging=root/name;staging.mkdir(mode=0o700);os.chown(staging,0,group);os.chmod(staging,0o750)
    for leaf,raw in sorted(files.items()):write(staging/leaf,raw,group)
    started=time.monotonic()
    if files:
        compile_sieve(config,staging,private_capture,seconds)
    expected=set(files)|{leaf[:-6]+'.svbin'for leaf in files};actual={entry.name for entry in staging.iterdir()}
    need(actual==expected,'forward_generation_inventory')
    binaries={}
    for leaf in sorted(expected):
        path=staging/leaf;fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(fd);need(stat.S_ISREG(info.st_mode)and info.st_uid==0 and info.st_nlink==1 and 0<info.st_size<=2*1024*1024,'forward_compiled_file')
            os.fchown(fd,0,group);os.fchmod(fd,0o640);os.fsync(fd);raw=os.pread(fd,info.st_size+1,0);need(len(raw)==info.st_size,'forward_compiled_readback')
            if leaf in files:need(raw==files[leaf],'forward_source_changed_during_compile')
            else:binaries[leaf]=hashlib.sha256(raw).hexdigest()
        finally:os.close(fd)
    sync_dir(staging);need(directory(root,group)==before,'forward_parent_changed')
    need(now-5<=time.time()<=now+60,'forward_generation_too_old_before_publish')
    if before_publish is not None:
        before_publish(name,{'version':1,'created_at':now,'files':dict({leaf:hashlib.sha256(raw).hexdigest()for leaf,raw in files.items()},**binaries)})
        sync_dir(staging)
    if previous is None:need(not os.path.lexists(current),'forward_current_appeared')
    else:need(current.is_symlink()and os.readlink(current)==previous,'forward_current_changed')
    temporary=root/('.current-'+uuid.uuid4().hex);os.symlink(name,temporary);os.replace(temporary,current);sync_dir(root)
    need(current.is_symlink()and os.readlink(current)==name,'forward_publish_readback')
    return {'generation':name,'previous_generation':previous,'scripts':len(files),'source_bytes':total,'binaries':binaries,'generated_at':now,'compile_seconds':time.monotonic()-started,'published':True}
