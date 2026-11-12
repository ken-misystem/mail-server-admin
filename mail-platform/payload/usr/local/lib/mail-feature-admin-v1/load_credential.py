"""Exact previously verified credential FD/metadata guard."""
import json,os,stat
from queue_admin import need

def credential(directory, on_metadata=None):
    descriptor=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        file=os.open('db.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=descriptor)
        try:
            info=os.fstat(file)
            facts={'uid':info.st_uid,'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode),
                'nlink':info.st_nlink,'bytes':info.st_size,'euid':os.geteuid(),'egid':os.getegid(),
                'regular':stat.S_ISREG(info.st_mode)}
            if on_metadata is not None:
                on_metadata(facts)
            need(facts['regular'] and info.st_nlink==1 and info.st_uid in (0,os.geteuid())
                 and stat.S_IMODE(info.st_mode) in (0o400,0o440) and info.st_gid in (0,os.getegid())
                 and 0<info.st_size<=4096,'credential_metadata')
            raw=os.pread(file,info.st_size+1,0)
            final=os.fstat(file)
            named=os.stat('db.json',dir_fd=descriptor,follow_symlinks=False)
            key=lambda value:(value.st_dev,value.st_ino,value.st_uid,value.st_gid,value.st_mode,
                              value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
            need(len(raw)==info.st_size and key(info)==key(final)==key(named),'credential_changed')
            value=json.loads(raw)
            need(type(value) is dict and set(value)=={'user','password'},'credential_fields')
            return value
        finally:
            os.close(file)
    finally:
        os.close(descriptor)
