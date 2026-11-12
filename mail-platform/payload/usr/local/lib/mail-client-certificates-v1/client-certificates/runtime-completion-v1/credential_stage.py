"""Read-only systemd credential -> actor-owned, mlocked private tmpfs FD.

Legacy FD adapters require actor ownership/nlink1/mode0400. Never weaken those
guards or write a credential to a persistent filesystem. Files exist only inside
the actor RuntimeDirectory, stay mlocked until retirement, then are zeroed.
"""
import ctypes
import mmap
import os
import stat
import uuid
from safety import need,unchanged

class Stage:
    def __init__(self,directory,runtime):
        self.runtime=runtime;self.runtime.require_armed();self.items=[];self.libc=ctypes.CDLL(None,use_errno=True)
        self.parent=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        meta=os.fstat(self.parent);need(meta.st_uid==os.geteuid()and meta.st_mode&0o022==0,'credential_stage_parent')
        # Linux fstatfs: the first machine word is f_type. Oversized storage
        # accommodates native struct statfs without relying on a guessed layout.
        data=ctypes.create_string_buffer(512)
        need(self.libc.fstatfs(self.parent,ctypes.byref(data))==0 and ctypes.c_long.from_buffer(data).value==0x1021994,'credential_stage_tmpfs_required')
    def add(self,source):
        self.runtime.require_armed();before=os.fstat(source)
        need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=65536
            and((before.st_uid==0 and stat.S_IMODE(before.st_mode)==0o440)
                or(before.st_uid==os.geteuid()and before.st_mode&0o077==0)),'credential_source_metadata')
        need(os.fstatvfs(source).f_flag&os.ST_RDONLY!=0,'credential_source_readonly_mount')
        raw=os.pread(source,before.st_size+1,0);need(len(raw)==before.st_size and unchanged(before,os.fstat(source)),'credential_source_drift')
        name='credential-'+uuid.uuid4().hex;fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.parent)
        mapping=None;address=None;readfd=None
        try:
            os.ftruncate(fd,len(raw));mapping=mmap.mmap(fd,len(raw),flags=mmap.MAP_SHARED,prot=mmap.PROT_READ|mmap.PROT_WRITE)
            address=ctypes.addressof(ctypes.c_char.from_buffer(mapping))
            need(self.libc.mlock(ctypes.c_void_p(address),ctypes.c_size_t(len(raw)))==0,'credential_stage_mlock')
            mapping.madvise(mmap.MADV_DONTDUMP);mapping[:]=raw;os.fchmod(fd,0o400)
            readfd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.parent)
            left,right=os.fstat(fd),os.fstat(readfd);need(unchanged(left,right),'credential_stage_reopen_identity')
            self.items.append((name,mapping,address,len(raw),readfd));return readfd
        except BaseException:
            if mapping is not None:
                if address is not None:ctypes.memset(ctypes.c_void_p(address),0,len(raw));self.libc.munlock(ctypes.c_void_p(address),ctypes.c_size_t(len(raw)))
                mapping.close()
            if readfd is not None:os.close(readfd)
            os.unlink(name,dir_fd=self.parent);raise
        finally:os.close(fd)
    def close(self):
        for name,mapping,address,size,fd in reversed(self.items):
            ctypes.memset(ctypes.c_void_p(address),0,size);self.libc.munlock(ctypes.c_void_p(address),ctypes.c_size_t(size));mapping.close();os.close(fd);os.unlink(name,dir_fd=self.parent)
        self.items.clear();os.close(self.parent)
