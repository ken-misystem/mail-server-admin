"""Durable intent and CAS-only file restore. Never rolls back mail, data or histories."""
import base64,hashlib,json,os,stat,uuid
from pathlib import Path
import read_support as c

def attrs(path):
 s=os.lstat(path);return {'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode),'inode':s.st_ino,'device':s.st_dev,'nlink':s.st_nlink,'mtime_ns':s.st_mtime_ns,'ctime_ns':s.st_ctime_ns,'xattrs':{k:base64.b64encode(os.getxattr(path,k,follow_symlinks=False)).decode()for k in os.listxattr(path,follow_symlinks=False)}}
def atomic(path,raw,mode,uid,gid,xattrs=None,expected=None):
 path=Path(path);temporary=path.parent/('.feature-'+uuid.uuid4().hex);fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,'wb',closefd=False)as f:f.write(raw);f.flush();os.fchmod(fd,mode);os.fchown(fd,uid,gid);os.fsync(fd)
 finally:os.close(fd)
 for k,v in(xattrs or{}).items():os.setxattr(temporary,k,base64.b64decode(v),follow_symlinks=False)
 syncfd=os.open(temporary,os.O_RDONLY|os.O_NOFOLLOW)
 try:os.fsync(syncfd)
 finally:os.close(syncfd)
 if expected is not None:c.need(attrs(path)==expected,'CAS_before_replace')
 os.replace(temporary,path);directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(directory)
 finally:os.close(directory)
class Journal:
 def __init__(self,work):self.work=Path(work);self.rows=[];self.path=self.work/'journal.json';self.phase='preflight';self.save()
 def save(self):atomic(self.path,(json.dumps({'version':1,'phase':self.phase,'files':self.rows},sort_keys=True,indent=2)+'\n').encode(),0o600,0,0)
 def mark(self,phase):self.phase=phase;self.save()
 def swap(self,path,raw):
  path=Path(path);old,meta=c.protected(path);before=attrs(path);record={'path':str(path),'before':before,'before_sha256':c.sha(old),'after_sha256':c.sha(raw),'backup':str(len(self.rows))+'.data','state':'intent','after':None};c.write(self.work/record['backup'],old);self.rows.append(record);self.save();c.need(attrs(path)==before,'CAS_before_swap');atomic(path,raw,before['mode'],before['uid'],before['gid'],before['xattrs'],expected=before);record['after']=attrs(path);c.need(c.protected(path)[1]['sha256']==record['after_sha256'],'CAS_after_swap');record['state']='applied';self.save()
 def assert_known(self,record):
  path=Path(record['path']);raw,meta=c.protected(path);c.need(record['state']=='applied'and meta['sha256']==record['after_sha256']and attrs(path)==record['after'],'unknown_change_no_restore')
 def restore(self,paths=None):
  selected=[r for r in reversed(self.rows)if paths is None or r['path']in paths]
  newest={}
  for r in selected:
   if r['state']!='restored':newest.setdefault(r['path'],r)
  for r in newest.values():self.assert_known(r)
  for r in selected:
   if r['state']=='restored':continue
   path=Path(r['path']);self.assert_known(r);old,meta=c.protected(self.work/r['backup']);c.need(meta['sha256']==r['before_sha256'],'backup_drift');before=r['before'];atomic(path,old,before['mode'],before['uid'],before['gid'],before['xattrs'],expected=r['after']);c.need(c.protected(Path(r['path']))[1]['sha256']==r['before_sha256'],'restore_readback');r['state']='restored'
   for older in reversed(self.rows[:self.rows.index(r)]):
    if older['path']==r['path']and older['state']=='applied':
     c.need(older['after_sha256']==r['before_sha256'],'restore_chain_changed');older['after']=attrs(path);break
   self.save()
