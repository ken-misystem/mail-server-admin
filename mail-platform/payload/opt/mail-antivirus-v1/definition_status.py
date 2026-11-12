"""Nonroot official database metadata after successful FreshClam; no email or secrets."""
import json,os,pathlib,pwd,stat,time,uuid
ROOT=pathlib.Path("/var/lib/mail-antivirus-v1")
def need(v,label):
 if not v:raise ValueError(label)
def main():
 user=pwd.getpwnam("mailantivirus");need(os.geteuid()==user.pw_uid and os.getegid()==111,"status_owner")
 records={}
 for name in("main","daily","bytecode"):
  candidates=[ROOT/"definitions"/(name+suffix)for suffix in(".cvd",".cld")]
  paths=[p for p in candidates if p.exists()];need(len(paths)==1,"official_database_inventory")
  path=paths[0];fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_uid==user.pw_uid and before.st_nlink==1 and before.st_size<=268435456,"database_attributes")
   parts=os.read(fd,512).decode("ascii").strip().split(":");need(len(parts)==9 and parts[0]=="ClamAV-VDB","official_header")
   records[name]={"version":int(parts[2]),"signatures":int(parts[3]),"build_epoch":int(parts[8]),"bytes":before.st_size}
   after=os.fstat(fd);named=os.stat(path,follow_symlinks=False);key=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
   need(key(before)==key(after)==key(named),"database_changed")
  finally:os.close(fd)
 need(-3600<=time.time()-records["daily"]["build_epoch"]<=172800,"official_daily_stale")
 value={"status":"pass","observed_at":time.time(),"databases":records,"real_mail_sent":False}
 temporary=ROOT/("."+uuid.uuid4().hex)
 with temporary.open("xb")as f:os.fchmod(f.fileno(),0o640);f.write((json.dumps(value,sort_keys=True)+"\n").encode());f.flush();os.fsync(f.fileno())
 os.replace(temporary,ROOT/"definitions-status.json")
 fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
if __name__=="__main__":main()
