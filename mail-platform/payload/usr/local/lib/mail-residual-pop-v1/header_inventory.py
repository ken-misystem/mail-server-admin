"""Strict header-only UIDL inventory; does not save or modify messages."""
import os,re,stat,time
from pathlib import Path
from email import policy
from email.parser import BytesHeaderParser
def scan(maildir,vmail_uid,deadline_seconds=120):
 root=Path(maildir);need=lambda v,label:None if v else (_ for _ in()).throw(ValueError(label))
 for p in(root,*root.parents):
  st=p.lstat();need(stat.S_ISDIR(st.st_mode)and st.st_uid in(0,vmail_uid)and not st.st_mode&0o022,"Maildir_parent")
 result={};count=untagged=0;deadline=time.monotonic()+deadline_seconds
 def failed(error):raise ValueError("Maildir_walk_failed")from None
 for dirname,dirs,files in os.walk(root,followlinks=False,onerror=failed):
  base=Path(dirname)
  need(time.monotonic()<deadline,"Maildir_deadline")
  for name in dirs:
   st=(base/name).lstat();need(stat.S_ISDIR(st.st_mode)and st.st_uid in(0,vmail_uid)and not st.st_mode&0o022,"Maildir_directory")
  if base.name not in("new","cur"):continue
  parent=base.parent
  need(parent==root or(parent.parent==root and parent.name.startswith(".")),"Maildir_folder_scope")
  box="INBOX"if parent==root else parent.name[1:]
  for name in files:
   count+=1;need(count<=200000 and time.monotonic()<deadline,"Maildir_bound")
   path=base/name
   with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),"rb")as f:
    st=os.fstat(f.fileno());need(stat.S_ISREG(st.st_mode)and st.st_uid==vmail_uid and st.st_nlink==1 and st.st_size>0,"message_metadata")
    header=bytearray()
    while True:
     line=f.readline(1048577-len(header));header.extend(line)
     need(line and len(header)<=1048576,"message_header_bound")
     if line in(b"\n",b"\r\n"):break
    parsed=BytesHeaderParser(policy=policy.default).parsebytes(bytes(header))
    values=parsed.get_all("X-UIDL",[])
    need(len(values)<=1,"message_multiple_UIDL_headers")
    if values:
     token=str(values[0]).strip();need(re.fullmatch("[!-~]{1,1024}",token)is not None,"message_UIDL")
     result.setdefault(token,[]).append((box,str(path)))
    else:untagged+=1
    key=lambda x:(x.st_dev,x.st_ino,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    need(key(st)==key(os.fstat(f.fileno()))==key(path.lstat()),"message_changed_during_scan")
 return result,{"files":count,"tagged_unique":len(result),"untagged":untagged,"body_requested":False}
