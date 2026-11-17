"""Read the publisher's atomic, root-owned recipient threshold. No fallback to Inbox."""
import json,math,os,re,stat
from pathlib import Path
FRAGMENT=Path('/var/lib/mail-feature-public-v1/rspamd-managed.conf')

def parse(raw):
    if type(raw)is not bytes or not 0<len(raw)<=2097152:raise ValueError('threshold_bound')
    rules={};domains={}
    for line in raw.decode('ascii').splitlines():
        name,sep,value=line.partition(' = ')
        if not sep or not value.endswith(';'):raise ValueError('threshold_line')
        key=json.loads(name);row=json.loads(value[:-1])
        if not isinstance(key,str) or not re.fullmatch(r'mailadmin_threshold_[0-9]{4}',key) or key in rules:raise ValueError('threshold_name')
        if type(row)is not dict or set(row) not in ({'priority','rcpt','apply'},{'priority','rcpt','apply','selector','expression'}) or row['priority']!=2:raise ValueError('threshold_rule')
        if set(row['apply'])!={'actions'} or set(row['apply']['actions'])!={'reject','add header','greylist'}:raise ValueError('threshold_actions')
        a=row['apply']['actions'];numbers=[a[k] for k in ('greylist','add header','reject')]
        if not all(type(v)in(int,float) and math.isfinite(v) for v in numbers) or not 0<=numbers[0]<numbers[1]<numbers[2]<=100:raise ValueError('threshold_order')
        if type(row['rcpt'])is not list or not 1<=len(row['rcpt'])<=10000:raise ValueError('threshold_recipients')
        for recipient in row['rcpt']:
            if type(recipient)is not str or not re.fullmatch(r'@[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]',recipient) or '..'in recipient or recipient[1:] in domains:raise ValueError('threshold_domain')
            domains[recipient[1:]]=a['add header']
        rules[key]=row
    canonical=('\n'.join(json.dumps(k)+' = '+json.dumps(v,sort_keys=True,separators=(',',':'))+';' for k,v in rules.items())+'\n').encode()
    if not domains or canonical!=raw:raise ValueError('threshold_canonical')
    return domains

def for_recipient(address,path=FRAGMENT):
    if not isinstance(address,str) or not re.fullmatch(r'[a-z0-9][a-z0-9._+\-]*@[a-z0-9][a-z0-9.-]*',address):raise ValueError('threshold_address')
    path=Path(path)
    for parent in [path.parent,*path.parents][:-1]:
        st=parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:raise ValueError('threshold_parent')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1 or stat.S_IMODE(s.st_mode)!=0o644 or not 0<s.st_size<=2097152:raise ValueError('threshold_metadata')
        raw=os.pread(fd,s.st_size+1,0)
        after=os.fstat(fd)
        if len(raw)!=s.st_size or (s.st_ino,s.st_size,s.st_mtime_ns)!=(after.st_ino,after.st_size,after.st_mtime_ns):raise ValueError('threshold_changed')
    finally:os.close(fd)
    return str(parse(raw)[address.rsplit('@',1)[1]])
