"""Prove the dedicated nonroot identity immediately before exec of a pinned binary."""
import hashlib,json,os,pathlib,pwd,stat,sys,time,uuid
ROOT=pathlib.Path("/var/lib/mail-antivirus-v1")
def need(v,label):
 if not v:raise ValueError(label)
def main():
 need(sys.argv[1:]in(["engine"],["update"]),"exact_guard_mode");mode=sys.argv[1]
 user=pwd.getpwnam("mailantivirus");need(user.pw_uid>0 and os.geteuid()==user.pw_uid and os.getegid()==111,"dedicated_antivirus_identity")
 fields=dict(x.split(":",1)for x in pathlib.Path("/proc/self/status").read_text().splitlines()if":"in x)
 role={k:fields[k].strip()for k in("Uid","Gid","Groups","NoNewPrivs","CapInh","CapBnd","CapPrm","CapEff","CapAmb")}
 need(role["Uid"].split()==[str(user.pw_uid)]*4 and role["Gid"].split()==["111"]*4 and set(role["Groups"].split())<={"111"}and role["NoNewPrivs"]=="1"and all(int(role[k],16)==0 for k in("CapInh","CapBnd","CapPrm","CapEff","CapAmb")),"antivirus_capability_boundary")
 binary="/usr/local/sbin/clamd"if mode=="engine"else"/usr/local/bin/freshclam"
 path=pathlib.Path(binary);info=path.lstat();need(stat.S_ISREG(info.st_mode)and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o755 and info.st_nlink==1,"pinned_binary_attributes")
 manifest_path=pathlib.Path("/etc/mail-antivirus-v1/runtime-pins.json");meta=manifest_path.lstat();need(stat.S_ISREG(meta.st_mode)and meta.st_uid==0 and not meta.st_mode&0o022,"runtime_manifest_attributes")
 expected=json.loads(manifest_path.read_bytes())[binary];need(hashlib.sha256(path.read_bytes()).hexdigest()==expected,"native_runtime_pin")
 value={"mode":mode,"pid":os.getpid(),"observed_at":time.time(),"identity":role,"binary_sha256":expected}
 temporary=ROOT/("."+uuid.uuid4().hex);target=ROOT/(mode+"-identity.json")
 with temporary.open("xb")as f:os.fchmod(f.fileno(),0o640);f.write((json.dumps(value,sort_keys=True)+"\n").encode());f.flush();os.fsync(f.fileno())
 os.replace(temporary,target)
 fd=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
 config="/etc/mail-antivirus-v1/"+("clamd.conf"if mode=="engine"else"freshclam.conf")
 args=[binary,"--config-file="+config]+(["--stdout"]if mode=="update"else[])
 os.execve(binary,args,{"PATH":"/usr/local/bin:/usr/local/sbin:/usr/bin:/bin","LD_LIBRARY_PATH":"/usr/local/lib","LC_ALL":"C","TZ":"UTC","SSL_CERT_FILE":"/etc/ssl/certs/ca-certificates.crt","CURL_CA_BUNDLE":"/etc/ssl/certs/ca-certificates.crt"})
if __name__=="__main__":main()
