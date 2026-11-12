"""Signed release format. No host data or credentials belong in a release."""
import base64,gzip,hashlib,io,json,os,re,subprocess,tarfile,tempfile
from pathlib import Path,PurePosixPath
MAX_ARCHIVE=128*1024*1024
MAX_EXPANDED=512*1024*1024
MAX_FILES=12000
class ReleaseError(ValueError):pass

def require(ok,reason):
 if not ok:raise ReleaseError(reason)
def canonical(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode()
def sha(b):return hashlib.sha256(b).hexdigest()
def version(v):
 require(isinstance(v,str)and re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',v),'version')
 return tuple(map(int,v.split('.')))
def member(name):
 require(isinstance(name,str)and len(name)<400 and '\\'not in name and '\x00'not in name,'member_name')
 p=PurePosixPath(name);require(not p.is_absolute()and p.as_posix()==name and all(x not in('','..','.')for x in name.split('/')),'member_path')
 require(name=='bundle.json'or name.startswith('payload/'),'member_scope');return p

def openssl_run(openssl,args,input_data=None):
 p=subprocess.run([str(openssl),*map(str,args)],input=input_data,capture_output=True,timeout=30)
 require(p.returncode==0,'signature_operation_failed');return p.stdout

def sign(meta,key,openssl='openssl',passphrase=None):
 if passphrase is not None:
  require(isinstance(passphrase,bytes)and passphrase and b'\n'not in passphrase and b'\r'not in passphrase and b'\0'not in passphrase,'signing_passphrase_input')
 with tempfile.TemporaryDirectory()as td:
  p=Path(td);(p/'data').write_bytes(canonical(meta))
  args=['pkeyutl','-sign','-rawin','-inkey',key,'-in',p/'data','-out',p/'sig']
  if passphrase is not None:args+=['-passin','stdin']
  openssl_run(openssl,args,None if passphrase is None else passphrase+b'\n')
  return base64.b64encode((p/'sig').read_bytes()).decode()
def verify_signature(meta,signature,key,openssl='openssl'):
 try:raw=base64.b64decode(signature,validate=True)
 except Exception:raise ReleaseError('signature_encoding')
 require(len(raw)==64,'signature_length')
 with tempfile.TemporaryDirectory()as td:
  p=Path(td);(p/'data').write_bytes(canonical(meta));(p/'sig').write_bytes(raw);openssl_run(openssl,['pkeyutl','-verify','-rawin','-pubin','-inkey',key,'-in',p/'data','-sigfile',p/'sig'])

def build(source,entries,release,output,ready=False):
 version(release);root=Path(source).resolve();files={};rows=[]
 for row in entries:
  name=row['name'];member(name);require(name!='bundle.json'and name not in files,'duplicate_member')
  rel=PurePosixPath(row['source']);require(not rel.is_absolute()and all(x not in('..','.')for x in rel.parts),'source_path')
  p=root.joinpath(*rel.parts);require(p.is_file()and not p.is_symlink()and root in p.resolve().parents,'source_escape')
  require(not any(x.is_symlink()for x in [p,*p.parents]if x!=root.parent),'source_link')
  require(p.suffix.lower()not in('.key','.pem','.p12','.pfx','.db','.sqlite','.csv','.log'),'private_file_type')
  raw=p.read_bytes();require(sha(raw)==row['sha256'],'source_pin')
  require(len(raw)<=8*1024*1024,'file_size');files[name]=raw;rows.append({'name':name,'sha256':sha(raw),'size':len(raw),'mode':row.get('mode',0o644)})
 require(0<len(files)<=MAX_FILES and sum(map(len,files.values()))<MAX_EXPANDED,'release_size')
 require(all(x['mode']in(0o644,0o755)for x in rows),'file_mode')
 manifest={'format':1,'product':'mail-platform','version':release,'os':'debian-13','architecture':'amd64','install_ready':bool(ready),'files':sorted(rows,key=lambda x:x['name'])}
 files['bundle.json']=canonical(manifest)
 with Path(output).open('xb')as out:
  with gzip.GzipFile(fileobj=out,mode='wb',mtime=0,filename='')as gz:
   with tarfile.open(fileobj=gz,mode='w',format=tarfile.USTAR_FORMAT)as tf:
    for name,raw in sorted(files.items()):
     i=tarfile.TarInfo(name);i.size=len(raw);i.mode=0o644 if name=='bundle.json'else next(x['mode']for x in rows if x['name']==name);i.mtime=0;i.uid=i.gid=0;i.uname=i.gname='';tf.addfile(i,io.BytesIO(raw))
 raw=Path(output).read_bytes();require(len(raw)<=MAX_ARCHIVE,'archive_size')
 return {'format':1,'product':'mail-platform','version':release,'sha256':sha(raw),'size':len(raw),'manifest_sha256':sha(canonical(manifest))}

def inspect(archive,meta,signature,key,openssl='openssl'):
 verify_signature(meta,signature,key,openssl);version(meta.get('version'));require(meta.get('product')=='mail-platform'and meta.get('format')==1,'metadata')
 require(0<meta['size']<=MAX_ARCHIVE,'archive_size');p=Path(archive);require(p.stat().st_size==meta['size'],'archive_size');require(sha(p.read_bytes())==meta['sha256'],'archive_hash')
 files={};total=0
 with tarfile.open(p,'r:gz')as tf:
  for i in tf:
   member(i.name);require(i.isfile()and not i.issparse()and i.name not in files,'archive_member_type')
   require(len(files)<MAX_FILES and 0<=i.size<=8*1024*1024,'member_size');total+=i.size;require(total<=MAX_EXPANDED,'expanded_size')
   raw=tf.extractfile(i).read(i.size+1);require(len(raw)==i.size,'truncated_member');files[i.name]=(raw,i.mode)
 require('bundle.json'in files,'manifest_missing');mraw=files['bundle.json'][0];require(sha(mraw)==meta['manifest_sha256'],'manifest_hash')
 m=json.loads(mraw);require(m['version']==meta['version']and m['product']=='mail-platform'and m['format']==1 and m['os']=='debian-13'and m['architecture']=='amd64','manifest')
 expected={x['name']:x for x in m['files']};require(len(expected)==len(m['files'])and set(files)==set(expected)|{'bundle.json'},'manifest_members')
 for name,row in expected.items():
  require(name!='bundle.json','manifest_recursive');raw,mode=files[name];require(sha(raw)==row['sha256']and len(raw)==row['size']and mode==row['mode']and mode in(0o644,0o755),'payload_hash_or_mode')
 return m,files

def extract_verified(files,destination):
 dest=Path(destination);require(not dest.exists(),'stage_exists');dest.mkdir(mode=0o700,parents=False)
 for name,(raw,mode)in files.items():
  member(name);p=dest.joinpath(*PurePosixPath(name).parts);p.parent.mkdir(parents=True,exist_ok=True)
  with p.open('xb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
  os.chmod(p,mode)
 return dest
