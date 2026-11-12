"""Bind public legacy code to a new site and recompute embedded code pins.
No live files, site secrets, DB rows or service operations are accessed here.
"""
import hashlib,ipaddress,json,re
from pathlib import Path
from release import require

def validate(site):
 require(set(site)=={'mail_host','primary_domain','public_ipv4','notification_recipient','legacy_pop_host','legacy_import_email','migration_domain'},'site_fields')
 for k in('mail_host','primary_domain','legacy_pop_host','migration_domain'):
  require(isinstance(site[k],str)and len(site[k])<=253 and re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}',site[k]),'site_hostname')
 require(isinstance(ipaddress.ip_address(site['public_ipv4']),ipaddress.IPv4Address),'site_IPv4')
 for k in('notification_recipient','legacy_import_email'):require(isinstance(site[k],str)and re.fullmatch(r'[a-z0-9_.+-]{1,64}@(?:[a-z0-9-]+\.)+[a-z]{2,63}',site[k]),'site_email')
 return site

def bind(files,site):
 validate(site)
 replacements={'ken@mi-sys.co.jp':site['notification_recipient'],'ken@mi-sys.jp':site['legacy_import_email'],'mail.mi-sys.jp':site['legacy_pop_host'],'mx.mi-sys.jp':site['mail_host'],'yukido.co.jp':site['migration_domain'],'mi-sys.jp':site['primary_domain'],'162.43.6.80':site['public_ipv4']}
 rendered={}
 for name,raw in files.items():
  try:text=raw.decode('utf-8')
  except UnicodeDecodeError:rendered[name]=raw;continue
  for old,new in sorted(replacements.items(),key=lambda x:-len(x[0])):text=text.replace(old,new)
  rendered[name]=text.encode()
 # Every iteration starts from the bound base, so transitive dependencies cannot retain intermediate hashes.
 hashes=lambda data:{n:hashlib.sha256(b).hexdigest()for n,b in data.items()}
 original=hashes(files);current=rendered
 for _ in range(len(files)+1):
  newhash=hashes(current);mapping={}
  for n,h in original.items():
   v=(newhash[n],len(current[n]),len(files[n]))
   require(h not in mapping or mapping[h]==v,'ambiguous_source_pin');mapping[h]=v
  following={}
  for name,raw in rendered.items():
   try:text=raw.decode()
   except UnicodeDecodeError:following[name]=raw;continue
   def pair(m):
    old=m['hash'];v=mapping.get(old)
    return m['head']+str(v[1])+m['sep']+v[0] if v and int(m['size'])==v[2] else m[0]
   text=re.sub(r"(?P<head>[\[(]\s*)(?P<size>[0-9]+)(?P<sep>\s*,\s*['\"])(?P<hash>[a-f0-9]{64})",pair,text)
   text=re.sub(r'[a-f0-9]{64}',lambda m:mapping[m[0]][0]if m[0]in mapping else m[0],text)
   following[name]=text.encode()
  if following==current:break
  current=following
 else:raise ValueError('cyclic_source_pins')
 for name,raw in current.items():
  if name.endswith('.py'):compile(raw,name,'exec')
 return current

def render(source,site,destination):
 root=Path(source);dest=Path(destination);require(not dest.exists(),'destination_exists')
 files={p.relative_to(root).as_posix():p.read_bytes()for p in root.rglob('*')if p.is_file()and not p.is_symlink()}
 out=bind(files,site);dest.mkdir(mode=0o700)
 for n,b in out.items():p=dest/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
 return {'files':len(out),'code_sha256':{n:hashlib.sha256(b).hexdigest()for n,b in out.items()}}
