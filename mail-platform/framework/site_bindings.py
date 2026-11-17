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
 bindings=dict(replacements)
 for old,new in replacements.items():
  if '.' in old and '@' not in old:
   for pattern in {re.escape(old),old.replace('.',r'\.')}:
    bindings[pattern]=re.escape(new)
    bindings[pattern.replace('\\','\\\\')]=re.escape(new).replace('\\','\\\\')
 matcher=re.compile('|'.join(re.escape(value) for value in sorted(bindings,key=len,reverse=True)))
 rendered={}
 for name,raw in files.items():
  try:text=raw.decode('utf-8')
  except UnicodeDecodeError:rendered[name]=raw;continue
  text=matcher.sub(lambda match:bindings[match.group()],text)
  rendered[name]=text.encode()
 return rebase(rendered,files)

def rebase(rendered,baseline):
 # Every iteration starts from the bound base, so transitive dependencies cannot retain intermediate hashes.
 hashes=lambda data:{n:hashlib.sha256(b).hexdigest()for n,b in data.items()}
 original=hashes(baseline);current=rendered
 for _ in range(len(rendered)+1):
  newhash=hashes(current);mapping={}
  for n,h in original.items():
   v=(newhash[n],len(current[n]),len(baseline[n]))
   require(h not in mapping or mapping[h]==v,'ambiguous_source_pin');mapping[h]=v
  following={}
  for name,raw in rendered.items():
   # Upstream diffs and their body digests are data, not code-pin references.
   if name.removeprefix('payload/').startswith('integration/roundcube-patches/')and name.endswith('.patch'):
    following[name]=raw;continue
   try:text=raw.decode()
   except UnicodeDecodeError:following[name]=raw;continue
   if name.endswith('.json'):
    def update(value):
     if isinstance(value,dict):
      old=value.get('sha256');v=mapping.get(old)if isinstance(old,str)else None
      result={mapping[k][0]if k in mapping else k:update(x)for k,x in value.items()}
      if v:
       result['sha256']=v[0]
       for key in ('bytes','size'):
        if value.get(key)==v[2]:result[key]=v[1]
      return result
     if isinstance(value,list):
      if len(value)==2 and type(value[0])is int and isinstance(value[1],str)and value[1]in mapping:
       v=mapping[value[1]]
       if value[0]==v[2]:return [v[1],v[0]]
      return [update(x)for x in value]
     return mapping[value][0]if isinstance(value,str)and value in mapping else value
    text=json.dumps(update(json.loads(text)),sort_keys=True,indent=2)+'\n'
   else:
    # Strict loaders compare a paired length and digest, not a tuple. Rebind
    # both from the same source; never replace an unrelated integer constant.
    def paired_loader(m):
     v=mapping.get(m['hash'])
     if not v:return m[0]
     require(int(m['size'])==v[2],'loader_source_size_pin')
     return m['head']+str(v[1])+m['between']+v[0]+m['quote']
    text=re.sub(r"(?P<head>len\((?P<variable>[A-Za-z_]\w*)\)\s*!=\s*)(?P<size>[0-9]+)(?P<between>\s+or\s+hashlib\.sha256\((?P=variable)\)\.hexdigest\(\)\s*!=\s*(?P<quote>['\"]))(?P<hash>[a-f0-9]{64})(?P=quote)",paired_loader,text)
    def reference(m):
     v=mapping.get(m['hash'])
     if not v:return m[0]
     if m['head']and int(m['size'])==v[2]:return m['head']+str(v[1])+m['sep']+v[0]
     return (m['head']+m['size']+m['sep']if m['head']else '')+v[0]
    text=re.sub(r"(?:(?P<head>[\[(]\s*)(?P<size>[0-9]+)(?P<sep>\s*,\s*['\"]))?(?P<hash>[a-f0-9]{64})",reference,text)
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
