"""GitHub Releases client: HTTPS only, token never follows asset redirects."""
import json,re,urllib.request,urllib.parse
from pathlib import Path
from release import require,ReleaseError,MAX_ARCHIVE,version
class Redirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,url):
  p=urllib.parse.urlsplit(url)
  require(p.scheme=='https'and p.hostname in('api.github.com','github.com','release-assets.githubusercontent.com','objects.githubusercontent.com')and p.port in(None,443)and not p.username and not p.password,'asset_redirect')
  new=super().redirect_request(req,fp,code,msg,headers,url)
  if new:
   for name in list(new.headers):
    if name.lower()=='authorization':del new.headers[name]
  return new

def repo(value):
 require(isinstance(value,str)and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}',value),'github_repository');return value

def request(url,limit,token=None,accept='application/vnd.github+json'):
 p=urllib.parse.urlsplit(url);require(p.scheme=='https'and p.hostname=='api.github.com'and p.port in(None,443)and not p.username and not p.password,'api_url')
 headers={'User-Agent':'mail-platform-updater/1','Accept':accept,'X-GitHub-Api-Version':'2022-11-28'}
 if token:headers['Authorization']='Bearer '+token
 opener=urllib.request.build_opener(Redirect());req=urllib.request.Request(url,headers=headers)
 try:
  with opener.open(req,timeout=30)as f:raw=f.read(limit+1)
 except Exception:raise ReleaseError('github_request_failed')from None
 require(len(raw)<=limit,'download_size');return raw

def latest(repository,token=None):
 repository=repo(repository);rows=json.loads(request('https://api.github.com/repos/'+repository+'/releases?per_page=100',1024*1024,token))
 require(isinstance(rows,list)and len(rows)<=100,'release_list')
 stable=[row for row in rows if isinstance(row,dict)and not row.get('draft')and not row.get('prerelease')and isinstance(row.get('tag_name'),str)and re.fullmatch(r'v(?:0|[1-9][0-9]*)[.](?:0|[1-9][0-9]*)[.](?:0|[1-9][0-9]*)',row['tag_name'])]
 if not stable:return None
 v=max(stable,key=lambda row:version(row['tag_name'][1:]))
 require(not v.get('draft')and not v.get('prerelease')and isinstance(v.get('assets'),list),'not_stable_release')
 wanted={}
 for a in v['assets']:
  if a.get('name')in('mail-platform.tar.gz','release.json','release.sig'):
   require(a['name']not in wanted,'duplicate_asset');require(isinstance(a.get('id'),int)and a['id']>0,'asset_id')
   wanted[a['name']]=a['id']
 require(len(wanted)==3,'release_assets_missing');return {'tag':v['tag_name'],'assets':wanted}

def fetch(repository,release,directory,token=None):
 repository=repo(repository);dest=Path(directory);require(not dest.exists(),'download_dir_exists');dest.mkdir(mode=0o700)
 for name,asset in release['assets'].items():
  require(name in('mail-platform.tar.gz','release.json','release.sig')and type(asset)is int and asset>0,'asset')
  limit=MAX_ARCHIVE if name.endswith('.tar.gz')else 65536
  raw=request('https://api.github.com/repos/'+repository+'/releases/assets/'+str(asset),limit,token,'application/octet-stream')
  with (dest/name).open('xb')as f:f.write(raw)
 return dest
