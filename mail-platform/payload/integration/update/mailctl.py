"""Installed entry point. A private-repository token is read only from systemd credentials."""
import argparse,json,os,time
from pathlib import Path
from release import require,version
from updater import load,save,run_update
from github import latest,fetch,repo
ROOT=Path('/var/lib/mail-platform-update')

def check(apply_manual=False):
 require(os.geteuid()==0,'root_required');os.umask(0o077)
 cfg=load('/etc/mail-platform/update-source.json');repository=repo(cfg['repository'])
 creds=os.environ.get('CREDENTIALS_DIRECTORY');token=None
 if creds and (Path(creds)/'github-token').is_file():
  token=(Path(creds)/'github-token').read_text().strip();require(0<len(token)<=4096 and '\n'not in token and '\r'not in token,'token_file')
 release=latest(repository,token);tag=release['tag'];require(tag.startswith('v'),'release_tag');version(tag[1:])
 current=load(ROOT/'installed.json',{'version':'0.0.0'})
 if version(tag[1:])<=version(current['version']):return {'phase':'current','version':current['version']}
 cache=ROOT/'downloads';cache.mkdir(mode=0o700,exist_ok=True)
 available=load(ROOT/'available.json',{})
 cached=available.get('cache')
 reusable=(available.get('verified')is True and available.get('assets')==release['assets']and available.get('version')==tag[1:]and isinstance(cached,str)and Path(cached).parent==cache and Path(cached).is_dir()and not Path(cached).is_symlink())
 settings=load(ROOT/'policy.json',{'revision':0,'mode':'manual'})
 if reusable and not apply_manual and settings['mode']=='manual':return {'phase':'available','version':tag[1:]}
 dest=Path(cached)if reusable else fetch(repository,release,cache/(tag+'-'+str(time.time_ns())),token)
 metadata=json.loads((dest/'release.json').read_bytes());require(metadata['version']==tag[1:],'tag_metadata_mismatch')
 result=run_update(ROOT,dest/'mail-platform.tar.gz',metadata,(dest/'release.sig').read_text().strip(),'/etc/mail-platform/release-public.pem',manual=apply_manual)
 if result['phase']=='available':save(ROOT/'available.json',{'version':tag[1:],'verified':True,'manual_approval_required':True,'assets':release['assets'],'cache':str(dest)})
 if result['phase']=='complete'and(ROOT/'manual-request.json').exists():
  # Preserve the accepted request instead of discarding its audit record.
  os.replace(ROOT/'manual-request.json',ROOT/('completed-request-'+str(time.time_ns())+'.json'))
 return result
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('command',choices=['check','worker']);args=p.parse_args()
 try:
  result=check(apply_manual=args.command=='worker'and(ROOT/'manual-request.json').exists());print(json.dumps(result))
 except Exception as e:
  # Finite error names, not subprocess output, secrets, tokens or URLs.
  print(json.dumps({'phase':'failed','error':type(e).__name__,'reason':str(e)if isinstance(e,ValueError)else'operation_failed'}));raise SystemExit(1)
