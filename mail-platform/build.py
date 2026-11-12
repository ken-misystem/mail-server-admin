"""Build from active sources in the SAME repository, never a second Git repository."""
import argparse,base64,hashlib,json,re,sys,tarfile,tempfile,gzip,io
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE/'framework'))
from release import build,sha,member,require,version,canonical
from site_bindings import rebase
from source_patches import apply as apply_source_patch

def release_cache(text):
 before="public function getCacheDir(): string { return $this->stateDirectory . '/cache-' . $this->environment . '-' . self::CACHE_LAYOUT; }"
 after="""public function getCacheDir(): string
    {
        $manifest = hash_file('sha256', dirname(__DIR__) . '/BUNDLE_MANIFEST.json');
        if (!is_string($manifest)) { throw new \\RuntimeException('application_manifest'); }
        return $this->stateDirectory . '/cache-' . $this->environment . '-' . self::CACHE_LAYOUT . '-' . substr($manifest, 0, 16);
    }"""
 if after in text:return text
 require(text.count(before)==1,'kernel_cache_anchor')
 return text.replace(before,after)

def transformed(name,raw):
 text=raw.decode('utf-8')
 if name=='update_navigation':
  if "'/mail-admin/updates'"in text:return raw
  a="'管理者・監査'=>[";require(text.count(a)==1,'navigation_anchor');return text.replace(a,a+"\n                ['ソフトウェア更新','/mail-admin/updates',['ソフトウェア更新']],").encode()
 if name=='update_kernel':
  if "'mail_admin_updates'"in text:return release_cache(text).encode()
  a="$services->set(ProtectionController::class)->public()->args([service('security.token_storage'),service('security.csrf.token_manager'),service(ProtectionStore::class),service('limiter.mail_admin_scoped_write')]);"
  require(text.count(a)==1,'kernel_service_anchor');text=text.replace(a,a+"\n        $services->set(UpdateClient::class)->public();\n        $services->set(UpdateController::class)->public()->args([service('security.token_storage'),service('security.csrf.token_manager'),service(UpdateClient::class),service('limiter.mail_admin_scoped_write')]);")
  a="$routes->add('mail_admin_protection_read'";require(text.count(a)==1,'kernel_route_anchor');text=text.replace(a,"$routes->add('mail_admin_updates','/mail-admin/updates')->methods(['GET'])->controller(UpdateController::class.'::show');\n        $routes->add('mail_admin_updates_save','/mail-admin/updates')->methods(['POST'])->controller(UpdateController::class.'::save');\n        "+a)
  return release_cache(text).encode()
 raise ValueError('unknown_transform')

def prepare(repository):
 repository=Path(repository).resolve();catalog=json.loads((HERE/'source-catalog.json').read_bytes());lock=json.loads((HERE/'dependency-lock.json').read_bytes());generated={};files={};changed=[];offline=0
 patches_path=HERE/'source-patches.json'
 patches=json.loads(patches_path.read_bytes())if patches_path.exists()else{}
 require(all(name in catalog and catalog[name]['provider']in('repository','generated')for name in patches),'source_patch_registration')
 for n,ref in sorted(catalog.items()):
  member('payload/'+n)
  if ref['provider']=='repository':
   source=repository/ref['path'];require(repository in source.resolve().parents,'repository_source_escape')
   if source.is_file():raw=source.read_bytes()
   else:
    require('/dependency/vendor.tmp/'in ref['path'],'repository_source_missing:'+ref['path']);require(sha((repository/lock['path']).read_bytes())==lock['sha256'],'offline_vendor_lock_changed');raw=(HERE/'payload'/n).read_bytes();offline+=1
   if ref.get('normalize_LF')and sha(raw)!=ref.get('baseline_sha256'):raw=raw.replace(b'\r\n',b'\n')
  elif ref['provider']=='generated':
   recipe=ref['recipe']
   if recipe not in generated:
    if recipe=='installation_recipes':
     import recipe_catalog;generated[recipe]=recipe_catalog.build(repository)
    elif recipe in ('protection_resume_bundle',):
     sys.path.insert(0,str(repository/'mail-management/feature-port-v1/protection-relay-v1/activation-v3'));import protection_resume_bundle;generated[recipe]={k:base64.b64decode(v['base64'],validate=True)for k,v in protection_resume_bundle.build()['files'].items()}
    else:raise ValueError('unregistered_build_recipe')
   raw=generated[recipe][ref['member']]
  elif ref['provider']=='package':
   source=HERE/ref['path'];require(HERE in source.resolve().parents,'package_source_escape');raw=source.read_bytes()
  else:raise ValueError('provider')
  raw=apply_source_patch(n,raw,patches)
  if ref.get('transform'):raw=transformed(ref['transform'],raw)
  files['payload/'+n]=raw
  if ref.get('baseline_sha256')and sha(raw)!=ref['baseline_sha256']:changed.append(n)
 # Rebase source-integrity references after a registered source was edited.
 baseline={}
 for n,raw in files.items():
  cached=HERE/n
  baseline[n]=cached.read_bytes()if cached.is_file()else raw
 files=rebase(files,baseline)
 # The application manifest is generated from current source bytes after integrations.
 prefix='payload/opt/mail-management/candidates/protection-relay-v1/';m={n[len(prefix):]:{'bytes':len(b),'sha256':sha(b)}for n,b in files.items()if n.startswith(prefix)and not n.endswith('/BUNDLE_MANIFEST.json')}
 files[prefix+'BUNDLE_MANIFEST.json']=json.dumps(m,sort_keys=True,indent=2).encode()+b'\n'
 for n in ['install.py','readiness.json','site.example.json','facts.example.json','kit.example.json','configuration-plan.json','README.md','INSTALLATION.md','RELEASE.md','ACCEPTANCE.md','native_assets.py','native-assets-lock.json','NATIVE_ASSETS.md','VALIDATION.md']:files[n]=(HERE/n).read_bytes()
 for name in ('LICENSE', 'LICENSING.md', 'licenses/roundcube/LICENSE'):
  raw = (HERE/name).read_bytes()
  files[name] = raw
  files['payload/usr/local/lib/mail-platform-update/licenses/'+name] = raw
 if patches:files['source-patches.json']=patches_path.read_bytes()
 hook=HERE/'update_entry.py'
 if hook.exists():files['payload/installer.py']=hook.read_bytes()
 return files,{'changed_sources':changed,'offline_vendor_files':offline,'source_providers':{k:sum(v['provider']==k for v in catalog.values())for k in ['repository','generated','package']}}

def main():
 p=argparse.ArgumentParser();p.add_argument('--repository-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--version',required=True);p.add_argument('--update-contract',type=Path);a=p.parse_args();version(a.version);files,info=prepare(a.repository_root)
 files['product-version.json']=canonical({'version':a.version})
 if a.update_contract:
  update=json.loads(a.update_contract.read_bytes())
  require(set(update)=={'format','from_version','to_version','pause','stop','start','reload','health'}and update['format']==1,'update_contract_shape')
  require(update['to_version']==a.version and version(update['from_version'])<version(a.version),'update_contract_version')
  files['payload/blueprint/update-contract.json']=canonical(update)
 require(not a.output.exists(),'output_exists');a.output.mkdir(parents=True)
 # Candidate archive. It intentionally is not a GitHub auto-installable release asset.
 target=a.output/('mail-platform-'+a.version+'-source-candidate.tar.gz')
 with target.open('xb')as f:
  with gzip.GzipFile(fileobj=f,mode='wb',mtime=0,filename='')as gz:
   with tarfile.open(fileobj=gz,mode='w',format=tarfile.USTAR_FORMAT)as tf:
    for n,raw in sorted(files.items()):
     require(not n.startswith('/')and '..'not in Path(n).parts,'candidate_path');t=tarfile.TarInfo(n);t.size=len(raw);t.mode=0o644;t.mtime=0;tf.addfile(t,io.BytesIO(raw))
 report={'status':'source_candidate_only','version':a.version,'files':len(files),'archive':target.name,'sha256':sha(target.read_bytes()),'bytes':target.stat().st_size,'install_ready':False,'formal_release_published':False,**info};(a.output/'build-result.json').write_text(json.dumps(report,indent=2),encoding='utf-8');require(json.loads((a.output/'build-result.json').read_bytes())==report,'report_readback');print(json.dumps(report))
if __name__=='__main__':main()
