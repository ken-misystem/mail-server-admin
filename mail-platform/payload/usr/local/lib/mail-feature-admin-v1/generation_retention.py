"""Only registered generated files, hash verified. Never recurse or touch mail."""
import hashlib,json,os,re,stat
from pathlib import Path
from runtime_files import read,write,encoded
from forward_publish import directory,sync_dir
from forwarding import need

def catalog(value):
    need(type(value)is dict and set(value)=={'version','generations'}and value['version']==1 and type(value['generations'])is dict and len(value['generations'])<=1000,'generation_catalog_schema')
    for name,row in value['generations'].items():
        need(type(name)is str and re.fullmatch('generation-[a-f0-9]{32}',name)is not None and type(row)is dict and set(row)=={'created_at','device','inode','manifest_sha256','deleting'},'generation_catalog_row')
        need(type(row['created_at'])is int and row['created_at']>=0 and type(row['device'])is int and row['device']>=0 and type(row['inode'])is int and row['inode']>0 and type(row['deleting'])is bool,'generation_catalog_attributes')
        need(type(row['manifest_sha256'])is str and re.fullmatch('[a-f0-9]{64}',row['manifest_sha256'])is not None,'generation_catalog_pin')
    return value

class Retention:
    def __init__(self,root,group,state):self.root=root;self.group=group;self.state=state;catalog(state.value)
    def validate_inventory(self):
        """An interrupted, unregistered compile stops publication, not disk growth.

        Unknown staging directories are evidence. Never remove or reuse them.
        A registered deletion may have reached rmdir before its state commit.
        """
        catalog(self.state.value);directory(self.root,self.group)
        rows=self.state.value['generations'];actual={entry.name for entry in self.root.iterdir()}
        need(actual<=set(rows)|{'current'},'generation_unregistered_artifact_preserved')
        need(all(name in actual or row['deleting']for name,row in rows.items()),'generation_registered_directory_missing')
        return {'unregistered_artifacts':0}
    def register(self,name,manifest):
        catalog(self.state.value);need(re.fullmatch('generation-[a-f0-9]{32}',name)is not None and name not in self.state.value['generations'],'generation_registration')
        path=self.root/name;directory(path,self.group);info=path.lstat();pin=write(path/'generation.json',encoded(manifest),group=self.group,mode=0o640,absent=True)
        value=json.loads(json.dumps(self.state.value));value['generations'][name]={'created_at':manifest['created_at'],'device':info.st_dev,'inode':info.st_ino,'manifest_sha256':pin,'deleting':False};catalog(value);self.state.save(value)
    def collect(self,now):
        need(type(now)is int and now>=0,'generation_retention_clock');self.validate_inventory()
        current=self.root/'current';info=current.lstat();need(stat.S_ISLNK(info.st_mode)and info.st_uid==0,'generation_retention_current');active=os.readlink(current)
        need(re.fullmatch('generation-[a-f0-9]{32}',active)is not None,'generation_retention_current_target');removed=0
        rows=self.state.value['generations'];need(active in rows and not rows[active]['deleting'],'generation_current_not_registered')
        current_path=self.root/active;directory(current_path,self.group);current_info=current_path.lstat();current_saved=rows[active]
        need((current_info.st_dev,current_info.st_ino)==(current_saved['device'],current_saved['inode']),'generation_current_directory_replaced')
        raw,meta=read(current_path/'generation.json',mode=0o640,group=self.group);need(meta['sha256']==current_saved['manifest_sha256'],'generation_current_manifest_changed');current_manifest=json.loads(raw)
        need(type(current_manifest)is dict and current_manifest.get('version')==1 and type(current_manifest.get('files'))is dict and len(current_manifest['files'])<=20000,'generation_current_manifest_schema')
        need({entry.name for entry in current_path.iterdir()}==set(current_manifest['files'])|{'generation.json'},'generation_current_inventory_changed')
        for leaf,pin in current_manifest['files'].items():
            need(type(leaf)is str and '/'not in leaf and '\\'not in leaf and leaf not in ('.','..'),'generation_current_leaf')
            _,meta=read(current_path/leaf,mode=0o640,group=self.group);need(meta['sha256']==pin,'generation_current_artifact_changed')
        need(os.readlink(current)==active,'generation_current_changed_during_validation')
        # A 300 second minimum exceeds the 120 second Sieve expiry. Retain two
        # newest registered generations even when the publisher has been idle.
        newest=set(sorted(rows,key=lambda key:(rows[key]['created_at'],key),reverse=True)[:2])
        for name in sorted(rows):
            saved=rows[name]
            if name==active or name in newest or now-saved['created_at']<300:continue
            path=self.root/name;value=json.loads(json.dumps(self.state.value))
            if not os.path.lexists(path):
                need(saved['deleting'],'generation_unexpected_missing');del value['generations'][name];self.state.save(value);continue
            directory(path,self.group);info=path.lstat();need((info.st_dev,info.st_ino)==(saved['device'],saved['inode']),'generation_directory_replaced')
            leaves={entry.name for entry in path.iterdir()}
            if 'generation.json'in leaves:
                raw,meta=read(path/'generation.json',mode=0o640,group=self.group);need(meta['sha256']==saved['manifest_sha256'],'generation_manifest_changed');manifest=json.loads(raw)
                need(type(manifest)is dict and set(manifest)=={'version','created_at','files'}and manifest['version']==1 and manifest['created_at']==saved['created_at']and type(manifest['files'])is dict and len(manifest['files'])<=20000,'generation_manifest_schema')
                expected=set(manifest['files'])|{'generation.json'};need(leaves<=expected and(saved['deleting']or leaves==expected),'generation_unknown_or_missing_file')
                for leaf in leaves-{'generation.json'}:
                    need(type(leaf)is str and '/'not in leaf and '\\'not in leaf and leaf not in ('.','..'),'generation_leaf_name')
                    raw,meta=read(path/leaf,mode=0o640,group=self.group);need(meta['sha256']==manifest['files'][leaf],'generation_artifact_changed')
            else:need(saved['deleting']and not leaves,'generation_manifest_missing')
            if not saved['deleting']:
                value['generations'][name]['deleting']=True;self.state.save(value)
            # Parent and current link are root-owned. Recheck immediately before
            # each known leaf unlink; a manual replacement is a stop condition.
            descriptor=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                for leaf in sorted(leaves-{'generation.json'})+(['generation.json']if 'generation.json'in leaves else[]):
                    need(os.readlink(current)==active and name!=active,'generation_became_current')
                    info=os.stat(path,follow_symlinks=False);need((info.st_dev,info.st_ino)==(saved['device'],saved['inode']),'generation_changed_before_unlink')
                    raw,meta=read(path/leaf,mode=0o640,group=self.group);expected_pin=saved['manifest_sha256']if leaf=='generation.json'else manifest['files'][leaf];need(meta['sha256']==expected_pin,'generation_changed_before_unlink')
                    os.unlink(leaf,dir_fd=descriptor)
                os.fsync(descriptor);need(not list(path.iterdir())and os.readlink(current)==active,'generation_not_empty_or_current_changed');os.rmdir(path);sync_dir(self.root)
            finally:os.close(descriptor)
            value=json.loads(json.dumps(self.state.value));del value['generations'][name];self.state.save(value);removed+=1
        return {'removed_registered_generations':removed,'minimum_age_seconds':300,'unknown_paths_deleted':False}
