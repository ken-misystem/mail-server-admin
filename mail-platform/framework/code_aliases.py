"""Explicit, immutable legacy plugin links; writes use canonical real paths only."""
import os
from pathlib import Path
import stat
import shutil

KNOWN = {
    '/usr/share/roundcube/plugins/app_passwords': '/usr/share/roundcube/plugins/.app-passwords-general-v1',
    '/usr/share/roundcube/plugins/junk_digest': '/usr/share/roundcube/plugins/.junk-digest-general-v1',
}

def validate(value):
    if type(value) is not dict or set(value)-set(KNOWN):
        raise ValueError('code_alias_inventory')
    for name, item in value.items():
        if (type(item) is not dict or set(item)!={'target','uid','gid','device','inode'}
                or item['target']!=KNOWN[name] or item['uid']!=0 or item['gid']!=0
                or any(type(item[k]) is not int or item[k]<0 for k in ('uid','gid','device','inode'))):
            raise ValueError('code_alias_contract')
    return value

def directory(root, name):
    root=Path(root)
    for part in [root, *reversed((root/name.lstrip('/')).parents)]:
        if part!=root and root not in part.parents:continue
        info=part.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022:
            raise ValueError('code_alias_parent_trust')
    path=root/name.lstrip('/');info=path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022:
        raise ValueError('code_alias_target_trust')
    return path

def capture(root, names):
    result={}
    for name in names:
        if name not in KNOWN:raise ValueError('code_alias_inventory')
        path=Path(root)/name.lstrip('/');directory(root,str(Path(name).parent))
        before=path.lstat()
        if not stat.S_ISLNK(before.st_mode):raise ValueError('code_alias_not_link')
        target=os.readlink(path)
        result[name]={'target':target,'uid':before.st_uid,'gid':before.st_gid,'device':before.st_dev,'inode':before.st_ino}
        after=path.lstat()
        if (after.st_dev,after.st_ino,after.st_ctime_ns)!=(before.st_dev,before.st_ino,before.st_ctime_ns):
            raise ValueError('code_alias_changed')
    check(root,result)
    return result

def check(root, value):
    validate(value)
    for name,item in value.items():
        directory(root,str(Path(name).parent));directory(root,item['target'])
        path=Path(root)/name.lstrip('/');s=path.lstat()
        if (not stat.S_ISLNK(s.st_mode) or os.readlink(path)!=item['target']
                or {k:v for k,v in zip(('uid','gid','device','inode'),(s.st_uid,s.st_gid,s.st_dev,s.st_ino))}
                !={k:item[k] for k in ('uid','gid','device','inode')}):
            raise ValueError('code_alias_changed')
    return value

def physical(name, value):
    validate(value)
    for alias,item in value.items():
        if name.startswith(alias+'/'):return item['target']+name[len(alias):]
    return name

def bind(files, value):
    """Render logical archive names to the pinned physical ownership namespace."""
    output={}
    for name,raw in files.items():
        mapped=physical('/'+name,value).lstrip('/')
        if mapped in output:raise ValueError('code_alias_payload_collision')
        output[mapped]=raw
    return output

def assert_physical(names, value):
    for name in names:
        if physical(name,value)!=name or name in value:
            raise ValueError('code_alias_logical_write')

def tree_links(source, logical_root, aliases):
    """Inspect a generation tree without traversing links; no outside targets."""
    validate(aliases);source=Path(source);result={}
    for path in [source,*source.rglob('*')]:
        info=path.lstat();relative=path.relative_to(source).as_posix()
        name=logical_root.rstrip('/')+('/'+relative if relative!='.' else '')
        if stat.S_ISLNK(info.st_mode):
            item=aliases.get(name)
            if (not item or info.st_uid!=item['uid'] or info.st_gid!=item['gid']
                    or os.readlink(path)!=item['target']
                    or not item['target'].startswith(logical_root.rstrip('/')+'/')):
                raise ValueError('generation_unknown_code_link')
            # The same private bind must contain the real target directory.
            directory(source,'/'+item['target'][len(logical_root.rstrip('/')):].lstrip('/'))
            result[relative]={'target':item['target'],'uid':info.st_uid,'gid':info.st_gid}
        elif (info.st_uid!=0 or info.st_mode & 0o022
                or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
                or (stat.S_ISREG(info.st_mode) and info.st_nlink!=1)):
            raise ValueError('generation_source_attributes:'+name)
    return result

def snapshot_tree(source, destination, logical_root, aliases):
    expected=tree_links(source,logical_root,aliases)
    shutil.copytree(source,destination,copy_function=shutil.copy2,symlinks=True)
    for original in [Path(source),*Path(source).rglob('*')]:
        target=Path(destination)/original.relative_to(source);info=original.lstat()
        os.chown(target,info.st_uid,info.st_gid,follow_symlinks=False)
    if tree_links(source,logical_root,aliases)!=expected or tree_links(destination,logical_root,aliases)!=expected:
        raise ValueError('generation_snapshot_links_changed')
    return expected
