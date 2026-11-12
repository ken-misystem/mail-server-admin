"""Verify complete installed public-code manifest before a single source run."""
import hashlib,json,os,stat,sys
from pathlib import Path
BASE=Path('/usr/local/lib/mail-pop-general-v1')
NAMES={'run-once.py','bridge.php','PopRunHistory.php','PopSourcePolicy.php','PopSealedBox.php','FetchmailConfig.php','fetchmail_history.py'}


def protected(name):
    with os.fdopen(os.open(BASE/name,os.O_RDONLY|os.O_NOFOLLOW),'rb') as f:
        m=os.fstat(f.fileno());raw=f.read(131073)
        if not stat.S_ISREG(m.st_mode) or m.st_uid!=0 or m.st_mode&0o022 or m.st_nlink!=1 or len(raw)>131072:raise ValueError('code_boundary')
    return raw


def main():
    try:
        import pwd
        user=pwd.getpwnam('mailpop')
        if os.geteuid()!=user.pw_uid or os.getuid()!=user.pw_uid or not sys.flags.isolated:raise ValueError('worker_identity')
        for path in reversed(BASE.parents):
            m=path.lstat()
            if not stat.S_ISDIR(m.st_mode) or m.st_uid!=0 or m.st_mode&0o022:raise ValueError('code_parent')
        m=BASE.lstat()
        if not stat.S_ISDIR(m.st_mode) or m.st_uid!=0 or m.st_mode&0o022:raise ValueError('code_parent')
        manifest=json.loads(protected('manifest.json'))
        if set(manifest)!=NAMES:raise ValueError('manifest_shape')
        raw={name:protected(name) for name in NAMES}
        for name,value in raw.items():
            if [len(value),hashlib.sha256(value).hexdigest()]!=manifest[name]:raise ValueError('code_pin')
        scope={'__name__':'general_worker_library','__file__':str(BASE/'run-once.py')}
        exec(compile(raw['run-once.py'],scope['__file__'],'exec'),scope);return scope['main']()
    except Exception as e:
        print(json.dumps({'status':'fail','stage':'scheduler_entry','error_class':type(e).__name__,
            'raw_error_output':False,'retrieval_attempted':False}));return 1


if __name__=='__main__':sys.exit(main())
