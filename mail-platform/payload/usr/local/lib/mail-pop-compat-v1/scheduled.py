#!/usr/bin/python3
"""Pinned singleton unit entry. No retries or secret output."""
import hashlib,json,os,stat,subprocess,sys
from pathlib import Path
PINS={'run-once.py': (39435, 'd46d7644887667fc87a9d812b638984b5819d0797981f0bf8548a9b87119e455'), 'bridge.php': (8228, '6576a02af1506a04d97f1cfe78d29f92e7d3cac9ddf0587df1b0e1f8ba974b95'), 'fetchmail_history.py': (2750, 'd624d6d53122a77d37cbccaf2c5c774384c0e3d6bd6233838c199684d7363a5c'), 'PopSourcePolicy.php': (3291, 'f99248331cd57a100a46d8515f05e0c777e4d35933340d1e59bf43817e303346'), 'PopSealedBox.php': (1293, 'e46b42e9e84d9cce7927ef5bb7c14bcd743c34c5bff4befb7bac88e2bb3ceba4'), 'FetchmailConfig.php': (2121, 'cf36050b9dca1ffdde1e360856cd8d146279dfaea56eec5cee7f929c99909fff'), 'PopRunHistory.php': (3380, 'bd25895ac369eb2ca4e5658e5804e7f71d0e0f949a1c744c4a5262079d38bc10')}
BASE=Path('/usr/local/lib/mail-pop-worker-v1')
def main():
    try:
        if len(sys.argv)!=1:raise ValueError()
        for name,expected in PINS.items():
            path=BASE/name
            with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as f:
                m=os.fstat(f.fileno());data=f.read(65537)
                if not stat.S_ISREG(m.st_mode) or m.st_uid!=0 or stat.S_IMODE(m.st_mode)!=0o640 or m.st_nlink!=1 or (len(data),hashlib.sha256(data).hexdigest())!=tuple(expected):raise ValueError()
        # stdout is already finite worker JSON; credentials remain in its private pipes.
        result=subprocess.run(['/usr/bin/python3','-I','-B',str(BASE/'run-once.py'),'--account1'],
            stdin=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=1020,cwd='/',
            env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'})
        return result.returncode if result.returncode in (0,1) else 1
    except Exception:
        print('{"status":"fail","stage":"scheduler_entry","raw_error_output":false}')
        return 1
if __name__=='__main__':sys.exit(main())
