"""Root one-shot directory setup for the new private smtpd only. No mail access."""
import grp
import os
from pathlib import Path
import pwd
import stat
import sys

def main():
    if os.geteuid()!=0 or sys.argv[1:]:raise RuntimeError('fixed_private_runtime_init')
    root=Path('/run/mail-client-certificates-v1/postfix');s=root.lstat();actor=pwd.getpwnam('postfix')
    if not stat.S_ISDIR(s.st_mode)or s.st_uid!=actor.pw_uid or s.st_mode&0o022:raise RuntimeError('postfix_runtime_parent')
    for name in ('data',):
        path=root/name
        try:path.mkdir(mode=0o700)
        except FileExistsError:
            s=path.lstat()
            if not stat.S_ISDIR(s.st_mode)or s.st_uid!=actor.pw_uid or s.st_mode&0o077:raise RuntimeError('postfix_runtime_existing_directory')
        else:os.chown(path,actor.pw_uid,actor.pw_gid);os.chmod(path,0o700)
    return 0
if __name__=='__main__':raise SystemExit(main())
