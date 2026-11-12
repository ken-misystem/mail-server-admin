"""Only gate new auth service readiness on its exact socket ownership/mode."""
import os
import stat
import time

path='/var/spool/postfix/private/mail-legacy-smtp-v1/auth'
deadline=time.monotonic()+20
while True:
    try:
        s=os.lstat(path)
        if stat.S_ISSOCK(s.st_mode) and s.st_uid==103 and s.st_gid==105 and stat.S_IMODE(s.st_mode)==0o660:break
    except FileNotFoundError:pass
    if time.monotonic()>=deadline:raise SystemExit('new_auth_socket_not_ready')
    time.sleep(.1)
