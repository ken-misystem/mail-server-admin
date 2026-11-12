"""Fixed low-priority initialization exec. Called as a new process; never preexec_fn in a thread."""
import os
import re
import sys


def main():
    args=sys.argv[1:]
    # Only the parent, running a pinned module, supplies these fixed native argument vectors.
    if not args or args[0]!='/usr/bin/doveadm' or len(args)>12:raise ValueError('cold_exec_scope')
    if any('\n'in x or '\x00'in x for x in args):raise ValueError('cold_exec_scope')
    command=args[1:]
    if command[:1]==['-c']:
        if len(command)<3 or not command[1].startswith('/')or not command[1].endswith('.conf'):raise ValueError('cold_exec_scope')
        command=command[2:]
    kick=len(command)==2 and command[0]=='kick'and re.fullmatch(r'[A-Za-z0-9._+\-]+@[A-Za-z0-9.\-]+',command[1])and not command[1].startswith('-')
    quota=len(command)==6 and command[:5]==['-f','tab','quota','get','-F']and command[5].startswith('/')and command[5].endswith('/private/bootstrap-users.txt')
    if not(kick or quota):raise ValueError('cold_exec_scope')
    os.nice(4)
    os.execve(args[0],args,{'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','PYTHONDONTWRITEBYTECODE':'1'})


if __name__=='__main__':main()
