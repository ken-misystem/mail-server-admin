"""Run the installed SQL-backed policy and FULL ledger behind its stable frontend."""
from pathlib import Path
import json
import os
import re
import socket
import sys

BASE = Path('/usr/local/lib/mail-send-limits-v1')


def listener(config):
    target = Path(config['socket'])
    if target.parent.is_symlink() or not target.parent.is_dir() or os.path.lexists(target):
        raise ValueError('policy_generation_socket_collision')
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        channel.bind(str(target))
        # The service verifies the exact frontend UID for every connection.
        # The unprivileged worker cannot chown the socket to its Postfix caller.
        os.chmod(target, 0o666)
        channel.listen(64)
        channel.settimeout(0.2)
        return channel
    except BaseException:
        channel.close()
        raise


def main():
    if len(sys.argv) != 2 or not re.fullmatch('g[a-zA-Z0-9]{1,40}', sys.argv[1]):
        raise ValueError('policy_generation_name')
    for path in (BASE, BASE/'runtime.py'):
        metadata = path.stat()
        if path.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError('policy_generation_code_trust')
    sys.path[:0] = [str(BASE), str(BASE/'pymysql-1.2.3-py3-none-any.whl')]
    import pymysql
    import runtime
    config = json.loads(Path('/etc/mail-send-limits-v1/runtime.json').read_bytes())
    config['socket'] = '/run/mail-platform-policy/'+sys.argv[1]+'/backend.sock'
    print(json.dumps({'generation':sys.argv[1], 'PID':os.getpid(),
                      'build':getattr(runtime, 'GENERATION_BUILD', 'initial')}), flush=True)
    runtime.run(config, pymysql, generation_front=True, listener_factory=listener)


if __name__ == '__main__':
    main()
