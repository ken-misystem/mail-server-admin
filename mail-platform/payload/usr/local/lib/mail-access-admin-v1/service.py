"""Socket-activated root broker. Only mailadmin peer UID may use the JSON API."""
import json
import os
import pwd
import socket
import stat
import struct
import time

from broker import Broker, JAILS, require
from audit import Audit


class Fail2Ban:
    deadline = 0

    def __call__(self, args):
        require(time.monotonic() < self.deadline, 'request_deadline')
        read = args == ['status'] or (len(args) == 2 and args[0] == 'status' and args[1] in JAILS)
        read = read or (len(args) in (3, 4) and args[:1] == ['get'] and args[1] in JAILS
                        and (args[2:] in [['findtime'], ['maxretry'], ['bantime'], ['banip', '--with-time']]))
        release = len(args) == 4 and args[0] == 'set' and args[1] in JAILS and args[2] == 'unbanip'
        require(read or release, 'command_not_allowed')
        if release:
            from broker import address
            address(args[3])
        # The native protocol contains pickle. Only the existing root-owned socket
        # in root-owned directories is trusted; the web frontend never sees it.
        for path in ('/run', '/run/fail2ban'):
            info = os.lstat(path)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'fail2ban_parent_unsafe')
        info = os.lstat('/run/fail2ban/fail2ban.sock')
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'fail2ban_socket_unsafe')
        from fail2ban.client.csocket import CSocket
        client = CSocket('/run/fail2ban/fail2ban.sock', timeout=2)
        try:
            code, reply = client.send(args)
            require(code == 0, 'fail2ban_failed')
            return reply
        finally:
            client.close()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'duplicate_key')
        value[key] = item
    return value


def main(audit_path='/var/lib/mail-access-admin-v1/releases.jsonl', adapter=None):
    require(os.geteuid() == 0 and os.environ.get('LISTEN_PID') == str(os.getpid())
            and os.environ.get('LISTEN_FDS') == '1', 'socket_activation_required')
    reader = pwd.getpwnam('mailadmin').pw_uid
    require(reader != 0, 'reader_uid')
    listener = socket.socket(fileno=3)
    require(listener.family == socket.AF_UNIX, 'unix_listener_required')
    audit = Audit(audit_path)
    if adapter is None:
        adapter = Fail2Ban()
    broker = Broker(adapter, audit)
    while True:
        connection, _ = listener.accept()
        try:
            connection.settimeout(3)
            _, uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(uid == reader, 'peer_rejected')
            data = bytearray()
            read_deadline = time.monotonic() + 3
            while b'\n' not in data:
                require(time.monotonic() < read_deadline, 'request_timeout')
                connection.settimeout(max(0.01, read_deadline - time.monotonic()))
                part = connection.recv(4097 - len(data))
                require(part and len(data) + len(part) <= 4096, 'request_bound')
                data.extend(part)
            require(data.endswith(b'\n') and data.count(b'\n') == 1, 'request_framing')
            request = json.loads(data, object_pairs_hook=unique)
            adapter.deadline = time.monotonic() + 8
            response = {'status': 'ok', 'data': broker.handle(request)}
        except Exception as error:
            import re
            reason = str(error) if type(error) is ValueError and re.fullmatch('[a-z_]{1,60}', str(error)) else 'operation_unavailable'
            response = {'status': 'fail', 'reason': reason}
        try:
            connection.sendall((json.dumps(response, separators=(',', ':')) + '\n').encode())
        except OSError:
            pass
        finally:
            connection.close()


if __name__ == '__main__':
    main()
