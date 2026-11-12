"""Bounded UNIX socketmap adapter; no network DNS, no SMTP, no message data."""
import json
import os
from pathlib import Path
import socket
import stat
import struct
import time
import threading
from routing import route_reply, dns_reply, status_reply, need


def validate_runtime(cfg):
    need(type(cfg)is dict and set(cfg)=={'version','activation_enabled','allowed_postfix_uids','collector_uid','self_addresses','local_transport'}
         and type(cfg['version'])is int and cfg['version']==1 and type(cfg['activation_enabled'])is bool,'runtime_shape')
    need(type(cfg['collector_uid'])is int and 0<cfg['collector_uid']<4294967295,'collector_uid_profile')
    peers=cfg['allowed_postfix_uids']
    need(type(peers)is list and 0<len(peers)<=8 and all(type(v)is int and 0<=v<4294967295 for v in peers)
         and len(peers)==len(set(peers)),'peer_uid_profile')
    from routing import address
    own=cfg['self_addresses']
    need(type(own)is list and 0<len(own)<=32 and all(address(v).is_global and not address(v).is_multicast for v in own),
         'public_self_identity_required')
    route_reply('invalid-key',{'domains':{}},1,cfg['local_transport'])
    return cfg


def read_snapshot(path, uid, private=False, require_routes=True):
    path = Path(path)
    fds = [os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    try:
        for part in path.parts[1:-1]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1]); fds.append(fd)
            s = os.fstat(fd)
            need(s.st_uid in (0, uid) and not s.st_mode & 0o022, 'snapshot_parent')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fds[-1]); fds.append(fd)
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == uid and not s.st_mode & 0o022
             and s.st_nlink == 1 and 0 < s.st_size <= 1048576, 'snapshot_file')
        need(not private or not s.st_mode & 0o007, 'private_reader_profile')
        raw = os.pread(fd, s.st_size + 1, 0)
        end = os.fstat(fd)
        key = lambda v: (v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
        need(len(raw) == s.st_size and key(s) == key(end)
             == key(os.stat(path.name,dir_fd=fds[-2],follow_symlinks=False)), 'snapshot_drift')
        value = json.loads(raw)
        need(type(value) is dict, 'snapshot_shape')
        if require_routes:
            need(value.get('version') == 1 and type(value.get('domains')) is dict
                 and len(value['domains']) <= 200, 'snapshot_shape')
        return value
    finally:
        for fd in reversed(fds):
            os.close(fd)


def receive(stream):
    count = b''
    while True:
        piece = stream.read(1)
        if not piece and not count:
            return None
        need(bool(piece), 'netstring_eof')
        if piece == b':':
            break
        need(piece.isdigit() and len(count) < 5, 'netstring_length')
        count += piece
    need(bool(count) and (len(count) == 1 or count[:1] != b'0'), 'netstring_length')
    n = int(count); need(0 < n <= 4096, 'netstring_bound')
    data = stream.read(n)
    need(len(data) == n and stream.read(1) == b',', 'netstring_framing')
    return data.decode('utf-8', 'strict')


def frame(value):
    raw = value.encode('ascii')
    need(0 < len(raw) <= 4096, 'reply_bound')
    return str(len(raw)).encode() + b':' + raw + b','


def lookup(query, load, now, local_transport, self_addresses):
    try:
        name, key = query.split(' ', 1)
        if name == 'route':
            snapshot=load()
            # Default paths must remain unknown to this map. Managed domains fail closed.
            from routing import request_domain
            try:managed=request_domain(key)in snapshot.get('domains',{})
            except ValueError:managed=False
            if managed and (snapshot.get('activation_enabled') is not True
                            or snapshot.get('lookup_healthy') is not True):
                return 'TEMP route_activation_or_health_pending'
            return route_reply(key, snapshot, now, local_transport)
        if name == 'dns':
            return dns_reply(key, self_addresses)
        if name == 'status':
            return status_reply(key)
        return 'TEMP unknown_map'
    except Exception:
        # Never expose a key, recipient, file path, exception string or raw snapshot.
        return 'TEMP route_lookup_failed'


class SnapshotCache:
    """At most one protected disk/JSON read per second; decision TTL checked per lookup."""
    def __init__(self,path,uid):
        self.path=path; self.uid=uid; self.until=0; self.value=None; self.lock=threading.Lock()

    def load(self):
        with self.lock:
            now=time.monotonic()
            if now>=self.until:
                self.value=None
                self.until=now+1
                self.value=read_snapshot(self.path,self.uid)
            need(self.value is not None,'snapshot_unavailable')
            return self.value


def serve(listener, allowed_uids, load, local_transport, self_addresses):
    need(hasattr(socket, 'SO_PEERCRED') and os.name == 'posix', 'linux_peer_required')
    slots = threading.BoundedSemaphore(8)
    def handle(conn):
      try:
        with conn:
            conn.settimeout(2)
            _, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid not in allowed_uids:
                return
            with conn.makefile('rwb') as stream:
                try:
                    for _ in range(64):
                        query = receive(stream)
                        if query is None:
                            break
                        stream.write(frame(lookup(query, load, int(time.time()), local_transport, self_addresses)))
                        stream.flush()
                except Exception:
                    # No request or raw error logging. Supervisor sees service faults separately.
                    pass
      except Exception as exc:
        print(json.dumps({'component':'domain_route_map','failure':{'class':type(exc).__name__,
                          'errno':getattr(exc,'errno',None),'reason':'connection_failed'}}),flush=True)
      finally:
        slots.release()
    while True:
        conn, _ = listener.accept()
        if not slots.acquire(blocking=False):
            conn.close(); continue
        threading.Thread(target=handle,args=(conn,),daemon=True).start()


def main():
    # Root-owned bootstrap supplies only non-secret endpoint/UID metadata, no CLI flexibility.
    cfg = validate_runtime(read_snapshot(Path('/etc/mail-domain-routing-v1/runtime.json'), 0,require_routes=False))
    need(int(os.environ.get('LISTEN_PID', '0')) == os.getpid()
         and os.environ.get('LISTEN_FDS') == '1', 'socket_activation_required')
    listener = socket.socket(fileno=3)
    need(listener.family == socket.AF_UNIX and listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN), 'unix_listener_required')
    cache=SnapshotCache(Path('/var/lib/mail-domain-routing-v1/snapshot.json'),cfg['collector_uid'])
    serve(listener, set(cfg['allowed_postfix_uids']), cache.load,
          cfg['local_transport'], cfg['self_addresses'])


if __name__ == '__main__':
    main()
