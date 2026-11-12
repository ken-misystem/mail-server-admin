"""One bounded collection, atomic metadata only. No SMTP/mail/UIDL access."""
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import time
import hashlib
from routing import decide, domain, need
from socketmap import read_snapshot, validate_runtime


class ChildFailure(ValueError):
    def __init__(self, reason, detail):
        super().__init__(reason)
        self.detail = detail


def child(argv, body=b'', seconds=10, limit=131072):
    """Bound real process output and time; never let resolver/config text reach logs."""
    p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         start_new_session=True, env={**os.environ, 'LC_ALL':'C'})
    try:
        p.stdin.write(body); p.stdin.close()
        streams = selectors.DefaultSelector(); buffers = [bytearray(), bytearray()]
        for i, stream in enumerate((p.stdout, p.stderr)):
            streams.register(stream, selectors.EVENT_READ, i)
        start = time.monotonic()
        try:
            while streams.get_map():
                need(time.monotonic() - start < seconds, 'child_timeout')
                for key, _ in streams.select(.05):
                    data = os.read(key.fileobj.fileno(), 8192)
                    if not data:
                        streams.unregister(key.fileobj); continue
                    buffers[key.data].extend(data)
                    need(sum(map(len, buffers)) <= limit, 'child_output_bound')
            code = p.wait(timeout=1)
            detail = {'exit':code,'stdout_bytes':len(buffers[0]),'stderr_bytes':len(buffers[1]),
                      'stdout_sha256':hashlib.sha256(buffers[0]).hexdigest(),
                      'stderr_sha256':hashlib.sha256(buffers[1]).hexdigest()}
            try:
                obj = json.loads(buffers[0])
            except Exception:
                raise ChildFailure('child_json',detail) from None
            if code != 0 or buffers[1] or type(obj) is not dict:
                # metadata.php exports only safe PDO class/state/native code, not messages.
                if type(obj) is dict and type(obj.get('failure')) is dict:
                    detail['safe_failure'] = {k:v for k,v in obj['failure'].items()
                        if k in ('class','sqlstate','native_code') and (type(v) is int or v is None
                        or type(v) is str and len(v)<=80 and all(c.isalnum() or c in '_\\' for c in v))}
                raise ChildFailure('child_failed',detail)
            return obj
        finally:
            streams.close()
    finally:
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL); p.wait(timeout=2)
        p.stdout.close(); p.stderr.close()


def collect(rows, previous, self_addresses, query, now, budget_deadline):
    need(type(rows) is list and len(rows) <= 200, 'domain_bound')
    out = {}
    for row in rows:
        need(type(row) is dict and str(row.get('follow_mx')) in ('0', '1'), 'policy_shape')
        name = domain(row.get('name'))
        need(name not in out and re_decimal(str(row.get('revision'))), 'policy_shape')
        revision = str(row['revision']); follow = str(row['follow_mx']) == '1'
        old = previous.get('domains', {}).get(name, {})
        if old.get('revision') == revision and old.get('follow_mx') is follow and old.get('state') in ('internal','external') \
                and type(old.get('expires_at')) is int and type(old.get('checked_at')) is int \
                and old['checked_at'] <= now < old['expires_at'] and old.get('self_addresses') == list(self_addresses):
            out[name] = old; continue
        data = {'failure':'dns_timeout'}
        failure_detail = None
        if follow and time.monotonic() < budget_deadline:
            try:
                data = query(name)
            except Exception as exc:
                data = {'failure':'dns_timeout' if str(exc)=='child_timeout' else 'dns_failure'}
                failure_detail = {'class':type(exc).__name__,'errno':getattr(exc,'errno',None),
                                  'native':getattr(exc,'detail',None)}
        decision = decide(follow, data, self_addresses, now)
        out[name] = dict(decision.json(), revision=revision, follow_mx=follow,
                         self_addresses=list(self_addresses))
        if failure_detail is not None:
            out[name]['failure_detail'] = failure_detail
    return {'version':1,'generated_at':now,'domains':out}


def re_decimal(value):
    return value.isascii() and value.isdecimal() and (value == '0' or not value.startswith('0')) \
        and len(value) <= 20 and int(value) <= 18446744073709551615


def lookup_health():
    p=subprocess.run(['/usr/bin/systemctl','show','mail-domain-routing.socket','mail-domain-routing.service',
                      '--property=Id,ActiveState'],capture_output=True,timeout=3)
    need(p.returncode==0 and not p.stderr and len(p.stdout)<=4096,'lookup_health_read')
    rows=[dict(line.split('=',1)for line in block.splitlines())for block in p.stdout.decode().strip().split('\n\n')]
    need(len(rows)==2 and {r.get('Id')for r in rows}=={'mail-domain-routing.socket','mail-domain-routing.service'},'lookup_health_shape')
    return all(row.get('ActiveState')=='active'for row in rows)


def publish(path, obj):
    parent = path.parent
    s = parent.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == os.geteuid() and not s.st_mode & 0o022, 'publication_parent')
    temp = parent / ('snapshot-' + str(os.getpid()) + '.tmp')
    raw = (json.dumps(obj, sort_keys=True, separators=(',',':'))+'\n').encode()
    need(len(raw) <= 1048576, 'snapshot_bound')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    try:
        with os.fdopen(fd,'wb',closefd=False) as f:
            f.write(raw); f.flush(); os.fsync(f.fileno())
        os.fchmod(fd,0o644)
    finally:
        os.close(fd)
    os.replace(temp,path)
    fd = os.open(parent,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    import fcntl
    here = Path(__file__).resolve().parent
    cfg = validate_runtime(read_snapshot(Path('/etc/mail-domain-routing-v1/runtime.json'),0,require_routes=False))
    path = Path('/var/lib/mail-domain-routing-v1/snapshot.json')
    lock = os.open(path.parent/'collect.lock',os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
        previous = {}
        try:
            previous = read_snapshot(path,os.geteuid())
        except Exception:
            pass  # Invalid old data is not used as a route. Fresh collection still has strict guards.
        reader = read_snapshot(Path('/etc/mail-domain-routing-v1/reader.json'),0,private=True,require_routes=False)
        reader_input=json.dumps(reader).encode();need(len(reader_input)<=8192,'reader_config_bound')
        meta = child(['/usr/bin/php',str(here/'metadata.php')],reader_input,seconds=5)
        need(meta.get('status') == 'ok','metadata_read_failed')
        now = int(time.time())
        snapshot = collect(meta['rows'],previous,cfg['self_addresses'],
            lambda name: child(['/usr/bin/php','-n',str(here/'dns_probe.php')],
                               json.dumps({'domain':name}).encode(),seconds=5),now,time.monotonic()+40)
        snapshot['activation_enabled']=cfg.get('activation_enabled')is True
        try:snapshot['lookup_healthy']=lookup_health()
        except Exception as exc:
            snapshot['lookup_healthy']=False
            snapshot['health_failure']={'class':type(exc).__name__,'errno':getattr(exc,'errno',None),
                                        'reason':'lookup_health_read_failed'}
        publish(path,snapshot)
        print(json.dumps({'status':'ok','domains':len(snapshot['domains']),
                          'deferred':sum(r['state']=='defer' for r in snapshot['domains'].values())}))
    except Exception as exc:
        # Preserve useful class/fixed cause/errno; never arbitrary error text/config/records.
        reason = str(exc) if type(exc) is ValueError and str(exc).replace('_','').isalpha() else 'collector_failed'
        print(json.dumps({'status':'fail','failure':{'class':type(exc).__name__,'reason':reason,
                                                  'errno':getattr(exc,'errno',None),
                                                  'native':getattr(exc,'detail',None)}}))
        return 1
    finally:
        os.close(lock)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
