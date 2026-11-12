"""Private-validation support. Raw streams never cross the SSH result boundary."""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
import traceback

WORK = Path('/root/mail-domain-routing-private-v1')
RUN = Path('/run/mail-domain-routing-private-v1')
ACTIVE = Path('/opt/mail-management/candidates/admin-audit-v1')
UNIT = 'mail-domain-routing-private-v1.service'
PHP = ['/usr/bin/php', '-d', 'display_errors=0', '-d', 'log_errors=0',
       '-d', 'zend.exception_ignore_args=1', '-d', 'auto_prepend_file=',
       '-d', 'auto_append_file=', '-d', 'opcache.enable_cli=0']


class CheckFailure(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise CheckFailure(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def write(path, raw, mode=0o600):
    need(path.is_relative_to(WORK) or path.is_relative_to(RUN), 'write_boundary')
    # All ancestors below the two newly created roots belong to this invocation.
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, mode)


def evidence(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    write(path, raw)
    need(json.loads(path.read_bytes()) == value, 'evidence_readback')
    return sha(raw)


def safe_failure(exc, phase):
    # Only our fixed CheckFailure labels may be exported. All other messages stay private.
    reason = str(exc) if type(exc) is CheckFailure else 'private_validation_exception'
    if re.fullmatch('[A-Za-z0-9_]{1,100}', reason) is None:
        reason = 'unclassified_private_failure'
    return {'phase': phase, 'class': type(exc).__name__, 'reason': reason,
            'errno': getattr(exc, 'errno', None),
            'frames': [{'source': Path(f.filename).name, 'function': f.name, 'line': f.lineno}
                       for f in traceback.extract_tb(exc.__traceback__)[-6:]],
            'raw_error_output': False}

def finite_native_reasons(raw):
    """Public error classes/known setting names only; never arbitrary native text."""
    text=raw.decode('utf-8','replace').lower();codes=[]
    for needles,code in ((('permission denied','operation not permitted'),'permission'),
        (('unknown setting','unknown variable'),'configuration_setting_unknown'),
        (('unknown capability','unknown sieve extension','unsupported extension'),'sieve_extension_unknown'),
        (('syntax error','parse error','unexpected token'),'syntax'),(('no such file','not found'),'missing'),
        (('failed to connect','connection refused'),'endpoint_unavailable')):
        if any(value in text for value in needles):codes.append(code)
    keys=('dovecot_config_version','dovecot_storage_version','mail_driver','mail_path','mail_uid','mail_gid','sieve_extensions','sieve_script','precedence','path','type','copy','date','relational','fileinto','mailbox')
    names=[key for key in keys if re.search(r'(?<![a-z0-9_])'+re.escape(key)+r'(?![a-z0-9_])',text)]
    return {'codes':codes or(['unclassified']if raw else[]),'known_public_names':names,'raw_reason_exported':False}


def protected(path, bound=2097152):
    """Anchored root-owned non-link read, including end name/descriptor binding."""
    path = Path(path)
    fds = [os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    try:
        for part in path.parts[1:-1]:
            fds.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1]))
            st = os.fstat(fds[-1])
            need(st.st_uid == 0 and not st.st_mode & 0o022, 'protected_parent')
        fds.append(os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fds[-1]))
        st = os.fstat(fds[-1])
        need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1
             and not st.st_mode & 0o022 and 0 <= st.st_size <= bound, 'protected_file')
        raw = os.pread(fds[-1], st.st_size + 1, 0)
        key = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode,
                         s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) == st.st_size and key(st) == key(os.fstat(fds[-1]))
             == key(os.stat(path.name, dir_fd=fds[-2], follow_symlinks=False)), 'protected_drift')
        return raw, {'sha256': sha(raw), 'bytes': len(raw), 'uid': st.st_uid,
                     'gid': st.st_gid, 'mode': stat.S_IMODE(st.st_mode)}
    finally:
        for fd in reversed(fds):
            os.close(fd)


def command(result, label, argv, body=b'', seconds=30, limit=1048576,
            required=True, stderr_allowed=False, **options):
    """Bound running output, retain output/exit BEFORE applying success assertions."""
    need(re.fullmatch('[a-z0-9_]{1,80}', label) is not None, 'native_label')
    index = len(result['native'])
    row = {'label': label, 'exit': None, 'timeout': False, 'overflow': False}
    result['native'].append(row)
    buffers = [bytearray(), bytearray()]
    process = None
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True,
                                   env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}, **options)
        # Inputs are fixed small JSON or SQL, never larger than the pipe capacity bound.
        need(len(body) <= 32768, 'native_input_bound')
        process.stdin.write(body)
        process.stdin.close()
        with selectors.DefaultSelector() as sel:
            for i, stream in enumerate((process.stdout, process.stderr)):
                sel.register(stream, selectors.EVENT_READ, i)
            deadline = time.monotonic() + seconds
            while sel.get_map():
                if time.monotonic() > deadline:
                    row['timeout'] = True
                    break
                for event, _ in sel.select(.05):
                    chunk = os.read(event.fileobj.fileno(), 8192)
                    if not chunk:
                        sel.unregister(event.fileobj)
                    else:
                        remaining = limit - sum(map(len, buffers))
                        buffers[event.data].extend(chunk[:max(0, remaining)])
                        if len(chunk) > remaining:
                            row['overflow'] = True
                            break
                if row['overflow']:
                    break
            if row['timeout'] or row['overflow']:
                os.killpg(process.pid, signal.SIGKILL)
            row['exit'] = process.wait(timeout=3)
    except BaseException as exc:
        row['capture_failure'] = safe_failure(exc, 'native_capture')
        raise
    finally:
        if process is not None:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                row['exit'] = process.wait(timeout=3)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
        for name, raw in zip(('stdout', 'stderr'), buffers):
            write(WORK / 'native' / f'{index:03d}-{label}.{name}', bytes(raw))
            row[name + '_bytes'] = len(raw)
            row[name + '_sha256'] = sha(raw)
        # Raw parser/API error details remain in these root-only files.
        evidence(WORK / 'native' / f'{index:03d}-{label}.json', row)
    if required:
        need(row['exit'] == 0 and not row['timeout'] and not row['overflow']
             and (stderr_allowed or not buffers[1]), 'native_failed_' + label)
    return bytes(buffers[0]), bytes(buffers[1]), row
