"""Account1 migration coordination. No retrieval or state changes on import."""
import atexit
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import stat
import time

STATE = Path('/var/lib/mail-pop/accounts/1')
LOCK = Path('/var/lib/mail-pop/locks/account-1.lock')
BARRIER = Path('/etc/mail-pop/migration-state.json')
MAILDIR = Path('/var/vmail/mi-sys.jp/ken/Maildir')
FIRST = Path('/root/mail-pop-first-fetch-v1')
LIMIT = 128*1024*1024
FIELDS = (b'message-id', b'date', b'from', b'to', b'cc', b'subject', b'mime-version',
          b'content-type', b'content-transfer-encoding', b'content-disposition')


def need(value):
    if not value:
        raise ValueError('migration_compat_unverified')


def signature(m):
    return (m.st_dev, m.st_ino, m.st_size, m.st_mtime_ns, m.st_ctime_ns)


def protected(path, uid, gid, mode, maximum):
    import pwd
    popuid = pwd.getpwnam('mailpop').pw_uid
    for p in reversed(path.parents):
        m = p.lstat()
        expected = popuid if p in (STATE, STATE.parent, STATE.parent.parent) else 0
        need(stat.S_ISDIR(m.st_mode) and m.st_uid == expected
             and not m.st_mode & 0o022)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
        m = os.fstat(f.fileno())
        need(stat.S_ISREG(m.st_mode) and (m.st_uid, m.st_gid, stat.S_IMODE(m.st_mode), m.st_nlink)
             == (uid, gid, mode, 1) and 0 < m.st_size <= maximum)
        raw = f.read(maximum+1)
        need(len(raw) == m.st_size and signature(m) == signature(os.fstat(f.fileno()))
             == signature(path.lstat()))
    return raw


def state(gid):
    value = json.loads(protected(BARRIER, 0, gid, 0o640, 4096))
    need(set(value) == {'version', 'account_id', 'phase', 'generation'}
         and type(value['version']) is int and value['version'] == 1
         and value['account_id'] == '1' and type(value['generation']) is int
         and 0 <= value['generation'] <= 1000000000
         and value['phase'] in ('idle', 'migration_in_progress', 'reconciliation_required'))
    return value


def worker_check():
    import pwd
    u = pwd.getpwnam('mailpop')
    need(os.getuid() == os.geteuid() == u.pw_uid > 0
         and os.getgid() == os.getegid() == u.pw_gid > 0)
    # Called only AFTER the existing worker holds its exclusive account lock,
    # and AFTER its history-start but BEFORE source password/key/native use.
    need(state(u.pw_gid)['phase'] == 'idle')


def write_state(value, gid, expected):
    # Only the NEW coordination metadata file, never mail/fetchids/attempt/init.
    before = state(gid)
    need(before == expected)
    starting = before['phase'] == 'idle' and value['phase'] == 'migration_in_progress' \
        and value['generation'] == before['generation']+1
    finishing = before['phase'] == 'migration_in_progress' and value['phase'] in ('idle', 'reconciliation_required') \
        and value['generation'] == before['generation']
    need((starting or finishing) and value['account_id'] == before['account_id']
         and value['version'] == before['version'])
    target = BARRIER.with_name('.migration-state.tmp')
    with os.fdopen(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as f:
        os.fchown(f.fileno(), 0, gid); os.fchmod(f.fileno(), 0o640)
        f.write((json.dumps(value, sort_keys=True)+'\n').encode())
        f.flush(); os.fsync(f.fileno())
    os.replace(target, BARRIER)
    fd = os.open(BARRIER.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def seen(raw, binding):
    need(isinstance(binding, dict) and binding.get('account_id') == '1'
         and binding.get('host') == 'mail.mi-sys.jp' and binding.get('port') == 995
         and binding.get('username') == 'ken@mi-sys.jp')
    need(isinstance(raw, bytes) and 0 < len(raw) <= 16*1024*1024 and raw.endswith(b'\n'))
    prefix = (binding['username']+'@'+binding['queryname']+' ').encode('ascii')
    result = set()
    for line in raw.split(b'\n')[:-1]:
        need(line.startswith(prefix) and len(line) < 512)
        uidl = line[len(prefix):]
        need(1 <= len(uidl) <= 70 and all(33 <= c <= 126 for c in uidl) and uidl not in result)
        result.add(uidl)
        need(len(result) <= 200000)
    return result


def fingerprint(raw):
    """Content equivalence, NOT proof of original UIDL or external receipt.

    Only CRLF -> LF normalization. No MIME decoding, final-newline stripping,
    subject-only/Message-ID-only match or broad ignore-all-header comparison.
    """
    need(isinstance(raw, bytes) and 0 < len(raw) <= LIMIT)
    raw = raw.replace(b'\r\n', b'\n')
    header, sep, body = raw.partition(b'\n\n')
    need(sep and 0 < len(header) <= 1024*1024 and b'\r' not in header and b'\x00' not in header)
    fields = []; name = None
    for line in header.split(b'\n'):
        if line.startswith((b' ', b'\t')):
            need(name is not None)
            fields[-1] = (name, fields[-1][1]+b' '+line.strip())
        else:
            name, colon, value = line.partition(b':')
            need(colon and 1 <= len(name) <= 78 and all(33 <= c <= 126 and c != 58 for c in name))
            name = name.lower(); fields.append((name, value.strip()))
    ids = [value for name, value in fields if name == b'message-id']
    need(len(ids) == 1 and 0 < len(ids[0]) <= 1024)
    h = hashlib.sha256()
    for name in FIELDS:
        values = [v for k, v in fields if k == name]
        h.update(len(name).to_bytes(4, 'big')+name+len(values).to_bytes(4, 'big'))
        for value in values:
            h.update(len(value).to_bytes(8, 'big')+value)
    h.update(len(body).to_bytes(8, 'big')); h.update(body)
    return h.hexdigest()


class Noop:
    def prepare(self, *args):
        pass

    def augment(self, value):
        return value

    def tagged_pop_missing(self, expected, actual):
        return expected-actual

    def tagged_pop_visible(self, expected, actual):
        return expected & actual

    def complete(self, imported, ok):
        pass


class Guard(Noop):
    def __init__(self, host):
        import fcntl
        import pwd
        need(os.getuid() == os.geteuid() == 0 and host == 'mail.mi-sys.jp')
        self.user = pwd.getpwnam('mailpop'); self.vmail = pwd.getpwnam('vmail')
        need(self.user.pw_uid > 0 and self.vmail.pw_uid > 0)
        for path in (STATE.parent.parent, STATE.parent, STATE, LOCK.parent):
            m = path.lstat()
            need(stat.S_ISDIR(m.st_mode) and m.st_uid == self.user.pw_uid
                 and m.st_gid == self.user.pw_gid and stat.S_IMODE(m.st_mode) == 0o700)
        self.fd = os.open(LOCK, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        atexit.register(os.close, self.fd)
        m = os.fstat(self.fd)
        need(stat.S_ISREG(m.st_mode) and (m.st_uid, m.st_gid, stat.S_IMODE(m.st_mode), m.st_nlink)
             == (self.user.pw_uid, self.user.pw_gid, 0o600, 1))
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        need(signature(m) == signature(LOCK.lstat()))
        self.barrier = state(self.user.pw_gid); need(self.barrier['phase'] == 'idle')
        self.matches = {}; self.stamps = {}; self.prepared = False

    def native_ids(self):
        u = self.user
        read = lambda p, uid, mode, size: protected(p, uid, u.pw_gid if uid != 0 or p.parent == STATE else 0, mode, size)
        bound = protected(STATE/'binding.json', 0, u.pw_gid, 0o640, 4096)
        init = protected(STATE/'initialization.json', 0, u.pw_gid, 0o640, 65536)
        need(bound == protected(FIRST/'before-binding.json', 0, 0, 0o600, 4096)
             and init == protected(FIRST/'before-initialization.json', 0, 0, 0o600, 65536))
        b = json.loads(bound); iv = json.loads(init)
        initial = read(FIRST/'before-fetchids', 0, 0o600, 16*1024*1024)
        current = read(STATE/'fetchids', u.pw_uid, 0o600, 16*1024*1024)
        old = seen(initial, b); now = seen(current, b)
        need(iv.get('complete') is True and iv.get('source_id') == '1'
             and iv.get('seeded_uidls') == len(old) == 45322
             and iv['fetchids']['sha256'] == hashlib.sha256(initial).hexdigest()
             and iv['fetchids']['bytes'] == len(initial) and old <= now)
        attempt = json.loads(read(STATE/'attempt.json', u.pw_uid, 0o600, 4096))
        need(attempt.get('account_id') == '1' and attempt.get('phase') == 'complete'
             and type(attempt.get('native_exit')) is int and attempt['native_exit'] in (0, 1, 13)
             and attempt.get('database_result_verified') is True
             and not any(os.path.lexists(STATE/n) for n in ('fetchmail.pid', '.attempt.tmp', 'fetchids_')))
        return now-old

    def candidates(self, maildir, box, deadline):
        need(maildir == MAILDIR)
        # Parent/entry symlinks are rejected. Match only untagged regular mail.
        for p in (maildir, *maildir.parents):
            m = p.lstat()
            need(stat.S_ISDIR(m.st_mode) and m.st_uid in (0, self.vmail.pw_uid) and not m.st_mode & 0o022)
        result = {}; entries = total = 0
        def walk_error(error):
            raise ValueError('migration_compat_unverified')
        for root, dirs, files in os.walk(maildir, followlinks=False, onerror=walk_error):
            base = Path(root)
            for name in dirs:
                m = (base/name).lstat()
                need(stat.S_ISDIR(m.st_mode) and m.st_uid in (0, self.vmail.pw_uid) and not m.st_mode & 0o022)
            if base.name not in ('new', 'cur'):
                continue
            for name in files:
                entries += 1; need(entries <= 100000 and time.monotonic() < deadline)
                path = base/name
                with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as f:
                    m = os.fstat(f.fileno())
                    need(stat.S_ISREG(m.st_mode) and m.st_uid == self.vmail.pw_uid
                         and m.st_nlink == 1 and not m.st_mode & 0o022 and 0 < m.st_size <= LIMIT)
                    header = bytearray()
                    while True:
                        line = f.readline(1024*1024+1-len(header)); header.extend(line)
                        need(line and len(header) <= 1024*1024)
                        if line in (b'\n', b'\r\n'):
                            break
                    # Existing tagged copies remain under original migration validation.
                    tagged = any(x.lower().startswith(b'x-uidl:') for x in bytes(header).splitlines())
                    if not tagged:
                        body = f.read(LIMIT+1-len(header)); raw = bytes(header)+body
                        need(len(raw) == m.st_size and len(raw) <= LIMIT)
                        total += len(raw); need(total <= 4*1024*1024*1024)
                        try:
                            fp = fingerprint(raw)
                        except ValueError:
                            # Untagged ordinary mail need not be eligible as a witness.
                            fp = None
                        if fp is not None:
                            result.setdefault(fp, []).append((box(maildir, path), str(path)))
                            self.stamps[path] = signature(m)
                    need(signature(m) == signature(os.fstat(f.fileno())) == signature(path.lstat()))
        return result

    def prepare(self, maildir, uidls, connect, retr, scan, box):
        need(not self.prepared)
        extra = self.native_ids()
        source = {}
        for num, value in uidls:
            key = value.encode('ascii')
            need(type(num) is int and num > 0 and key not in source)
            source[key] = num
        need(extra <= set(source))
        existing = scan(maildir)
        pending = extra-{u.encode('ascii') for u, locations in existing.items() if len(locations) == 1}
        need(not any(len(locations) != 1 for u, locations in existing.items() if u.encode('ascii') in extra))
        active = self.barrier | dict(phase='migration_in_progress', generation=self.barrier['generation']+1)
        write_state(active, self.user.pw_gid, self.barrier)
        self.barrier = active
        deadline = time.monotonic()+900
        witnesses = self.candidates(maildir, box, deadline) if pending else {}
        used = set(); pop = None
        try:
            if pending:
                pop = connect()
            for key in sorted(pending):
                need(time.monotonic() < deadline)
                number = source[key]
                reply = pop.uidl(number)
                if isinstance(reply, bytes):
                    reply = reply.decode('ascii')
                need(reply.split() == ['+OK', str(number), key.decode('ascii')])
                _, lines, _ = retr(pop, number)
                raw = b'\r\n'.join(lines)+b'\r\n'
                candidates = witnesses.get(fingerprint(raw), [])
                need(len(candidates) == 1 and candidates[0][1] not in used)
                location = candidates[0]; used.add(location[1])
                self.matches[key.decode('ascii')] = [location]
        finally:
            if pop is not None:
                # No DELE, no save/import. Failed comparison retains review barrier.
                pop.close()
        self.prepared = True

    def augment(self, existing):
        need(self.prepared)
        result = dict(existing)
        for uidl, locations in self.matches.items():
            need(uidl not in existing)
            path = Path(locations[0][1])
            need(signature(path.lstat()) == self.stamps[path])
            result[uidl] = list(locations)
        return result

    def tagged_pop_missing(self, expected, actual):
        return (expected-set(self.matches))-actual

    def tagged_pop_visible(self, expected, actual):
        return (expected-set(self.matches)) & actual

    def complete(self, imported, ok):
        need(self.prepared and type(imported) is int and imported >= 0 and ok is True)
        # New migration imports have X-UIDL but are not in native fetchids.
        # Never edit that history here: stop regular POP until a separate review.
        value = self.barrier | dict(phase='reconciliation_required' if imported else 'idle')
        write_state(value, self.user.pw_gid, self.barrier)
        print(json.dumps(dict(compatibility_content_matches=len(self.matches),
            existing_uidl_changed=False, stored_headers_changed=False,
            tagged_local_pop_uidl_check_only=True, untagged_pop_visibility_verified=False,
            regular_pop_requires_reconciliation=bool(imported)), sort_keys=True))


class SafeGuard:
    """No raw native/file/POP errors and no old wrapper retry on safety stops."""
    def __init__(self, value):
        self.value = value

    def __getattr__(self, name):
        need(name in ('prepare', 'augment', 'tagged_pop_missing', 'tagged_pop_visible', 'complete'))
        def invoke(*args):
            try:
                return getattr(self.value, name)(*args)
            except Exception:
                raise SystemExit(78) from None
        return invoke


def enter(email, host):
    if email != 'ken@mi-sys.jp':
        return Noop()
    try:
        return SafeGuard(Guard(host))
    except Exception:
        raise SystemExit(78) from None
