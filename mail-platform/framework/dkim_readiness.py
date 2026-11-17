"""Site DKIM reconciliation. No DNS writes, mail submission, or private-key export.

New keys stay private until two public resolvers match. Configuration rollback
uses its own CAS journal; generated keys survive rollback in private staging.
"""
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import time
import urllib.request
import urllib.parse
import uuid

from host_transaction import Commands, CommandFailure, Files, durable_json, regular

CONFIG = '/etc/rspamd/local.d/dkim_signing.conf'
STATE = '/var/lib/mail-platform-dkim'
BOOLS = ('check_pubkey', 'allow_pubkey_mismatch', 'sign_inbound')
TOKEN = re.compile(r'\s+|\#[^\n]*|//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\x27(?:\\.|[^\x27\\])*\x27|[A-Za-z_][A-Za-z_0-9]*|.', re.S)


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def deduplicate(raw):
    """Remove only identical top-level boolean duplicates, preserving other bytes."""
    text = raw.decode('utf-8')
    tokens = [m for m in TOKEN.finditer(text)
              if not m.group().isspace() and not m.group().startswith(('#', '//', '/*'))]
    depth = 0
    found = {}
    removals = []
    for i, match in enumerate(tokens):
        token = match.group()
        if token in ('{', '['): depth += 1
        elif token in ('}', ']'): depth -= 1
        need(depth >= 0, 'configuration_nesting')
        if depth == 0 and token in BOOLS:
            tail = tokens[i:i+4]
            need(len(tail) == 4 and tail[1].group() == '=' and
                 tail[2].group() in ('true', 'false') and tail[3].group() == ';',
                 'manual_boolean_expression')
            value = tail[2].group()
            if token in found:
                need(found[token] == value, 'conflicting_boolean_values')
                removals.append((match.start(), tail[3].end()))
            found[token] = value
    need(depth == 0, 'configuration_nesting')
    for start, end in reversed(removals): text = text[:start] + text[end:]
    return text.encode(), len(removals)


def domain(value):
    need(type(value) is str and len(value) <= 253 and value == value.lower()
         and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x)
                 for x in value.split('.')) and '.' in value, 'domain_requires_review')
    return value


def targets(settings, site):
    """Deliberately unsupported custom signing programs produce an actionable warning."""
    for key in BOOLS:
        value = settings.get(key, {'check_pubkey': False, 'allow_pubkey_mismatch': True, 'sign_inbound': False}[key])
        if isinstance(value, list):
            need(value and all(type(x) is bool and x == value[0] for x in value), 'conflicting_boolean_values')
            value = value[0]
        need(type(value) is bool, 'manual_boolean_expression')
    need(settings.get('enabled', True) is not False, 'signing_disabled')
    need(settings.get('use_domain', 'header') == 'header' and not settings.get('use_redis', False)
         and not any(settings.get(x) for x in ('selector_map', 'path_map', 'signing_table', 'key_table', 'use_vault')),
         'custom_signing_requires_review')
    domains = settings.get('domain', {})
    need(type(domains) is dict, 'custom_domain_rules')
    names = set(domains) | {domain(site['primary_domain'])}
    # Never guess a public suffix. With ESLD enabled the administrator must
    # confirm notification-domain selection, rather than creating the wrong key.
    esld = settings.get('use_esld', True)
    need(type(esld) is bool, 'custom_esld_expression')
    if not esld: names.add(domain(site['mail_host']))
    need(len(names) <= 32, 'domain_count_requires_review')
    result = []
    for name in sorted(names):
        domain(name)
        spec = domains.get(name, {})
        need(type(spec) is dict, 'multiple_selectors_require_review')
        selector = spec.get('selector', settings.get('selector', 'dkim'))
        need(type(selector) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,63}', selector), 'selector_requires_review')
        pattern = spec.get('path', settings.get('path', '/var/lib/rspamd/dkim/$domain.$selector.key'))
        need(type(pattern) is str, 'key_path_requires_review')
        path = pattern.replace('${domain}', name).replace('$domain', name).replace('${selector}', selector).replace('$selector', selector)
        need(re.fullmatch(r'/var/lib/rspamd/dkim/[A-Za-z0-9_.-]+\.key', path) and '..' not in Path(path).name,
             'custom_key_path_requires_review')
        result.append({'domain': name, 'selector': selector, 'key_path': path,
                       'dns_name': selector+'._domainkey.'+name})
    need(len({x['key_path'] for x in result}) == len(result), 'shared_key_path_requires_review')
    return result, esld and site['mail_host'] != site['primary_domain']


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): raise ValueError('DNS_redirect')


def public_dns(name, deadline=None):
    answers = []
    for base in ('https://dns.google/resolve', 'https://cloudflare-dns.com/dns-query'):
        req = urllib.request.Request(base+'?'+urllib.parse.urlencode({'name': name, 'type': 'TXT'}),
                                     headers={'Accept': 'application/dns-json'})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        remaining = 4 if deadline is None else min(4, deadline-time.monotonic())
        if remaining <= 0: raise TimeoutError('DNS_check_budget')
        with opener.open(req, timeout=remaining) as response:
            raw = response.read(65537)
        need(len(raw) <= 65536, 'DNS_response_size')
        value = json.loads(raw)
        need(value.get('Status') in (0, 3) and not value.get('TC', False), 'DNS_unavailable')
        rows = []
        for row in value.get('Answer', []):
            if row.get('type') == 16:
                need(row.get('name', '').rstrip('.').lower() == name.lower(), 'DNS_owner_mismatch')
                rows.append(''.join(shlex.split(row['data'])))
        answers.append(rows)
    return answers


def dns_state(answers, public):
    if len(answers) != 2: return 'dns_unavailable'
    if all(not rows for rows in answers): return 'dns_missing'
    if answers[0] != answers[1]: return 'dns_propagating'
    if len(answers[0]) != 1: return 'dns_conflict'
    tags = {}
    try:
        for item in answers[0][0].split(';'):
            if not item.strip(): continue
            key, value = item.strip().split('=', 1)
            if key in tags: return 'dns_conflict'
            tags[key] = value.strip()
        if tags.get('v') != 'DKIM1' or tags.get('k', 'rsa') != 'rsa': return 'dns_conflict'
        if ('h' in tags and 'sha256' not in tags['h'].split(':')) or ('s' in tags and not {'*','email'} & set(tags['s'].split(':'))):
            return 'dns_policy_review'
        actual = base64.b64decode(re.sub(r'\s', '', tags.get('p', '')), validate=True)
        return 'matched' if actual == public else 'dns_mismatch'
    except (ValueError, TypeError): return 'dns_conflict'


class Reconcile:
    def __init__(self, root, evidence, commands=None, resolver=public_dns):
        self.root = Path(root)
        self.evidence = Path(evidence)
        self.commands = commands or Commands(self.evidence)
        self.resolver = resolver
        self.state = self.root / STATE.lstrip('/')
        self.record_path = self.evidence/'dkim-operation.json'
        self.config_files = Files(self.root, self.evidence)
        self.record = {'format': 1, 'phase': 'planned', 'new_links': [], 'reload_started': False}

    def path(self, logical): return self.root/logical.lstrip('/')

    @staticmethod
    def safe_dir(path, allowed=(0,), create=False, mode=0o700):
        if create:
            try:
                path.mkdir(mode=mode)
                os.chmod(path, mode)
            except FileExistsError:
                pass
        st = path.lstat()
        need(stat.S_ISDIR(st.st_mode) and st.st_uid in allowed and not st.st_mode & 0o022, 'directory_requires_review')
        return st

    @contextlib.contextmanager
    def lock(self):
        self.safe_dir(self.path('/var/lib'))
        self.safe_dir(self.state, create=True, mode=0o755)
        fd = os.open(self.state/'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            st = os.fstat(fd);need(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1 and not st.st_mode & 0o077, 'DKIM_lock_attributes')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally: os.close(fd)

    def save(self): durable_json(self.record_path, self.record)

    def effective(self):
        raw = self.commands.run('dkim_effective', ['/usr/bin/rspamadm', 'configdump', 'dkim_signing', '-j'], timeout=20)
        value = json.loads(raw);return value.get('dkim_signing', value)

    def reload_ready(self):
        # Reuse the already verified signal-handler/library readiness check.
        # systemd active alone does not mean the master can safely accept HUP.
        from native_package_update import NativePackage
        probe = object.__new__(NativePackage);probe.root = self.root
        deadline = time.monotonic()+60;last = None;stable = 0
        while stable < 2:
            raw = self.commands.run('dkim_reload_state', ['/usr/bin/systemctl','show','rspamd.service',
                       '-p','ActiveState,MainPID,Job'], timeout=10)
            unit = dict(line.split('=',1) for line in raw.decode().splitlines())
            need(unit.get('Job') in ('','0') and unit.get('ActiveState')=='active' and int(unit['MainPID'])>1, 'Rspamd_reload_not_ready')
            observed = probe.process(int(unit['MainPID']))
            identity = (observed['pid'], observed['ticks'])
            self.record.setdefault('reload_readiness',[]).append(observed);self.save()
            stable = (stable+1 if identity==last else 1) if observed['ready'] else 0;last = identity
            need(time.monotonic()<deadline, 'Rspamd_reload_readiness_timeout')
            if stable < 2: time.sleep(.5)
        return identity

    def reload(self, label):
        identity = self.reload_ready()
        self.record['reload_started'] = True;self.save()
        self.commands.run(label, ['/usr/bin/systemctl','reload','rspamd.service'], timeout=30)
        need(self.reload_ready()==identity, 'Rspamd_reload_master_changed')
        self.record['reload_started'] = False;self.record['reloaded'] = True;self.save()

    def public(self, key):
        st = key.lstat()
        need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid in getattr(self, 'keyowners', (0,))
             and not st.st_mode & 0o137, 'key_attributes_require_review')
        raw = self.commands.run('dkim_public', ['/usr/bin/openssl', 'pkey', '-in', str(key), '-passin', 'pass:', '-pubout', '-outform', 'DER'], timeout=15)
        need(bytes.fromhex('06092a864886f70d010101') in raw[:40] and len(raw) >= 140, 'non_RSA_key_requires_review')
        return raw

    def pending(self, item):
        area = self.state/'pending';self.safe_dir(area, create=True)
        stem = hashlib.sha256(item['key_path'].encode()).hexdigest()
        directory = area/stem
        if directory.exists():
            st = self.safe_dir(directory);need(stat.S_IMODE(st.st_mode) == 0o700, 'pending_permissions')
            need((directory/'complete.json').exists(), 'interrupted_key_generation_requires_review')
        else:
            directory.mkdir(mode=0o700)
            self.commands.run('dkim_generate', ['/usr/bin/openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(directory/'key.pem')], timeout=30)
            os.chmod(directory/'key.pem', 0o600)
            with (directory/'key.pem').open('rb') as stream: os.fsync(stream.fileno())
            durable_json(directory/'complete.json', {'path': item['key_path'], 'public_sha256': hashlib.sha256(self.public(directory/'key.pem')).hexdigest()})
        key = directory/'key.pem';record = json.loads(regular(directory/'complete.json')[0])
        need(record == {'path': item['key_path'], 'public_sha256': hashlib.sha256(self.public(key)).hexdigest()}, 'pending_key_changed')
        return key

    def expose(self, key, target, uid, gid):
        # Copy into a private temporary file on the target mount, then publish
        # by an exclusive hardlink. The private source key is retained.
        self.safe_dir(self.path('/var/lib/rspamd'), (0, uid))
        if not target.parent.exists():
            target.parent.mkdir(mode=0o750);os.chown(target.parent, 0, gid);os.chmod(target.parent, 0o750)
        self.safe_dir(target.parent, (0, uid))
        fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        temporary = '.mail-dkim-'+uuid.uuid4().hex
        try:
            out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            raw, _ = regular(key)
            with os.fdopen(out, 'wb') as stream:
                os.fchown(stream.fileno(), 0, gid);os.fchmod(stream.fileno(), 0o640)
                stream.write(raw);stream.flush();os.fsync(stream.fileno())
            record = {'target': '/'+str(target.relative_to(self.root)), 'public_sha256': hashlib.sha256(self.public(key)).hexdigest(), 'phase': 'link_started'}
            self.record['new_links'].append(record);self.save()
            os.link(temporary, target.name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            os.unlink(temporary, dir_fd=fd);os.fsync(fd)
            _, record['metadata'] = regular(target)
            record['phase'] = 'linked';self.save()
        finally: os.close(fd)

    def publish(self, entries, warnings):
        value = {'format': 1, 'observed_at': int(time.time()), 'entries': entries, 'warnings': warnings,
                 'needs_attention': bool(warnings) or any(x['state'] != 'ready' for x in entries)}
        # World-readable by design: only public TXT, finite states, no key paths.
        durable_json(self.state/'status.json', value, mode=0o644)
        return value

    def apply(self, site, identities, *, refresh_only=False):
        entries, warnings = [], []
        with self.lock():
            if not refresh_only:
                need(not self.record_path.exists(), 'DKIM_operation_already_started')
                self.save()
            try:
                raw, before = regular(self.path(CONFIG), 131072)
                need(before['uid']==0 and not before['mode'] & 0o022, 'configuration_permissions_require_review')
                normalized, removed = deduplicate(raw)
                settings = self.effective()
                selected, esld_review = targets(settings, site)
                if esld_review: warnings.append('notification_domain_ESLD_requires_review')
                uid, gid = identities['_rspamd.uid'], identities['_rspamd.gid']
                need(type(uid) is int and uid > 0 and type(gid) is int and gid > 0, 'Rspamd_identity')
                self.keyowners = (0, uid)
                if removed and not refresh_only:
                    self.config_files.write(CONFIG, normalized, before['mode'], before['uid'], before['gid'], expected_before=before)
                    self.commands.run('dkim_configtest', ['/usr/bin/rspamadm', 'configtest'], timeout=30)
                    settings = self.effective()
                    need(all(type(settings.get(k)) is bool for k in BOOLS), 'effective_boolean_not_scalar')
                    self.record['config_changed'] = True;self.save()
                    active = self.commands.run('dkim_active', ['/usr/bin/systemctl', 'show', 'rspamd.service', '-p', 'ActiveState', '--value'], timeout=10).strip()
                    if active == b'active':
                        self.reload('dkim_reload')
                elif removed: warnings.append('duplicate_boolean_values')
                safe_policy = (settings.get('check_pubkey') is True and settings.get('allow_pubkey_mismatch') is False
                               and settings.get('sign_inbound', False) is False)
                if not safe_policy:
                    warnings.append('public_key_policy_requires_review')
                deadline = time.monotonic()+20
                for item in selected:
                    target = self.path(item['key_path'])
                    self.safe_dir(self.path('/var/lib/rspamd'), (0, uid))
                    if target.parent.exists(): self.safe_dir(target.parent, (0, uid))
                    exists = os.path.lexists(target)
                    if exists:
                        key = target
                    elif refresh_only:
                        key = self.state/'pending'/hashlib.sha256(item['key_path'].encode()).hexdigest()/'key.pem'
                        if not key.exists():
                            entries.append({'domain': item['domain'], 'selector': item['selector'], 'dns_name': item['dns_name'], 'state': 'key_missing', 'txt': None});continue
                    else: key = self.pending(item)
                    try: public = self.public(key)
                    except (ValueError, CommandFailure, OSError):
                        if not exists: raise
                        # An existing custom/unreadable key is not replaced.
                        # It remains a visible, per-domain operator task.
                        entries.append({'domain':item['domain'],'selector':item['selector'],
                                        'dns_name':item['dns_name'],'txt':None,'state':'key_review'})
                        continue
                    key_metadata = key.lstat()
                    worker_readable = (not exists or (key_metadata.st_uid==uid and bool(key_metadata.st_mode & 0o400))
                                       or (key_metadata.st_gid==gid and bool(key_metadata.st_mode & 0o040)))
                    try:
                        answers = (public_dns(item['dns_name'], deadline) if self.resolver is public_dns
                                   else self.resolver(item['dns_name']))
                        state = dns_state(answers, public)
                    except Exception: state = 'dns_unavailable'
                    if state == 'matched':
                        if not exists and not refresh_only and safe_policy and not esld_review:
                            self.expose(key, target, uid, gid);exists = True
                        state = 'policy_review' if not safe_policy or esld_review else ('ready' if exists else 'activation_pending')
                    if not worker_readable: state = 'key_review'
                    entries.append({'domain': item['domain'], 'selector': item['selector'], 'dns_name': item['dns_name'],
                                    'txt': 'v=DKIM1; k=rsa; p='+base64.b64encode(public).decode(), 'state': state})
                value = self.publish(entries, warnings)
                if not refresh_only: self.record['phase'] = 'complete';self.save()
                return value
            except (ValueError, FileNotFoundError) as error:
                # Unsupported site configuration is a visible manual task. An
                # error after a mutation must propagate to the update rollback.
                if self.config_files.entries or self.record['new_links']: raise
                reason = str(error) if isinstance(error, ValueError) else 'missing_configuration_or_directory'
                value = self.publish(entries, ['manual_review:'+reason])
                if not refresh_only: self.record['phase'] = 'manual_review';self.save()
                return value

    def rollback(self):
        if not self.record_path.exists(): return
        with self.lock():
            self.record = json.loads(regular(self.record_path)[0])
            need(not self.record['reload_started'], 'DKIM_reload_outcome_unknown')
            for link in reversed(self.record['new_links']):
                if link['phase'] == 'withdrawn': continue
                need(link['phase'] == 'linked', 'DKIM_link_outcome_unknown')
                target = self.path(link['target'])
                need(regular(target)[1] == link['metadata'] and hashlib.sha256(self.public(target)).hexdigest() == link['public_sha256'], 'DKIM_withdraw_CAS')
                target.unlink()
                fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try: os.fsync(fd)
                finally: os.close(fd)
                link['phase'] = 'withdrawn';self.save()
            self.config_files.entries = [json.loads(p.read_bytes()) for p in sorted(self.evidence.glob('file-entry-*.json'))]
            need(self.config_files.restore()['status'] == 'restored', 'DKIM_config_restore_held')
            if self.record.get('reloaded'):
                self.reload('dkim_restore_reload')
                self.record['reloaded'] = False;self.save()
            self.record['phase'] = 'rolled_back';self.save()
            self.publish([], ['update_rolled_back_keys_retained'])


def update_apply(engine):
    directory = engine.directory/'dkim';directory.mkdir(mode=0o700, exist_ok=True)
    receipt = engine.record['old_receipt']
    return Reconcile(engine.root, directory, commands=engine.commands).apply(receipt['site'], receipt['identities'])


def update_rollback(engine):
    directory = engine.directory/'dkim'
    if directory.exists(): Reconcile(engine.root, directory, commands=engine.commands).rollback()


def installed(refresh_only=True, root='/'):
    root = Path(root)
    # Manual activation shares the package updater's exclusive lock. The
    # updater itself calls update_apply while already holding this lock.
    if not refresh_only:
        fd = os.open(root/'var/lib/mail-platform-update/update.lock', os.O_RDWR | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and not info.st_mode & 0o077, 'update_lock_attributes')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return _installed(False, root)
        finally: os.close(fd)
    return _installed(True, root)


def refresh_for_update(root='/'):
    """An informational read failure cannot cancel an otherwise valid update."""
    try:
        return installed(True, root)
    except Exception as error:
        state = Path(root)/STATE.lstrip('/')
        # Separate marker: do not overwrite another operation's status or lock.
        # If even this cannot be saved, the retained status expires visibly.
        try:
            Reconcile.safe_dir(state, (0,))
            durable_json(state/'refresh-failure.json', {'observed_at':int(time.time()),
                         'error':type(error).__name__}, mode=0o644)
        except (OSError, ValueError): pass
        return {'phase':'checklist_unavailable','error':type(error).__name__}


def _installed(refresh_only, root):
    receipt = json.loads(regular(root/'var/lib/mail-platform-update/installed-code.json')[0])
    evidence = root/'var/lib/mail-platform-update'/('dkim-'+str(time.time_ns()))
    evidence.mkdir(mode=0o700)
    operation = Reconcile(root, evidence)
    try:
        return operation.apply(receipt['site'], receipt['identities'], refresh_only=refresh_only)
    except Exception as error:
        durable_json(evidence/'failure.json', {'class': type(error).__name__, 'reason': str(error) if isinstance(error, ValueError) else 'operation_failed'})
        if not refresh_only: operation.rollback()
        raise
