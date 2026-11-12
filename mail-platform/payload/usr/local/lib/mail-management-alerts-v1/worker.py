"""Fixed one-cycle worker. Installation/enablement requires reviewed activation.

LoadCredential supplies the webhook; no URL in config, argv, stdout or evidence.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import smtplib
import stat
import sys
import time
import uuid
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime
import datetime as dt

LIB = Path('/usr/local/lib/mail-management-alerts-v1')
PRIVATE = '/var/lib/mail-management-alerts-v1'
PUBLIC = '/var/lib/mail-management-alerts-public-v1'
CONFIG = '/etc/mail-management-alerts-v1/runtime.json'
SNAPSHOT = '/var/lib/mail-management-operations-v1/snapshot.json'
MODULES = ('alerts.py', 'channel_delivery.py', 'discord_webhook.py', 'engine.py', 'store.py')


def need(ok, code):
    if not ok:
        raise ValueError(code)


def identity(s):
    return (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def read_file(path, limit, credential=False):
    """Bounded FD read. Credential parents may be owned by the unit user."""
    parts = Path(path).parts
    need(Path(path).is_absolute() and '..' not in parts, 'read_path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            s = os.fstat(fd)
            need(s.st_uid in ((0, os.geteuid()) if credential else (0,)) and not s.st_mode & 0o022, 'read_parent')
        filefd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            start = os.fstat(filefd)
            need(stat.S_ISREG(start.st_mode) and start.st_nlink == 1 and 0 < start.st_size <= limit and
                 start.st_uid in ((0, os.geteuid()) if credential else (0,)) and not start.st_mode & 0o022, 'read_file_attributes')
            if credential:
                need(stat.S_IMODE(start.st_mode) in (0o400, 0o440) and start.st_gid in (0, os.getegid()), 'credential_permissions')
            raw = os.pread(filefd, start.st_size+1, 0)
            named = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
            need(identity(start) == identity(os.fstat(filefd)) == identity(named) and len(raw) == start.st_size, 'read_drift')
            return raw
        finally:
            os.close(filefd)
    finally:
        os.close(fd)


def libraries():
    need(Path(__file__).absolute() == LIB/'worker.py', 'fixed_worker_path')
    manifest = json.loads(read_file(str(LIB/'BUNDLE_MANIFEST.json'), 16384))
    need(type(manifest) is dict and set(manifest) == set(MODULES) | {'policy.json'}, 'library_manifest')
    for name, pin in manifest.items():
        need(type(pin) is str and re.fullmatch('[a-f0-9]{64}', pin), 'library_pin')
        need(hashlib.sha256(read_file(str(LIB/name), 1048576)).hexdigest() == pin, 'library_drift')
    sys.path.insert(0, str(LIB))
    import alerts, channel_delivery, discord_webhook, engine, store
    return alerts, channel_delivery, discord_webhook, engine, store


def configuration(raw):
    value = json.loads(raw)
    need(type(value) is dict and set(value) == {'version', 'enabled', 'channels', 'smtp', 'public_group'} and
         type(value['version']) is int and value['version'] == 1 and type(value['enabled']) is bool, 'runtime_config')
    need(type(value['channels']) is dict and set(value['channels']) == {'email', 'discord'} and
         all(type(x) is bool for x in value['channels'].values()), 'channel_config')
    smtp = value['smtp']
    need(type(smtp) is dict and set(smtp) == {'host', 'port', 'sender'} and smtp['host'] == '127.0.0.1' and
         type(smtp['port']) is int and smtp['port'] == 25 and smtp['sender'] == 'postmaster@mx.mi-sys.jp', 'fixed_local_smtp')
    need(type(value['public_group']) is int and value['public_group'] == 113, 'public_group')
    need(value['enabled'] or not any(value['channels'].values()), 'disabled_channel_conflict')
    return value


def email_bytes(event, sender, delivery):
    message = EmailMessage(policy=SMTP)
    message['From'] = sender
    message['To'] = 'ken@mi-sys.co.jp'
    message['Subject'] = 'mx.mi-sys.jp 内部障害通知'
    message['Message-ID'] = '<'+event['id']+'@mx.mi-sys.jp>'
    message['Date'] = format_datetime(dt.datetime.fromtimestamp(event['created'], dt.timezone.utc))
    message['Auto-Submitted'] = 'auto-generated'
    message.set_content(delivery.payload(event, delivery.UNIT_NAMES)['content'], charset='utf-8', cte='base64')
    raw = message.as_bytes()
    need(len(raw) <= 16384, 'email_size_bound')
    return raw


def credential_endpoint(discord, expected_unit='mail-management-alerts-v1.service'):
    root = os.environ.get('CREDENTIALS_DIRECTORY')
    need(type(root) is str and root.startswith('/run/credentials/') and
         Path(root).name == expected_unit and '..' not in Path(root).parts, 'credential_directory')
    raw = read_file(str(Path(root)/'discord_webhook'), 4096, credential=True)
    text = raw.decode('utf-8-sig').rstrip('\r\n')
    return discord.Endpoint(text)


def public_write(value):
    raw = (json.dumps(value, ensure_ascii=True, separators=(',', ':'), allow_nan=False)+'\n').encode('ascii')
    need(0 < len(raw) <= 16384, 'public_status_bound')
    fd = os.open(PUBLIC, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        need(s.st_uid == os.geteuid() and s.st_gid == 113 and stat.S_IMODE(s.st_mode) == 0o750, 'public_directory')
        try:
            old = os.stat('status.json', dir_fd=fd, follow_symlinks=False)
            need(stat.S_ISREG(old.st_mode) and old.st_uid == os.geteuid() and old.st_gid == 113 and
                 old.st_nlink == 1 and stat.S_IMODE(old.st_mode) == 0o640, 'public_file')
        except FileNotFoundError:
            old = None
        name = '.status-'+uuid.uuid4().hex+'.tmp'
        child = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            os.fchown(child, -1, 113)
            view = memoryview(raw)
            while view:
                count = os.write(child, view)
                need(count > 0, 'public_short_write')
                view = view[count:]
            os.fchmod(child, 0o640)
            os.fsync(child)
        finally:
            os.close(child)
        try:
            current = os.stat('status.json', dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        need((identity(old) if old else None) == (identity(current) if current else None), 'public_changed')
        os.rename(name, 'status.json', src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    phase = 'guard'
    try:
        need(sys.argv[1:] == ['--cycle'] and os.geteuid() != 0, 'exact_nonroot_cycle')
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        need(ctypes.CDLL(None).prctl(4, 0, 0, 0, 0) == 0, 'dump_protection')
        alerts, delivery, discord, engine, storage = libraries()
        phase = 'configuration'
        config = configuration(read_file(CONFIG, 16384))
        if not config['enabled']:
            print(json.dumps({'status': 'disabled', 'submission_attempted': False}))
            return 0
        policy = alerts.policy(read_file(str(LIB/'policy.json'), 16384))
        phase = 'observation'
        try:
            raw = read_file(SNAPSHOT, 65536)
        except (OSError, ValueError):
            raw = b'{}'  # Missing/unreadable input is an unknown critical observation.
        observation = alerts.observations(raw, int(time.time()), policy, engine.UNITS,
                        ('mail-pop-general-dispatch.service', 'mail-junk-digest-general.service',
                         'mail-client-cert-health.service', 'mail-management-log-viewer.service', 'mail-domain-routing-collect.service', 'mail-management-alerts-v1.service', 'mail-access-admin-v1.service', 'mail-feature-observer-v1.service', 'mail-protection-definitions-v1.service', 'mail-protection-publish-v1.service'))
        adapters = {}
        if config['channels']['email']:
            def email_adapter(event):
                payload = email_bytes(event, config['smtp']['sender'], delivery)
                return delivery.email_result(alerts.smtp_submit(lambda: smtplib.SMTP(config['smtp']['host'], config['smtp']['port'],
                    local_hostname='mx.mi-sys.jp', timeout=10), config['smtp']['sender'], policy['recipient'], payload))
            adapters['email'] = email_adapter
        if config['channels']['discord']:
            adapters['discord'] = lambda event: discord.submit(credential_endpoint(discord), delivery.payload(event, engine.UNITS))
        phase = 'locked_cycle'
        with storage.Store(PRIVATE, lambda v: engine.validate(v, policy)) as journal:
            state, outcomes, faults = engine.cycle(journal, observation, policy, config['channels'], adapters,
                                                  lambda: int(time.time()), storage.Archive(PRIVATE+'/archive'))
            status = engine.summary(state, int(time.time()), config['channels'], outcomes)
            status['worker'] = {'status': 'warning' if faults else 'ok', 'faults': faults}
            phase = 'public_status'
            public_write(status)
        print(json.dumps({'status': 'warning' if faults else 'ok', 'outcomes': outcomes, 'faults': faults,
                          'mailbox_delivery_verified': False}))
        return int(bool(faults))
    except Exception as exc:
        # No raw exception message, URL, traceback locals, config or SMTP reply.
        kind = type(exc).__name__
        safe = {'status': 'fail', 'phase': phase,
                'error_class': kind if kind in ('ValueError', 'OSError', 'FileNotFoundError', 'PermissionError', 'BlockingIOError', 'JSONDecodeError') else 'other',
                'errno': exc.errno if isinstance(exc, OSError) and type(exc.errno) is int else None}
        print(json.dumps(safe))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
