"""Fresh-site admission barriers and terminal-only initial access issuance."""
import json
import hashlib
import os
from pathlib import Path
import secrets
import stat
import time

from host_transaction import durable_json, regular

STATE = Path('/var/lib/mail-platform-setup/state.json')
ACCESS = Path('/etc/mail-platform/initial-access.json')
GUARD = 'mail-platform-publication-approved.service'
GUARD_PATH = '/usr/local/lib/mail-platform-setup/guard.py'
LIFETIME = 1800
LOCAL_WEB = ' listen 127.0.0.1:443 ssl;'
PUBLIC_WEB = ' listen 443 ssl;'
WEB = '/etc/nginx/sites-enabled/mail-platform.conf'

GUARD_CODE = b'''"""Root-owned publication barrier for fresh installations."""
import json, os, stat, sys
from pathlib import Path
path = Path('/var/lib/mail-platform-setup/state.json')
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > 4096:
        raise ValueError('publication_state_trust')
    state = json.loads(os.read(descriptor, 4097))
finally:
    os.close(descriptor)
allowed = state.get('phase') == 'published'
if sys.argv[1:] == ['ui']:
    allowed = state.get('phase') in ('setup', 'activating', 'published')
if state.get('phase') == 'activating':
    allowed = state.get('boot_id') == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
if not allowed:
    raise SystemExit('initial_setup_not_published')
'''


def guard_unit(ui=False):
    return ('[Unit]\nDescription=Mail platform explicit publication approval\n'
            'DefaultDependencies=no\nAfter=local-fs.target\nBefore=network-pre.target\n'
            '[Service]\nType=oneshot\nRemainAfterExit=yes\nUser=root\nGroup=root\n'
            'ExecStart=/usr/bin/python3 -I -S -B '+GUARD_PATH+(' ui' if ui else '')+'\n'
            'NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\n'
            'PrivateNetwork=yes\nCapabilityBoundingSet=\n').encode()


def guarded_units(units, base_services):
    # DNS-01 renewal only connects outward and refreshes the loopback setup UI.
    allowed = {'mariadb.service', 'php8.4-fpm.service', 'nginx.service', 'mail-client-cert-health.service',
               'mail-platform-acme.service','mail-platform-acme.timer'}
    selected = set(units) | set(base_services) | {'mail-client-certificates.target', 'postfix@.service', 'syslog.socket'}
    return sorted(selected - allowed)


def persistent_file(path, raw, mode=0o644):
    """Create the admission barrier outside config rollback so failure stays sealed."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        previous, metadata = regular(path)
        if previous != raw or metadata != {'sha256': hashlib.sha256(raw).hexdigest(),
                                           'uid': 0, 'gid': 0, 'mode': mode}:
            raise ValueError('existing_setup_barrier_requires_review')
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchmod(descriptor, mode)
        os.write(descriptor, raw)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def install_barriers(units, base_services):
    if STATE.exists() or STATE.is_symlink():
        raise ValueError('initial_setup_state_already_exists')
    STATE.parent.mkdir(mode=0o700, parents=True, exist_ok=False)
    durable_json(STATE, {'format': 1, 'phase': 'sealed'})
    persistent_file(GUARD_PATH, GUARD_CODE)
    persistent_file('/etc/systemd/system/'+GUARD, guard_unit())
    persistent_file('/etc/systemd/system/mail-platform-setup-ui-approved.service', guard_unit(ui=True))
    persistent_file('/etc/systemd/system/nginx.service.d/90-initial-setup.conf',
                    b'[Unit]\nRequires=mail-platform-setup-ui-approved.service\nAfter=mail-platform-setup-ui-approved.service\n')
    dropin = ('[Unit]\nRequires='+GUARD+'\nAfter='+GUARD+'\n').encode()
    for unit in guarded_units(units, base_services):
        persistent_file('/etc/systemd/system/'+unit+'.d/90-initial-setup.conf', dropin)


def local_web(raw):
    text = raw.decode()
    if text.count(PUBLIC_WEB) != 1 or LOCAL_WEB in text:
        raise ValueError('initial_web_listener_anchor')
    return text.replace(PUBLIC_WEB, LOCAL_WEB).encode()


def access_metadata(administrator, now=None):
    now = int(time.time()) if now is None else now
    if set(administrator) != {'id', 'email', 'password_fingerprint', 'epoch'}:
        raise ValueError('initial_administrator_receipt')
    return {'format': 1, 'phase': 'setup', 'administrator': administrator,
            'issued_at': now, 'expires_at': now+LIFETIME}


def terminal_password():
    """Refuse unattended issuance before the installer changes anything."""
    stream = open('/dev/tty', 'w', encoding='utf-8')
    if not stream.isatty():
        stream.close()
        raise ValueError('initial_access_interactive_terminal_required')
    return stream, secrets.token_urlsafe(32)


def show_initial_access(stream, host, email, password):
    stream.write('\nInitial mail administration access\n')
    stream.write('URL https://'+host+'/mail-admin/login\n')
    stream.write('Account '+email+'\nTemporary password '+password+'\n')
    stream.write('Expires in 30 minutes. Connect through the local HTTPS tunnel.\n')
    stream.write('Register a passkey, then use the explicit publication command.\n')
    stream.flush()
