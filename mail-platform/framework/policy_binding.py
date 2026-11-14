"""Fixed, read-only publication path for the live SMTP stop controls."""
from pathlib import Path
import os
import stat
import json

DROPIN = '/etc/systemd/system/mail-send-limits-v1.service.d/60-mail-platform-stops.conf'
CONTENT = (b'[Unit]\nRequires=mail-feature-admin-v1.service\nAfter=mail-feature-admin-v1.service\n'
           b'[Service]\nBindReadOnlyPaths=/var/lib/mail-feature-admin-v1/public-stops:'
           b'/run/mail-send-limits-v1/admin-stops\n')


def ensure_directories():
    """Retain existing controls and reject unexpected attributes before using them."""
    import grp
    group = grp.getgrnam('mailsendlimits').gr_gid
    for path, mode, gid in [('/var/lib/mail-feature-admin-v1/diagnostics', 0o700, 0),
                            ('/var/lib/mail-feature-admin-v1/public-stops', 0o750, group)]:
        target = Path(path)
        if not target.exists() and not target.is_symlink():
            target.mkdir(mode=0o700)
            descriptor = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fchown(descriptor, 0, gid)
                os.fchmod(descriptor, mode)
            finally:
                os.close(descriptor)
        metadata = target.lstat()
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                or metadata.st_gid != gid or stat.S_IMODE(metadata.st_mode) != mode):
            raise ValueError('policy_stop_directory_requires_review')


def probe(commands):
    """Check the real SQL profiles and published controls without reserving mail."""
    import pwd
    from host_transaction import regular
    from release import canonical
    config = json.loads(regular('/etc/mail-send-limits-v1/runtime.json')[0])
    if config['socket'] != '/var/spool/postfix/private/mail-send-limits-v1.sock':
        raise ValueError('policy_stop_probe_socket')
    peer = pwd.getpwuid(config['peer_uid'])
    request = {'kind':'policy','request':'request=mail_platform_generation_health\n\n',
               'reply':'action=DUNNO\n\n','peer_uid':peer.pw_uid,'peer_gid':peer.pw_gid,'socket':config['socket']}
    commands.run('policy_stop_health', ['/usr/bin/python3','-I','-S','-B',
                 '/usr/local/lib/mail-platform-update/generation_probe.py'], canonical(request), timeout=8)
