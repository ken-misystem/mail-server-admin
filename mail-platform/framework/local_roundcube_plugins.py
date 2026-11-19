"""Exclude the old Roundcube sources and metadata from product exports."""

PREFIX = 'usr/share/roundcube/plugins/'
NAMES = frozenset({'account_recovery', 'local_ja_tweaks', 'local_password_recovery',
                   'session_epoch_guard', 'turnstile'})


def excluded(name):
    name = name.removeprefix('payload/')
    for prefix in (PREFIX, 'plugins/roundcube-about/'):
        if name.startswith(prefix):
            return name[len(prefix):].split('/')[0] in NAMES
    return False
