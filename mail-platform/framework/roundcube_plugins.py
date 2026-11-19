"""Register packaged plugins in Debian's Roundcube web root with a CAS receipt."""
import json
import os
from pathlib import Path
import re
import stat

from host_transaction import durable_json

SOURCE = '/usr/share/roundcube/plugins'
WEB = '/var/lib/roundcube/plugins'


def packaged_plugins(files):
    recipes = json.loads(files['blueprint/install-recipes.json'])
    names = recipes['roundcube_plugins']
    if not isinstance(names, list) or any(not isinstance(name, str)
            or not re.fullmatch(r'[a-z][a-z0-9_]*', name) for name in names) or len(set(names)) != len(names):
        raise ValueError('roundcube_plugin_names')
    if SOURCE.lstrip('/') + '/mi_system_compat/LoginView.php' in files:
        # Link the optional adapters without enabling them in Roundcube's config.
        names = names + [name for name in ('local_password_recovery', 'turnstile') if name not in names]
    return [name for name in names if (SOURCE.lstrip('/')+'/'+name+'/'+name+'.php') in files]


class PluginLinks:
    def __init__(self, root, receipt):
        self.root = Path(root)
        self.receipt = Path(receipt)

    def path(self, logical):
        path = self.root / logical.lstrip('/')
        for parent in reversed(path.parents):
            if parent == self.root or self.root in parent.parents:
                info = parent.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                    raise ValueError('roundcube_plugin_parent')
        return path

    @staticmethod
    def link_state(path):
        try:
            info = path.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISLNK(info.st_mode):
            raise ValueError('roundcube_plugin_path_conflict')
        return {'target': os.readlink(path), 'uid': info.st_uid, 'gid': info.st_gid,
                'inode': info.st_ino, 'device': info.st_dev}

    def apply(self, names):
        if self.receipt.exists():
            raise ValueError('roundcube_plugin_receipt_exists')
        entries = []
        for name in names:
            if not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9_]*', name):
                raise ValueError('roundcube_plugin_names')
            source = SOURCE+'/'+name
            entry = self.path(source+'/'+name+'.php')
            info = entry.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('roundcube_plugin_source')
            destination = WEB+'/'+name
            state = self.link_state(self.path(destination))
            if state is not None and (state['target'] != source or state['uid'] != 0):
                raise ValueError('roundcube_plugin_path_conflict')
            entries.append({'path': destination, 'target': source, 'before': state, 'after': None})
        record = {'format': 1, 'phase': 'prepared', 'entries': entries}
        durable_json(self.receipt, record)
        for row in entries:
            path = self.path(row['path'])
            if self.link_state(path) != row['before']:
                raise ValueError('roundcube_plugin_path_changed')
            if row['before'] is None:
                os.symlink(row['target'], path)
                row['after'] = self.link_state(path)
                directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
                durable_json(self.receipt, record)
        record['phase'] = 'installed'
        durable_json(self.receipt, record)
        return record

    def restore(self):
        if not self.receipt.exists():
            return {'status': 'not_created', 'held': []}
        record = json.loads(self.receipt.read_bytes())
        held = []
        for row in reversed(record['entries']):
            if row['before'] is not None:
                continue
            path = self.path(row['path'])
            try:
                current = self.link_state(path)
            except ValueError:
                held.append(row['path'])
                continue
            if current is None:
                continue
            if row['after'] is None or current != row['after']:
                held.append(row['path'])
                continue
            path.unlink()
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        record['phase'] = 'held' if held else 'restored'
        durable_json(self.receipt, record)
        return {'status': record['phase'], 'held': held}
