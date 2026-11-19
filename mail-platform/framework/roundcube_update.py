"""Roundcube update compatibility for known legacy locales and web plugin links."""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid

from host_transaction import durable_json, regular
from release import canonical, sha
from roundcube_plugins import PluginLinks, SOURCE, WEB

AUTH = ('local_auth', 'local_auth_gate')
LEGACY = SOURCE + '/.passkey-general-v1'
INITIAL_PROJECTION = SOURCE + '/.mail-platform-047-registered-auth'
PROJECTION_PREFIX = SOURCE + '/.mail-platform-registered-auth-'
MODE = {'uid': 0, 'gid': 0, 'mode': 0o644}
LOCALES = {SOURCE + '/account_recovery/localization/' + name + '.inc': digest for name, digest in (
    ('en_US', '11c599617c46d04bf7a632c99608a44d125e22a77df151585515d0a51fb96dba'),
    ('ja_JP', '97cbc651205ce2319c9b048f33a2b58c4bb0a4afff13c1e799094d2f4ea46f8f'),
)}
OLD_GATE = '7ee3c01ff4db02050c90b6c0f7fc8cc16065f609d7606fc0e872dcea8b2ff754'


def locale_before(engine, target, candidate):
    """Adopt only a known or byte-identical locale that is unowned by dpkg."""
    if target not in LOCALES or not os.path.lexists(engine.files.target(target)):
        return None
    raw, observed = engine.live(target)
    if observed != dict(MODE, sha256=LOCALES[target]) and not (raw == candidate and observed == dict(MODE, sha256=sha(candidate))):
        return None
    admindir = engine.files.target('/var/lib/dpkg/status').parent
    result = subprocess.run(['/usr/bin/dpkg-query', '--admindir='+str(admindir), '-S', target],
                            env={'PATH':'/usr/bin:/bin','LC_ALL':'C'}, capture_output=True, timeout=10)
    missing = f'dpkg-query: no path found matching pattern {target}\n'.encode()
    return observed if result.returncode == 1 and not result.stdout and result.stderr == missing else None


def inventories(paths):
    paths = tuple(paths)
    return {name: sorted(path.removeprefix(SOURCE+'/'+name+'/') for path in paths
                         if path.startswith(SOURCE+'/'+name+'/')) for name in AUTH}


def trusted_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('roundcube_update_untrusted_directory')


def observed_tree(path, links):
    trusted_directory(path)
    found = {}
    for parent, dirs, names in os.walk(path, followlinks=False):
        for name in dirs:
            trusted_directory(Path(parent)/name)
        for name in names:
            entry = Path(parent)/name
            relative = entry.relative_to(path).as_posix()
            found[relative] = PluginLinks.link_state(entry) if links else regular(entry)[1]
    return found


def check_projection(path, names, *, complete):
    found = observed_tree(path, links=True)
    wanted = {name+'/'+relative for name, files in names.items() for relative in files}
    if not found.keys() <= wanted or (complete and found.keys() != wanted):
        raise ValueError('roundcube_update_projection_inventory')
    if any(row['target'] != SOURCE+'/'+relative or row['uid'] != 0 or row['gid'] != 0
           for relative, row in found.items()):
        raise ValueError('roundcube_update_projection_link')
    if any(name+'/'+name+'.php' not in found for name, files in names.items() if files):
        raise ValueError('roundcube_update_projection_entrypoint')


def is_projection(target):
    return target == INITIAL_PROJECTION or re.fullmatch(re.escape(PROJECTION_PREFIX)+r'[a-f0-9]{24}', target) is not None


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class AuthLinks(PluginLinks):
    def plan(self, bound, receipt):
        names = inventories('/'+name for name in bound)
        if not any(names.values()):
            return None
        if any(name+'.php' not in names[name] for name in AUTH):
            raise ValueError('roundcube_update_missing_entrypoint')
        registered = receipt['code']
        old_names = inventories(registered)
        projection = PROJECTION_PREFIX+sha(canonical(names))[:24]
        rows = []
        seen = set()
        project = False
        for name in AUTH:
            path = WEB+'/'+name
            before = self.link_state(self.path(path))
            if before is not None:
                target = before['target']
                base, leaf = target.rsplit('/', 1) if '/' in target else ('', target)
                if before['uid'] != 0 or before['gid'] != 0 or leaf != name:
                    raise ValueError('roundcube_update_unknown_link:'+path)
                if base == LEGACY:
                    old = observed_tree(self.path(target), links=False)
                    for relative, metadata in old.items():
                        known = metadata == registered.get(SOURCE+'/'+name+'/'+relative)
                        gate = name == 'local_auth_gate' and relative == 'local_auth_gate.php' and metadata == dict(MODE, sha256=OLD_GATE)
                        if relative not in names[name] or not (known or gate):
                            raise ValueError('roundcube_update_legacy_file:'+relative)
                    if name+'.php' not in old:
                        raise ValueError('roundcube_update_missing_legacy_entrypoint')
                    project = True
                elif is_projection(base):
                    if base not in seen:
                        check_projection(self.path(base), old_names, complete=False)
                        seen.add(base)
                    project = True
                elif base != SOURCE:
                    raise ValueError('roundcube_update_unknown_link:'+path)
            rows.append({'name':name,'path':path,'before':before})
        for row in rows:
            row['target'] = (projection if project else SOURCE)+'/'+row['name']
        if project and os.path.lexists(self.path(projection)):
            check_projection(self.path(projection), names, complete=True)
        change = any(row['before'] is None or row['before']['target'] != row['target'] for row in rows)
        hashes = {SOURCE+'/'+name+'/'+relative: sha(bound[(SOURCE+'/'+name+'/'+relative).lstrip('/')])
                  for name, files in names.items() for relative in files}
        return {'entries':rows,'files':names,'hashes':hashes,'change':change,
                'projection':projection if project else None}

    def build_projection(self, plan):
        logical = plan['projection']
        if logical is None:
            return
        target = self.path(logical)
        if not os.path.lexists(target):
            staging = target.with_name('.staged-auth-'+uuid.uuid4().hex)
            staging.mkdir(mode=0o755)
            staging.chmod(0o755)
            for name, files in plan['files'].items():
                for relative in files:
                    path = staging/name/relative
                    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                    for parent in path.relative_to(staging).parents:
                        if parent != Path('.'):
                            (staging/parent).chmod(0o755)
                    path.symlink_to(SOURCE+'/'+name+'/'+relative)
            check_projection(staging, plan['files'], complete=True)
            for folder in (p for p, _, _ in os.walk(staging, topdown=False)):
                sync_directory(folder)
            if os.path.lexists(target):
                raise ValueError('roundcube_update_projection_appeared')
            os.rename(staging, target)
            sync_directory(target.parent)
        check_projection(target, plan['files'], complete=True)

    def replace(self, path, before, target, record, row, field):
        temporary = path.with_name('.mail-platform-auth-link-'+uuid.uuid4().hex)
        temporary.symlink_to(target)
        try:
            row[field] = self.link_state(temporary)
            durable_json(self.receipt, record)
            if self.link_state(path) != before:
                raise ValueError('roundcube_update_link_CAS:'+row['path'])
            if before is None:
                os.link(temporary, path, follow_symlinks=False)
            else:
                os.replace(temporary, path)
            sync_directory(path.parent)
            if self.link_state(path) != row[field]:
                raise ValueError('roundcube_update_link_readback')
        finally:
            if temporary.is_symlink():
                temporary.unlink()

    def update(self, plan):
        if self.receipt.exists():
            raise ValueError('roundcube_update_link_journal_exists')
        for row in plan['entries']:
            if self.link_state(self.path(row['path'])) != row['before']:
                raise ValueError('roundcube_update_link_drift:'+row['path'])
        self.verify_sources(plan)
        self.build_projection(plan)
        rows = [dict(row, after=row['before']) for row in plan['entries']]
        record = {'entries':rows}
        durable_json(self.receipt, record)
        for row in rows:
            before = row['before']
            if before is None or before['target'] != row['target']:
                self.replace(self.path(row['path']), before, row['target'], record, row, 'after')
        self.verify_update(plan)

    def verify_update(self, plan):
        self.verify_sources(plan)
        entries = self.read_journal()['entries'] if plan['change'] else [dict(row, after=row['before']) for row in plan['entries']]
        for row, wanted in zip(entries, plan['entries'], strict=True):
            current = self.link_state(self.path(row['path']))
            if (row['path'] != wanted['path'] or current is None
                    or current != row['after'] or current['target'] != wanted['target']):
                raise ValueError('roundcube_update_link_health')
        if plan['projection']:
            check_projection(self.path(plan['projection']), plan['files'], complete=True)

    def verify_sources(self, plan):
        for path, digest in plan['hashes'].items():
            meta = regular(self.path(path))[1]
            if meta['uid'] != 0 or meta['mode'] & 0o022 or meta['sha256'] != digest:
                raise ValueError('roundcube_update_source_trust:'+path)

    def read_journal(self):
        raw, meta = regular(self.receipt)
        value = json.loads(raw)
        if (meta['uid'] != 0 or meta['mode'] != 0o600
                or [row['path'] for row in value['entries']] != [WEB+'/'+name for name in AUTH]):
            raise ValueError('roundcube_update_link_journal_trust')
        return value

    def recoverable(self):
        if self.receipt.exists():
            for row in self.read_journal()['entries']:
                observed = self.link_state(self.path(row['path']))
                known = (row['before'], row['after'], row.get('restored', row['before']))
                if observed not in known:
                    raise ValueError('roundcube_update_link_rollback_held:'+row['path'])

    def restore_update(self):
        if not self.receipt.exists():
            return
        self.recoverable()
        record = self.read_journal()
        for row in reversed(record['entries']):
            path = self.path(row['path'])
            before = row['before']
            current = self.link_state(path)
            if current == before or current == row.get('restored', before):
                continue
            if current != row['after']:
                raise ValueError('roundcube_update_link_restore_CAS')
            if before is None:
                path.unlink()
                sync_directory(path.parent)
            else:
                self.replace(path, current, before['target'], record, row, 'restored')
        self.verify_restored()

    def verify_restored(self):
        if self.receipt.exists():
            for row in self.read_journal()['entries']:
                current = self.link_state(self.path(row['path']))
                if current not in (row['before'], row.get('restored', row['before'])):
                    raise ValueError('roundcube_update_link_not_restored:'+row['path'])
