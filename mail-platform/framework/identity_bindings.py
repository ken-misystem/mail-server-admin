"""Rebind audited identity guards without changing unrelated numeric literals."""
import re

from site_bindings import rebase


def rules():
    library = 'usr/local/lib/'
    result = [
        ('etc/mail-legacy-smtp-v1/wait_ready.py',
         's.st_uid==103', 's.st_uid==', 'postfix.uid', 1),
        ('etc/mail-legacy-smtp-v1/wait_ready.py',
         's.st_gid==105', 's.st_gid==', 'postfix.gid', 1),
        (library + 'mail-domain-routing-v1/db_ops.php',
         "$before['gid']===113", "$before['gid']===", 'mailadmin.gid', 1),
        (library + 'mail-management-log-viewer-v1/collector.py',
         'GROUP=113', 'GROUP=', 'mailadmin.gid', 1),
        (library + 'mail-management-log-viewer-v1/collector.py',
         '(0,33)', '(0,', 'www-data.uid', 3),
        (library + 'mail-management-alerts-v1/worker.py',
         '== 113', '== ', 'mailadmin.gid', 3),
        (library + 'mail-management-alerts-v1/worker.py',
         'os.fchown(child, -1, 113)', 'os.fchown(child, -1, ', 'mailadmin.gid', 1),
        (library + 'mail-management-operations-v1/publish_runtime.py',
         'GROUP = 113', 'GROUP = ', 'mailadmin.gid', 1),
        (library + 'mail-protection-admin-v1/runtime/backend_companion.py',
         'value.get("postfix_uid")==103', 'value.get("postfix_uid")==', 'postfix.uid', 1),
        (library + 'mail-protection-admin-v1/runtime/backend_companion.py',
         'value.get("postfix_gid")==105', 'value.get("postfix_gid")==', 'postfix.gid', 1),
        (library + 'mail-protection-admin-v1/fixed_runner.py',
         's.st_gid==111', 's.st_gid==', '_rspamd.gid', 1),
    ]
    for family in ('mail-feature-admin-v1', 'mail-feature-runtime-v1'):
        for filename in ('published_auth.py', 'published_events.py'):
            result.append((library + family + '/' + filename,
                           'group=113', 'group=', 'mailadmin.gid', 2))
    result += [
        ('usr/share/roundcube/plugins/mail_pop/mail_pop.php',
         "$info['gid']!==33", "$info['gid']!==", 'www-data.gid', 1),
        ('usr/share/roundcube/plugins/mail_aliases/mail_aliases.php',
         "$info['gid'] !== 33", "$info['gid'] !== ", 'www-data.gid', 1),
    ]
    application = 'opt/mail-management/candidates/protection-relay-v1/src/InternalAlertsStatus.php'
    for old, prefix in (("self::file($config,0,113,", 'self::file($config,0,'),
                        ("$v['public_gid']===113", "$v['public_gid']==="),
                        ("$v['worker_uid'],113,", "$v['worker_uid'],")):
        result.append((application, old, prefix, 'mailadmin.gid', 1))
    return result


def replacement(old, prefix, number):
    # The suffix belongs to the literal guard's punctuation, never to the ID.
    matched = re.search(r'[0-9]+(?=[^0-9]*$)', old)
    return prefix + str(number) + old[matched.end():]


def bind(files, identities, baseline):
    output = dict(files)
    changed = set()
    for path, old, prefix, name, count in rules():
        number = identities.get(name)
        if type(number) is not int or not 0 < number < 4294967295:
            raise ValueError('identity_input')
        text = output[path].decode('utf-8')
        if text.count(old) != count:
            raise ValueError('identity_source_contract')
        output[path] = text.replace(old, replacement(old, prefix, number)).encode()
        changed.add(path)
    profile = 'usr/local/lib/mail-protection-admin-v1/deployment_profile.py'
    text = output[profile].decode()
    for old, new in (('"Group=111"', '"Group=_rspamd"'),
                     ('"SupplementaryGroups=105 111"', '"SupplementaryGroups=postfix _rspamd"')):
        if text.count(old) != 1:
            raise ValueError('identity_profile_contract')
        text = text.replace(old, new)
    output[profile] = text.encode()
    changed.add(profile)
    for path in ('opt/mail-antivirus-v1/definition_status.py', 'opt/mail-antivirus-v1/identity_guard.py'):
        text = output[path].decode()
        if text.count('os.getegid()==111') != 1:
            raise ValueError('AV_identity_guard_contract')
        number = identities['_rspamd.gid']
        text = text.replace('os.getegid()==111', 'os.getegid()==' + str(number))
        if path.endswith('identity_guard.py'):
            if text.count('["111"]') != 1 or text.count('{"111"}') != 1:
                raise ValueError('AV_group_guard_contract')
            text = text.replace('["111"]', '["' + str(number) + '"]')
            text = text.replace('{"111"}', '{"' + str(number) + '"}')
        output[path] = text.encode()
        changed.add(path)
    for path, raw in list(output.items()):
        if not path.startswith('blueprint/systemd/'):
            continue
        text = raw.decode()
        for directive in ('User', 'Group', 'SupplementaryGroups'):
            def symbolic(match):
                names = []
                section = 'users' if directive == 'User' else 'groups'
                for name in match[1].split():
                    if name.isdecimal():
                        key = int(name)
                        if key not in baseline[section]:
                            raise ValueError('unmapped_unit_identity')
                        name = baseline[section][key]
                    names.append(name)
                return directive + '=' + ' '.join(names)
            text = re.sub(r'^' + directive + r'=(.*)$', symbolic, text, flags=re.MULTILINE)
        output[path] = text.encode()
    return rebase(output, files), sorted(changed)
