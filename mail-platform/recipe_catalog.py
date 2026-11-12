"""Build install recipe inputs directly from their same-repository public sources."""
import ast
import importlib.util
import json
from pathlib import Path


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def build(repository):
    repository = Path(repository)
    legacy = load(repository / 'mail-management/legacy-smtp-v1/auth-v5/native_candidates.py', 'install_legacy_recipe')
    queries = load(repository / 'mail-management/legacy-smtp-v1/sender-independent-v1/queries.py', 'install_legacy_queries')
    legacy.AUTH_QUERY = queries.AUTH_QUERY
    auth = legacy.auth_candidate('2.4.1', 'mail-legacy-auth').replace(
        '/var/spool/postfix/private/mail-legacy-smtp-auth', '/var/spool/postfix/private/mail-legacy-smtp-v1/auth')
    preferences = load(repository / 'mail-management/deploy/address-preference-queries.py', 'install_address_queries')
    pilot = (repository / 'app-password/dovecot/90-app-password-pilot-safe-v2.conf').read_text(encoding='utf-8')
    start = pilot.index('  passdb_sql_query = ') + len('  passdb_sql_query = ')
    query = pilot[start:pilot.rfind('\n}')].replace('\\\n', ' ').strip()
    query = query.replace("WHERE u.email = 'gmailpoptest@mi-sys.jp'", 'WHERE 1=1')
    query = query.replace("u.email = '%{user}'", "u.id IN (SELECT owner_id FROM mail_management.mail_client_bootstrap_login_owners WHERE BINARY login_name=BINARY LOWER('%{user}') AND active=1)")
    source = (repository / 'mail-management/feature-port-v1/publication-native-v1/native_fixture.py').read_text(encoding='utf-8')
    tree = ast.parse(source)
    node = next(node for node in ast.walk(tree) if isinstance(node, ast.JoinedStr) and any(
        isinstance(part, ast.Constant) and isinstance(part.value, str)
        and part.value.startswith('dovecot_config_version = 2.4.1') for part in node.values))
    pieces = []
    for part in node.values:
        if isinstance(part, ast.Constant):
            pieces.append(part.value)
        elif isinstance(part, ast.FormattedValue) and isinstance(part.value, ast.Name) and part.value.id == 'DATA':
            pieces.append('/var/lib/mail-feature-runtime-v1')
        else:
            raise ValueError('compiler_template_expression')
    compiler = ''.join(pieces)
    ingress = load(repository / 'mail-pop/deploy/prepare-ingress-v2.py', 'install_POP_ingress')
    overrides = ingress.desired_overrides('j {daemon_name} v _')
    for name in list(overrides):
        if name.endswith('/smtpd_milters'):
            overrides[name] = 'unix:/run/rspamd/mail-platform-milter.sock'
    pop_master = ingress.master_fragment(overrides).decode()
    # The new host uses absolute Unix map paths with no smtpd chroot.
    pop_master = pop_master.replace('10027 inet n - y', '10027 inet n - n').replace('pop_cleanup unix n - y', 'pop_cleanup unix n - n')
    ingress_effective={ingress.TAG:{'priority':4,'request_header':{'MTA-Name':'^'+ingress.TAG+'$'},
                       'apply':{'plugins':{'milter_headers':{'routines':['spam-header','x-spam-status']}},
                                'symbols_disabled':['DKIM_SIGNED','ARC_SIGNED']}}}
    ingress.verify_settings({},ingress_effective,4)
    # Copy only the fixed public helper sources, not any production state.
    files = {'etc/mail-legacy-smtp-v1/' + name:
             (repository / 'mail-management/legacy-smtp-v1/deploy-v6' / name).read_bytes()
             for name in ('wait_ready.py', 'runtime_probe.py')}
    forward_source = (repository / 'mail-management/feature-port-v1/configuration-native-v1/configuration_candidates.py').read_text(encoding='utf-8')
    forward_function = next(item for item in ast.parse(forward_source).body
                            if isinstance(item, ast.FunctionDef) and item.name == 'forward_include')
    namespace = {'SCRIPT': 'mail_feature_forward_v1'}
    exec(compile(ast.Module(body=[forward_function], type_ignores=[]), '<public-forward-renderer>', 'exec'), namespace)
    recipe = {
        'legacy_auth': auth, 'legacy_sender_query': queries.SENDER_QUERY,
        'address_preferences': preferences.queries(), 'app_password_query': query,
        'compiler_configuration': compiler,
        'POP_ingress_master': pop_master,
        'POP_ingress_settings': ingress.settings_fragment(4).decode(),
        'POP_ingress_effective': ingress_effective,
        'roundcube_plugins': ['archive', 'zipdownload', 'managesieve',
            'session_epoch_guard', 'local_auth', 'local_auth_gate', 'account_recovery',
            'app_passwords', 'mail_aliases', 'mail_pop', 'local_ja_tweaks', 'junk_digest',
            'local_imap_loopback', 'mail_client_certificates', 'ui_feedback'],
        'postfix_master': '''pickup unix n - n 60 1 pickup
cleanup unix n - n - 0 cleanup
qmgr unix n - n 300 1 qmgr
tlsmgr unix - - n 1000? 1 tlsmgr
rewrite unix - - n - - trivial-rewrite
bounce unix - - n - 0 bounce
defer unix - - n - 0 bounce
trace unix - - n - 0 bounce
verify unix - - n - 1 verify
flush unix n - n 1000? 0 flush
proxymap unix - - n - - proxymap
proxywrite unix - - n - 1 proxymap
smtp unix - - n - - smtp
relay unix - - n - - smtp
showq unix n - n - - showq
error unix - - n - - error
retry unix - - n - - error
discard unix - - n - - discard
local unix - n n - - local
virtual unix - n n - - virtual
lmtp unix - - n - - lmtp
anvil unix - - n - 1 anvil
scache unix - - n - 1 scache
smtpd pass - - n - - smtpd
dnsblog unix - - n - 0 dnsblog
tlsproxy unix - - n - 0 tlsproxy
''',
        'sieve_configuration': '''sieve_script personal {
 driver = file
 path = ~/sieve
 active_path = ~/.dovecot.sieve
}
''' + namespace['forward_include']().decode(),
    }
    files['blueprint/install-recipes.json'] = (json.dumps(recipe, sort_keys=True, indent=2) + '\n').encode()
    return files
