"""Debian 13 fresh installation orchestration. Execution requires explicit --apply."""
import getpass
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import sqlite3
import stat
import time
import traceback
try:
    import grp
    import pwd
except ImportError:
    # Planning/tests are also available on the Windows development workstation.
    grp = pwd = None

from components_install import CERTIFICATE, assemble, encoded, recipe, sha
from database_install import execute as install_database, plan as database_plan, principals
from host_transaction import Commands, Files, Transaction, durable_json, regular
from identity_bindings import bind as bind_identities
from profile_bindings import bind as bind_profile
from install_preparation import baseline_identities, read_payload
from site_bindings import bind as bind_site, validate
from release import version
from roundcube_core import render as render_roundcube_core
from roundcube_plugins import PluginLinks, packaged_plugins

PACKAGES = ('postfix', 'postfix-mysql', 'mariadb-server', 'dovecot-core', 'dovecot-imapd',
            'dovecot-pop3d', 'dovecot-lmtpd', 'dovecot-sieve', 'dovecot-managesieved',
            'dovecot-mysql', 'rspamd', 'redis-server', 'nginx', 'php8.4-fpm', 'php8.4-cli',
            'php8.4-mysql', 'php8.4-sqlite3', 'php8.4-mbstring', 'php8.4-intl', 'php8.4-xml',
            'php8.4-curl', 'php8.4-zip', 'roundcube-core', 'roundcube-plugins', 'fail2ban',
            'postsrsd', 'rsyslog', 'libsasl2-modules', 'python3-cryptography', 'openssl', 'ca-certificates',
            'curl', 'ufw', 'fetchmail', 'php-net-smtp', 'php-net-sieve', 'bind9-dnsutils')
CUSTOM_USERS = ('mailadmin', 'mailpop', 'vmail', 'mailalerts', 'mailantivirus', 'mailsendlimits',
                'mail-route-collector', 'mail-route-map', 'mail-legacy-auth',
                'mailcert-owner', 'mailcert-lifecycle', 'mailcert-verifier', 'mailcert-issuer', 'mailcert-gate')
LEGACY_UNITS = frozenset(('mail-pop-account1.service', 'mail-pop-account1.timer',
                          'mail-residual-pop-v1.service', 'mail-residual-pop-v1.timer'))
BASE_SERVICES = ('mariadb.service', 'redis-server.service', 'rsyslog.service', 'dovecot.service',
                 'rspamd.service', 'postsrsd.service', 'postfix.service', 'php8.4-fpm.service',
                 'nginx.service', 'fail2ban.service', 'ufw.service')
PERSISTENT = ('mail-legacy-smtp-auth.service', 'mail-quota-collect-v1.service',
              'mail-feature-config-v1.service', 'mail-protection-clamav-v1.service')


def plan(product, site):
    validate(site)
    units = sorted(path.name for path in (Path(product) / 'payload/blueprint/systemd').iterdir()
                   if path.name not in LEGACY_UNITS)
    return {'target': 'Debian 13 amd64', 'phase_order': [
        'environment_check', 'preflight', 'packages', 'identities', 'assemble', 'database', 'files', 'native_package', 'native_validation',
        'administrator', 'isolated_UI_start', 'isolated_health'], 'packages': list(PACKAGES), 'custom_users': list(CUSTOM_USERS),
        'public_activation': 'separate_root_publish_after_verified_passkey_and_password_rotation',
        'initial_UI': '127.0.0.1:443 over an administrator-controlled HTTPS tunnel',
        'units': units, 'host_changes': False, 'empty_OS_test': 'deferred',
        'failure_behavior': 'CAS_restore_config_keep_DB_mail_credentials_history',
        'site': site}


def read_kit(directory):
    directory = Path(directory).resolve(strict=True)
    info = directory.stat()
    if info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError('private_kit_directory')
    raw, _ = regular(directory / 'kit.json')
    value = json.loads(raw)
    if set(value) != {'version', 'files', 'dovecot_packages'} or value['version'] != 1:
        raise ValueError('kit_schema')
    files = {}
    for name, entry in value['files'].items():
        if set(entry) != {'path', 'sha256'} or not re.fullmatch('[a-z][a-z0-9_]{0,63}', name):
            raise ValueError('kit_entry')
        path = Path(entry['path'])
        if path.is_absolute() or '..' in path.parts or '\\' in str(path):
            raise ValueError('kit_path')
        for parent in (directory / path).parents:
            if parent == directory:
                break
            if parent.is_symlink():
                raise ValueError('kit_parent_link')
        raw, metadata = regular(directory / path, limit=268435456)
        if metadata['sha256'] != entry['sha256'] or metadata['uid'] != 0 or metadata['mode'] & 0o077:
            raise ValueError('kit_file_pin_or_permissions')
        files[name] = {'bytes': raw, 'path': str(directory / path), 'sha256': entry['sha256']}
    required = {'tls_certificate', 'tls_key', 'root', 'issuer', 'root_crl', 'custody', 'restoration',
                'custody_statement', 'issuer_key', 'issuer_password', 'guard', 'release_public_key',
                'clamav_runtime_manifest', 'definition_main', 'definition_daily', 'definition_bytecode', 'github_token',
                'sieve_session_lock', 'sieve_session_lock_metadata'}
    if not required <= set(files):
        raise ValueError('kit_required_resources')
    packages = value['dovecot_packages']
    if not packages or any(name not in files for name in packages):
        raise ValueError('kit_dovecot_packages')
    return value, files


class Installer:
    def __init__(self, product, site, kit, evidence, resolvers=()):
        self.product = Path(product)
        version_file = self.product/'product-version.json'
        self.product_version = json.loads(version_file.read_bytes())['version'] if version_file.exists() else '0.1.0'
        version(self.product_version)
        self.payload = self.product / 'payload'
        self.site = validate(site)
        self.kit_path = Path(kit)
        self.evidence = Path(evidence)
        self.transaction = None
        self.files = None
        self.commands = None
        self.started = []
        self.policy_original = None
        self.resolvers = tuple(resolvers)
        self.activation_attempted = False

    def preflight(self):
        report = self.check_environment()
        if report['status'] != 'PASS':
            from environment_check import record_report
            record_report(self.evidence, report)
            raise ValueError('environment_check_refused_see_environment_check_json')
        import ipaddress
        if not ipaddress.ip_address(self.site['public_ipv4']).is_global:
            raise ValueError('site_public_IPv4_required')
        if os.name != 'posix' or os.geteuid() != 0:
            raise ValueError('Debian_root_required')
        release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
        if release.get('ID', '').strip('"') != 'debian' or release.get('VERSION_ID', '').strip('"') != '13':
            raise ValueError('Debian13_required')
        if os.uname().machine != 'x86_64':
            raise ValueError('amd64_required')
        if any(Path(path).exists() for path in ('/var/vmail', '/etc/mail-management',
                '/var/lib/mail-platform-install', '/etc/postfix/main.cf', '/etc/dovecot/dovecot.conf',
                '/etc/nginx/nginx.conf', '/etc/roundcube/config.inc.php', '/var/lib/mysql/mysql', '/var/lib/mail-platform-setup')):
            raise ValueError('existing_mail_installation')
        if not self.evidence.is_absolute() or self.evidence.exists() or self.evidence.is_symlink():
            raise ValueError('new_evidence_directory_required')
        for parent in self.evidence.parents:
            info = parent.lstat()
            if parent.is_symlink() or info.st_uid != 0 or (info.st_mode & 0o022 and not info.st_mode & 0o1000):
                raise ValueError('evidence_parent_trust')
        self.kit, self.inputs = read_kit(self.kit_path)
        if getattr(self,'acme_config',None) is not None:
            from acme_lifecycle import validate as validate_ACME
            from certificate_state import trusted
            self.acme=validate_ACME(json.loads(trusted(self.acme_config,private=True)[0]))
            if self.acme['host']!=self.site['mail_host']:
                raise ValueError('ACME_site_hostname_mismatch')
        self.transaction = Transaction(self.evidence)
        durable_json(self.evidence/'environment-check.json', report)
        self.commands = Commands(self.evidence)
        self.files = Files('/', self.evidence)
        # Fresh install does not adopt any local account with a custom role name.
        for name in CUSTOM_USERS:
            try:
                pwd.getpwnam(name)
            except KeyError:
                continue
            raise ValueError('custom_role_already_exists')
        if Path('/usr/sbin/policy-rc.d').exists():
            raise ValueError('existing_service_start_policy')
        self.files.write('/usr/sbin/policy-rc.d', b'#!/bin/sh\nexit 101\n', 0o755)
        from setup_access import install_barriers
        install_barriers(plan(self.product, self.site)['units'], BASE_SERVICES)
        self.commands.run('setup_barrier_reload', ['/usr/bin/systemctl', 'daemon-reload'])

    def check_environment(self):
        from environment_check import inspect
        return inspect(self.product, self.site, CUSTOM_USERS, self.evidence)

    def packages(self):
        self.commands.run('APT_index', ['/usr/bin/apt-get', 'update'], timeout=300)
        custom = []
        observed = set()
        for name in self.kit['dovecot_packages']:
            path = self.inputs[name]['path']
            out = self.commands.run('deb_metadata_' + name,
                ['/usr/bin/dpkg-deb', '-f', path, 'Package', 'Version', 'Architecture'])
            fields = dict(line.split(': ', 1) for line in out.decode().splitlines())
            if (not fields.get('Package', '').startswith('dovecot-')
                    or fields.get('Version') != '1:2.4.1+dfsg1-6+deb13u7+cnfix1'
                    or fields.get('Architecture') not in ('amd64', 'all')):
                raise ValueError('custom_Dovecot_metadata')
            observed.add(fields['Package'])
            custom.append(path)
        required = {name for name in PACKAGES if name.startswith('dovecot-')}
        if not required <= observed:
            raise ValueError('custom_Dovecot_package_inventory')
        selected_packages=list(PACKAGES)
        if getattr(self,'acme',None) is not None:
            from acme_lifecycle import PROVIDERS
            selected_packages+=['certbot',PROVIDERS[self.acme['provider']]]
        ordinary = [name for name in selected_packages if name not in observed]
        from native_package_update import DESCRIPTOR, descriptor
        if (self.payload/DESCRIPTOR).is_file():
            offer = descriptor(self.payload)
            ordinary.remove('rspamd')
            custom.append(str(self.payload/Path(DESCRIPTOR).parent/offer['candidate']['archive']))
        policies = self.commands.run('APT_candidates', ['/usr/bin/apt-cache', 'policy', *ordinary]).decode()
        selected = {}
        package = None
        for line in policies.splitlines():
            if line and not line[0].isspace() and line.endswith(':'):
                package = line[:-1]
            elif line.strip().startswith('Candidate:'):
                selected[package] = line.split(':', 1)[1].strip()
        if set(selected) != set(ordinary) or any(value == '(none)' for value in selected.values()):
            raise ValueError('APT_candidate_missing')
        arguments = [name + '=' + selected[name] for name in ordinary] + custom
        simulation = self.commands.run('APT_simulation',
            ['/usr/bin/apt-get', '--simulate', '--no-remove', 'install', *arguments], timeout=180)
        if any(line.startswith(b'Remv ') for line in simulation.splitlines()):
            raise ValueError('APT_removal_proposed')
        selections = ('postfix postfix/main_mailer_type select No configuration\n'
                      'postfix postfix/mailname string ' + self.site['mail_host'] + '\n'
                      'roundcube-core roundcube/dbconfig-install boolean false\n')
        self.commands.run('package_configuration_policy', ['/usr/bin/debconf-set-selections'], selections.encode())
        self.commands.run('APT_install', ['/usr/bin/apt-get', '-y', '--no-remove',
                          '-o', 'Dpkg::Options::=--force-confold', 'install', *arguments], timeout=1200)
        installed = self.commands.run('installed_versions', ['/usr/bin/dpkg-query', '-W',
                                      '-f=${Package}\t${Version}\t${Architecture}\n', *selected_packages])
        durable_json(self.evidence / 'installed-packages.json', {'rows': installed.decode().splitlines()})

    def identities(self):
        for name in CUSTOM_USERS:
            try:
                grp.getgrnam(name)
            except KeyError:
                self.commands.run('group_' + name.replace('-', '_'), ['/usr/sbin/groupadd', '--system', name])
            self.commands.run('user_' + name.replace('-', '_'), ['/usr/sbin/useradd', '--system',
                '--no-create-home', '--gid', name, '--shell', '/usr/sbin/nologin', name])
        self.commands.run('Roundcube_group', ['/usr/sbin/usermod', '--append', '--groups', 'mailcert-owner', 'www-data'])
        self.ids = {}
        for name in CUSTOM_USERS + ('postfix', '_rspamd', 'www-data'):
            account = pwd.getpwnam(name)
            self.ids[name + '.uid'] = account.pw_uid
            self.ids[name + '.gid'] = account.pw_gid
        self.ids['_rspamd.groups'] = sorted(os.getgrouplist('_rspamd', self.ids['_rspamd.gid']))
        durable_json(self.evidence / 'identities.json', self.ids)

    def register_native_package(self):
        from native_package_update import DESCRIPTOR, NativePackage
        if (self.payload/DESCRIPTOR).is_file():
            engine = NativePackage(self.payload,self.evidence/'native-package')
            result = engine.plan()
            if result['package_change'] or engine.record['before_unit']['ActiveState'] != 'inactive':
                raise ValueError('fresh_native_package_not_closed_candidate')
            engine.stage();engine.activate();engine.health()

    def assemble(self):
        metadata = json.loads((self.payload / 'blueprint/grants.json').read_bytes())
        names = set(principals(metadata)) | {'management_application', 'roundcube_session', 'postsrsd_secret'}
        self.passwords = {name: secrets.token_hex(32) for name in sorted(names)}
        durable_json(self.evidence / 'generated-credentials.json', self.passwords)
        self.bound = bind_site(read_payload(self.payload), self.site)
        self.bound, guards = bind_identities(self.bound, self.ids, baseline_identities(self.payload))
        self.bound = bind_profile(self.bound)
        staged = self.evidence / 'bound'
        staged.mkdir(mode=0o700)
        for name, raw in self.bound.items():
            path = staged / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.staged = staged
        from sieve_lock import resources as sieve_lock_resources
        sieve_resources = sieve_lock_resources(self.inputs, (staged/'blueprint/native-sources/sieve_session_lock.c').read_bytes())
        certificate = staged / CERTIFICATE.lstrip('/')
        self.bound[CERTIFICATE.lstrip('/') + '/guard.so'] = self.inputs['guard']['bytes']
        manifest = json.loads((certificate / 'runtime-manifest.json').read_bytes())
        manifest['pins'] = {name: sha((certificate / name).read_bytes()) for name in manifest['pins']}
        manifest['guard_pin'] = self.inputs['guard']['sha256']
        manifest['python_pin'] = sha(Path('/usr/bin/python3').resolve().read_bytes())
        manifest['openssl_pin'] = sha(Path('/usr/bin/openssl').read_bytes())
        manifest['php_pin'] = sha(Path('/usr/bin/php8.4').read_bytes())
        raw = encoded(manifest)
        self.bound[CERTIFICATE.lstrip('/') + '/runtime-manifest.json'] = raw
        namespace = Path('/proc/1/ns/net').stat()
        ca = {name: {'path': '/var/lib/mail-platform-pki/' + name, 'sha256': self.inputs[name]['sha256']}
              for name in ('root', 'issuer', 'root_crl', 'custody', 'restoration', 'custody_statement')}
        install_recipes=json.loads((staged/'blueprint/install-recipes.json').read_bytes())
        settings_pin=sha(json.dumps(install_recipes['POP_ingress_effective'],sort_keys=True,separators=(',',':')).encode())
        native = {'ca': ca, 'executables': {'smtpd': sha(Path('/usr/lib/postfix/sbin/smtpd').read_bytes())},
                  'certificate_manifest_sha256': sha(raw), 'host_namespace': [namespace.st_dev, namespace.st_ino],
                  'settings_sha256': settings_pin,
                  'owner_lifecycle_activation_cutoff': int(self.transaction.value['started'])}
        native['executable_paths'] = {}
        for name, path in (('python', '/usr/bin/python3'), ('openssl', '/usr/bin/openssl'), ('php', '/usr/bin/php8.4')):
            resolved = Path(path).resolve(strict=True)
            _, metadata = regular(resolved)
            if metadata['uid'] != 0 or metadata['mode'] & 0o022 or not metadata['mode'] & 0o111:
                raise ValueError('native_executable_permissions')
            native['executable_paths'][name] = str(resolved)
        durable_json(self.evidence / 'native-executable-paths.json', native['executable_paths'])
        native['actor_gids'] = {}
        native['actor_groups'] = {}
        for actor in ('owner', 'lifecycle', 'verifier', 'issuer', 'gate'):
            unit = self.bound['blueprint/systemd/mail-client-cert-' + actor + '.service'].decode()
            matches = re.findall(r'^Group=(\S+)$', unit, re.M)
            if len(matches) != 1:
                raise ValueError('actor_primary_group_inventory')
            native['actor_gids'][actor] = grp.getgrnam(matches[0]).gr_gid
            native['actor_groups'][actor] = matches[0]
        self.resources = assemble(staged, self.site, self.ids, self.passwords, native) + sieve_resources
        self.bound.update(render_roundcube_core(self.bound,lambda name:regular(Path(name))))
        resolvers = []
        import ipaddress
        for item in self.resolvers:
            value = ipaddress.ip_address(item)
            if not value.is_global:
                raise ValueError('public_DNS_resolver')
            resolvers.append(str(value))
        for line in (() if resolvers else Path('/etc/resolv.conf').read_text().splitlines()):
            parts = line.split()
            if len(parts) >= 2 and parts[0] == 'nameserver':
                value = ipaddress.ip_address(parts[1])
                if value.is_global:
                    resolvers.append(str(value))
        if not resolvers:
            raise ValueError('public_DNS_resolver_input_required')
        from base_configuration import Resource
        import base64
        resolver_configuration=recipe(staged,'public_dns',{'servers':resolvers})
        self.resources.append(Resource('/etc/mail-domain-routing-v1/public-resolv.conf',
                                       base64.b64decode(resolver_configuration['configuration'],validate=True)))
        self.compiled_database = database_plan(self.payload, self.passwords)
        durable_json(self.evidence / 'assembly.json', {'code_files': len(self.bound),
                     'configuration_files': len(self.resources), 'guard_sources': guards,
                     'database_steps': len(self.compiled_database['steps'])})

    def database(self):
        self.commands.run('start_MariaDB', ['/usr/bin/systemctl', 'start', 'mariadb.service'])
        self.started.append('mariadb.service')
        paths = [Path('/usr/share/dbconfig-common/data/roundcube/install/mysql'),
                 Path('/usr/share/roundcube/SQL/mysql.initial.sql')]
        source = next((path for path in paths if path.is_file()), None)
        if source is None:
            raise ValueError('Roundcube_package_schema_missing')
        install_database(self.compiled_database, self.commands, self.transaction, source.read_text(encoding='utf-8'))

    def write_files(self):
        from monitor_environment import MONITOR_CONFIG
        if os.path.lexists(self.files.target(MONITOR_CONFIG)):
            raise ValueError('fresh_install_existing_monitor_environment_requires_adoption')
        for name, raw in self.bound.items():
            if name.startswith('blueprint/'):
                continue
            from code_attributes import attributes
            metadata = attributes('/' + name, self.ids)
            self.files.write('/' + name, raw, metadata['mode'], uid=metadata['uid'], gid=metadata['gid'])
        for resource in self.resources:
            group = grp.getgrnam(resource.group).gr_gid
            from setup_access import WEB, local_web
            raw = local_web(resource.raw) if resource.path == WEB else resource.raw
            self.files.write(resource.path, raw, resource.mode, gid=group, preserve=resource.preserve)
        nginx, _ = regular('/etc/nginx/nginx.conf')
        for anchor, replacement in [
            (b'include /etc/nginx/sites-enabled/*;', b'include /etc/nginx/sites-enabled/mail-platform.conf;'),
            (b'include /etc/nginx/conf.d/*.conf;', b'# Optional server snippets are disabled by the fresh-site installer.')]:
            if nginx.count(anchor) != 1:
                raise ValueError('initial_nginx_include_requires_review')
            nginx = nginx.replace(anchor, replacement)
        self.files.write('/etc/nginx/nginx.conf', nginx)
        for name, raw in self.bound.items():
            if name.startswith('blueprint/systemd/') and Path(name).name not in LEGACY_UNITS:
                self.files.write('/etc/systemd/system/' + Path(name).name, raw)
        # The suppressed package configuration has not initialized queue ownership.
        # Apply the installed Postfix package's own postfix-files permission table.
        self.commands.run('Postfix_package_permissions', ['/usr/sbin/postfix', 'set-permissions'])
        self.install_private_assets()
        self.initialize_state()
        if getattr(self,'acme_config',None) is not None:
            from acme_lifecycle import configure
            configure(self.acme_config,self.commands,self.files,enable=False)
        PluginLinks(self.files.root, self.evidence / 'roundcube-plugin-links.json').apply(packaged_plugins(self.bound))
        # Reuse the existing public certificate preparation before enabling its marker.
        self.commands.run('preparation_systemd_reload', ['/usr/bin/systemctl', 'daemon-reload'])
        self.commands.run('prepare_TLS_bundle', ['/usr/bin/systemctl', 'start', 'mail-client-cert-health.service'])

    def install_private_assets(self):
        for name in ('root', 'issuer', 'root_crl', 'custody', 'restoration', 'custody_statement'):
            self.files.write('/var/lib/mail-platform-pki/' + name, self.inputs[name]['bytes'], preserve=True)
        for name in ('issuer_key', 'issuer_password'):
            self.files.write('/var/lib/mail-client-certificates-v1/credentials/issuer/' + name,
                             self.inputs[name]['bytes'], 0o600, preserve=True)
        self.files.write('/var/lib/mail-client-certificates-v1/credentials/issuer/issuer_certificate',
                         self.inputs['issuer']['bytes'], 0o600, preserve=True)
        self.files.write('/etc/mail-platform/release-public.pem', self.inputs['release_public_key']['bytes'], preserve=True)
        self.files.write('/etc/mail-platform/private/github-token', self.inputs['github_token']['bytes'],
                         0o600, preserve=True)
        self.install_tls_sources()
        self.files.write('/var/lib/mail-platform-update/update.lock',b'',0o600,preserve=True)
        # Native runtime files are a bounded, pinned flat file inventory in the kit.
        manifest = json.loads(self.inputs['clamav_runtime_manifest']['bytes'])
        if set(manifest) != {'files'} or not 1 <= len(manifest['files']) <= 128:
            raise ValueError('AV_runtime_inventory')
        pins = {}
        for member, name in manifest['files'].items():
            if not member.startswith('usr/local/') or '..' in Path(member).parts or name not in self.inputs:
                raise ValueError('AV_runtime_member')
            mode = 0o755 if '/bin/' in member or '/sbin/' in member else 0o644
            self.files.write('/opt/mail-antivirus-v1/runtime/' + member, self.inputs[name]['bytes'], mode)
            pins['/' + member] = self.inputs[name]['sha256']
        self.files.write('/etc/mail-antivirus-v1/runtime-pins.json', encoded(pins))
        for name in ('main', 'daily', 'bytecode'):
            value = self.inputs['definition_' + name]
            self.files.write('/var/lib/mail-antivirus-v1/definitions/' + name + '.cvd', value['bytes'],
                             0o640, self.ids['mailantivirus.uid'], self.ids['_rspamd.gid'], preserve=True)

    def install_tls_sources(self):
        # Retain the numbered archive and relative live links checked by the monitor.
        host = self.site['mail_host']
        from certificate_state import private_directory
        private_directory('/var/lib/mail-platform-certificates')
        private_directory('/var/lib/mail-platform-acme')
        self.files.write('/etc/mail-platform/certificates.json',encoded({'format':1,'profile':'production',
            'host':host,'probe_address':self.site['public_ipv4'],'trust_store':'/etc/ssl/certs/ca-certificates.crt'}),0o600)
        for name, stem in (('tls_certificate', 'fullchain'), ('tls_key', 'privkey')):
            archive = stem + '1.pem'
            self.files.write('/etc/letsencrypt/archive/' + host + '/' + archive,
                             self.inputs[name]['bytes'], 0o600, preserve=True)
            link = Path('/etc/letsencrypt/live') / host / (stem + '.pem')
            link.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if os.path.lexists(link):
                raise ValueError('TLS_live_source_exists')
            os.symlink('../../archive/' + host + '/' + archive, link)

    def initialize_state(self):
        directory_roles = {
            '/var/lib/roundcube/mail-settings-locks': ('www-data', 'www-data', 0o700),
            '/var/vmail': ('vmail', 'vmail', 0o750), '/var/lib/mail-management': ('mailadmin', 'mailadmin', 0o700),
            '/var/lib/mail-client-cert-issuer-v1': ('mailcert-issuer', 'mailcert-issuer', 0o700),
            '/var/lib/mail-feature-admin-v1': ('root', 'root', 0o700),
            '/var/lib/mail-feature-admin-v1/diagnostics': ('root', 'root', 0o700),
            '/var/lib/mail-feature-admin-v1/public-stops': ('root', 'mailsendlimits', 0o750),
            '/var/lib/mail-feature-runtime-v1': ('root', 'root', 0o700),
            '/var/lib/mail-feature-runtime-v1/diagnostics': ('root', 'root', 0o700),
            '/var/lib/mail-feature-runtime-v1/compiler': ('root', 'root', 0o700),
            '/var/lib/mail-feature-runtime-v1/compiler/run': ('root', 'root', 0o700),
            '/var/lib/mail-feature-runtime-v1/compiler/state': ('root', 'root', 0o700),
            '/var/lib/mail-feature-runtime-v1/compiler/mail': ('root', 'root', 0o700),
            '/var/lib/mail-feature-public-v1/sieve': ('root', 'vmail', 0o750),
            '/var/lib/mail-antivirus-v1': ('mailantivirus', '_rspamd', 0o750),
            '/var/lib/mail-antivirus-v1/definitions': ('mailantivirus', '_rspamd', 0o750),
            '/var/lib/mail-protection-admin-v1': ('root', 'root', 0o700),
            '/var/lib/mail-protection-admin-v1/transactions': ('root', 'root', 0o700),
            '/var/lib/mail-pop': ('mailpop', 'mailpop', 0o700),
            '/var/lib/mail-pop/accounts': ('mailpop', 'mailpop', 0o700),
            '/var/lib/mail-pop/locks': ('mailpop', 'mailpop', 0o700),
            '/var/log/roundcube': ('www-data', 'www-data', 0o750),
            '/var/spool/postfix/private/mail-legacy-smtp-v1': ('postfix', 'postfix', 0o750),
            '/var/lib/mail-send-limits-v1': ('mailsendlimits', 'mailsendlimits', 0o700),
            '/var/lib/mail-domain-routing-v1': ('mail-route-collector', 'mail-route-collector', 0o755),
            '/var/lib/mail-junk-digest-general-v1': ('root', 'root', 0o700),
            '/var/lib/mail-management-alerts-v1': ('mailalerts', 'mailalerts', 0o700),
            '/var/lib/mail-management-alerts-public-v1': ('mailalerts', 'mailadmin', 0o750),
            '/var/lib/mail-management-log-viewer-v1': ('root', 'mailadmin', 0o750),
            '/var/lib/mail-management-log-viewer-v1/private': ('root', 'root', 0o700),
            '/var/lib/mail-management-log-viewer-v1/published': ('root', 'mailadmin', 0o750),
            '/var/lib/mail-management-log-viewer-v1/published/pages': ('root', 'mailadmin', 0o750),
            '/var/lib/mail-management-operations-v1': ('root', 'mailadmin', 0o750),
            '/var/lib/mail-quota-v1': ('root', 'mailadmin', 0o750),
            '/var/lib/mail-quota-v1/private': ('root', 'root', 0o700),
        }
        for name, (user, group, mode) in directory_roles.items():
            path = Path(name)
            if path.is_symlink():
                raise ValueError('state_directory_link')
            path.mkdir(mode=mode, parents=True, exist_ok=True)
            os.chown(path, pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid)
            os.chmod(path, mode)
        for name, owner, group in (('/var/log/roundcube/errors.log', 'www-data', 'www-data'),
                                   ('/var/log/mail.log', 'root', 'adm'),
                                   ('/var/log/fail2ban.log', 'root', 'root')):
            if not os.path.lexists(name):
                uid, gid = pwd.getpwnam(owner).pw_uid, grp.getgrnam(group).gr_gid
                if uid:
                    self.files.create_state(name, b'', uid, gid)
                else:
                    self.files.write(name, b'', 0o640, uid, gid, preserve=True)
        path = Path('/var/lib/mail-feature-admin-v1/controls.sqlite')
        if path.exists():
            raise ValueError('controls_state_exists')
        connection = sqlite3.connect(path)
        try:
            connection.execute('PRAGMA synchronous=FULL')
            connection.executescript((self.payload / 'usr/local/lib/mail-protection-admin-v1/schema.sql').read_text())
            defaults = recipe(self.payload, 'protection', {})
            with connection:
                for kind in ('scanner', 'upstream'):
                    connection.execute('INSERT INTO protection_settings '
                        '(kind,revision,payload,private_credential,applied_revision,phase,failure_code) '
                        "VALUES (?,1,?,NULL,1,'applied',NULL)", (kind, encoded(defaults[kind]).decode()))
        finally:
            connection.close()
        os.chmod(path, 0o600)
        code = "$k=sodium_crypto_box_keypair();file_put_contents($argv[1].'/pop-keypair',$k,LOCK_EX);file_put_contents($argv[1].'/pop-public',sodium_crypto_box_publickey($k),LOCK_EX);sodium_memzero($k);"
        self.commands.run('POP_sealed_box_keys', ['/usr/bin/php8.4', '-d', 'display_errors=0',
                          '-d', 'log_errors=0', '-r', code, str(self.evidence)])
        self.files.write('/etc/mail-pop/keypair.bin', (self.evidence / 'pop-keypair').read_bytes(),
                         0o640, gid=self.ids['mailpop.gid'], preserve=True)
        self.files.write('/etc/roundcube/mail-pop-public.key', (self.evidence / 'pop-public').read_bytes(),
                         0o640, gid=self.ids['www-data.gid'], preserve=True)
        self.initialize_dkim()

    def initialize_dkim(self):
        from dkim_readiness import Reconcile
        evidence = self.evidence/'dkim'
        evidence.mkdir(mode=0o700)
        Reconcile(self.files.root, evidence, commands=self.commands).apply(self.site, self.ids)

    def native_validation(self):
        self.commands.run('TLS_hostname_chain', ['/usr/bin/openssl', 'verify', '-verify_hostname',
            self.site['mail_host'], '-CAfile', '/etc/ssl/certs/ca-certificates.crt',
            '-untrusted', self.inputs['tls_certificate']['path'], self.inputs['tls_certificate']['path']])
        key = self.commands.run('release_trust_key', ['/usr/bin/openssl', 'pkey', '-pubin',
            '-in', '/etc/mail-platform/release-public.pem', '-text', '-noout'])
        if b'ED25519' not in key:
            raise ValueError('Ed25519_release_key_required')
        outputs={}
        for label, args in [('Postfix_main', ['/usr/sbin/postconf', '-n']),
                            ('Postfix_master', ['/usr/sbin/postconf', '-M']),
                            ('Dovecot', ['/usr/bin/doveconf', '-n']),
                            ('Rspamd', ['/usr/sbin/runuser', '-u', '_rspamd', '--', '/usr/bin/rspamadm', 'configtest']),
                            ('nginx', ['/usr/sbin/nginx', '-t']),
                            ('FPM', ['/usr/sbin/php-fpm8.4', '-t'])]:
            outputs[label]=self.commands.run('native_' + label, args)
        backend=self.commands.run('native_Dovecot_backend',['/usr/bin/doveconf','-c',
                                  '/etc/mail-client-certificates-v1/dovecot-backend.conf','-n'])
        quota_root=Path('/usr/local/lib/mail-quota-v1')
        quota_artifacts={name:sha((quota_root/name).read_bytes()) for name in ('runtime.py','binding.py','collector_core.py')}
        quota_split={name:sha((quota_root/name).read_bytes()) for name in ('split_core.py','split_runtime.py','cold_exec.py','scale_core.py')}
        quota_effective=[sha(outputs['Dovecot']),sha(backend)]
        quota_generation=sha(encoded({'artifacts':quota_artifacts,'split_sources':quota_split,'effective_hashes':quota_effective}))
        self.files.write(str(quota_root/'deployment.json'),encoded({'version':1,
            'deployment_hash':quota_generation,'initial_applied':{},'artifact_pins':quota_artifacts,
            'effective_hashes':quota_effective,'split_policy':{'revision':1,'period':12,'warm_budget':9,'cold_budget':30},
            'split_sources':quota_split}),0o600)
        self.files.write(str(quota_root/'public-binding.json'),encoded({'version':1,
                         'deployment_hash':quota_generation}),0o644)
        settings = self.commands.run('settings_canonical', ['/usr/sbin/runuser', '-u', '_rspamd', '--',
                                      '/usr/bin/rspamadm', 'configdump', 'settings', '-j'])
        if (self.evidence/self.commands.records[-1]['stderr']).stat().st_size:
            raise ValueError('native_Rspamd_settings_stderr')
        value = json.loads(settings)
        canonical = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        self.files.write('/etc/mail-feature-runtime-v1/deployment.json',
                         encoded({'version': 1, 'legacy_settings_sha256': sha(canonical)}), 0o600)
        units = [str(Path('/etc/systemd/system') / name) for name in plan(self.product, self.site)['units']]
        self.commands.run('native_units', ['/usr/bin/systemd-analyze', 'verify', *units])
        paths = {}
        for unit in units:
            for line in Path(unit).read_text().splitlines():
                if not line.startswith(('ReadWritePaths=', 'ReadOnlyPaths=', 'InaccessiblePaths=', 'WorkingDirectory=')):
                    continue
                for name in shlex.split(line.split('=', 1)[1]):
                    if name.startswith('/') and not name.startswith('/run/') and '%' not in name:
                        paths.setdefault(name, []).append(Path(unit).name)
        missing = [name for name in paths if not Path(name).exists()]
        durable_json(self.evidence / 'native-unit-input-paths.json', {'paths': paths, 'missing': missing})
        if missing:
            raise ValueError('unit_input_paths_missing')

    def administrator(self, email, password, repeat):
        if password != repeat:
            raise ValueError('administrator_password_confirmation')
        output = self.commands.run('bootstrap_administrator', ['/usr/bin/php8.4', '-d', 'display_errors=0',
            '-d', 'log_errors=0', '/usr/local/lib/mail-platform-update/bootstrap_admin_secure.php'],
            encoded({'email': email, 'password': password, 'repeat': repeat}))
        result = json.loads(output)
        if result.get('status') != 'ok':
            raise ValueError('administrator_bootstrap')
        from setup_access import ACCESS, access_metadata
        durable_json(ACCESS, access_metadata(result['administrator']), mode=0o640, gid=self.ids['mailadmin.gid'])

    def start(self):
        from setup_access import STATE
        self.activation_attempted = True
        if self.files.restore(['/usr/sbin/policy-rc.d'])['status'] != 'restored':
            raise ValueError('package_start_policy_restoration')
        self.commands.run('setup_systemd_reload', ['/usr/bin/systemctl', 'daemon-reload'])
        blocked = sorted(set(plan(self.product, self.site)['units']) | (set(BASE_SERVICES)-{'mariadb.service', 'php8.4-fpm.service', 'nginx.service'}))
        self.commands.run('disable_unpublished_units', ['/usr/bin/systemctl', 'disable', '--quiet', *blocked])
        durable_json(STATE, {'format': 1, 'phase': 'setup', 'site': self.site})
        for name in ['php8.4-fpm.service', 'nginx.service']:
            self.started.append(name)
            self.commands.run('setup_start_'+name.replace('.', '_').replace('-', '_'), ['/usr/bin/systemctl', 'start', name])
        self.commands.run('enable_setup_UI', ['/usr/bin/systemctl', 'enable', '--quiet',
                                           'mariadb.service', 'php8.4-fpm.service', 'nginx.service'])
        if getattr(self,'acme_config',None) is not None:
            self.commands.run('enable_setup_DNS01_renewal',['/usr/bin/systemctl','enable','--now','mail-platform-acme.timer'])
            self.started.append('mail-platform-acme.timer')

    def activate_public_services(self):
        self.activation_attempted = True
        if self.files.restore(['/usr/sbin/policy-rc.d'])['status'] != 'restored':
            raise ValueError('package_start_policy_restoration')
        self.commands.run('systemd_reload', ['/usr/bin/systemctl', 'daemon-reload'])
        # bootstrap disable removes the package's syslog.service alias as well.
        self.commands.run('restore_rsyslog_alias', ['/usr/bin/systemctl', 'enable', '--quiet', 'rsyslog.service'])
        # TLS preparation, schema and native syntax have completed before markers.
        self.files.write('/etc/mail-client-certificates-v1/private-backends-approved.json',
                         encoded({'version': 1, 'installer_transaction': self.evidence.name}))
        self.files.write('/etc/mail-client-certificates-v1/activation-approved.json',
                         encoded({'version': 1, 'installer_transaction': self.evidence.name}))
        units = plan(self.product, self.site)['units']
        sockets = [name for name in units if name.endswith('.socket')]
        for name in sockets + ['mail-legacy-smtp-auth.service'] + list(BASE_SERVICES):
            self.started.append(name)
            self.commands.run('start_' + name.replace('.', '_').replace('-', '_'),
                              ['/usr/bin/systemctl', 'start', name], timeout=180)
        deadline = time.monotonic() + 30
        observed = None
        while True:
            try:
                info = Path('/run/rspamd/mail-platform-milter.sock').lstat()
                observed = {'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode),
                            'socket': stat.S_ISSOCK(info.st_mode)}
            except FileNotFoundError:
                pass
            durable_json(self.evidence / 'Rspamd-milter-readiness.json', {'observed': observed})
            if observed == {'uid': self.ids['_rspamd.uid'], 'gid': self.ids['postfix.gid'],
                            'mode': 0o660, 'socket': True}:
                break
            if time.monotonic() >= deadline:
                raise ValueError('Rspamd_milter_socket_attributes' if observed else 'Rspamd_milter_socket_not_ready')
            time.sleep(0.1)
        self.commands.run('certificate_stack', ['/usr/bin/systemctl', 'start', 'mail-client-certificates.target'])
        self.started.append('mail-client-certificates.target')
        for name in ('mail-management-log-viewer.service', 'mail-feature-config-v1.service',
                     'mail-domain-routing-collect.service', 'mail-quota-collect-v1.service',
                     'mail-protection-clamav-v1.service', 'mail-protection-definitions-v1.service'):
            self.commands.run('initial_' + name.replace('.', '_').replace('-', '_'),
                              ['/usr/bin/systemctl', 'start', name], timeout=600)
            self.started.append(name)
        for socket in sockets:
            name = socket[:-7] + '.service'
            if name not in units:
                raise ValueError('socket_service_inventory')
            self.started.append(name)
            self.commands.run('socket_worker_' + name.replace('.', '_').replace('-', '_'),
                              ['/usr/bin/systemctl', 'start', name], timeout=120)
        timers = [name for name in units if name.endswith('.timer')]
        for name in timers:
            self.commands.run('timer_' + name.replace('.', '_').replace('-', '_'), ['/usr/bin/systemctl', 'start', name])
            self.started.append(name)
        self.commands.run('enable_installed_units', ['/usr/bin/systemctl', 'enable', '--quiet',
                          *sockets, *timers, 'mail-client-certificates.target', *PERSISTENT,
                          *BASE_SERVICES])

    def health(self):
        from setup_access import STATE, guarded_units
        if json.loads(regular(STATE)[0]).get('phase') != 'setup':
            raise ValueError('initial_setup_state')
        self.commands.run('setup_DB_health', ['/usr/bin/mariadb-admin', '--no-defaults', '--protocol=socket', '--user=root', 'ping'])
        self.commands.run('setup_web_TLS', ['/usr/bin/curl', '--fail', '--silent', '--show-error',
                          '--resolve', self.site['mail_host']+':443:127.0.0.1', '--output', '/dev/null',
                          'https://'+self.site['mail_host']+'/mail-admin/login'])
        units = [name for name in guarded_units(plan(self.product, self.site)['units'], BASE_SERVICES)
                 if '@.' not in name]
        output = self.commands.run('setup_guarded_unit_states', ['/usr/bin/systemctl', 'show', *units,
                                   '-p', 'Id,ActiveState,SubState,MainPID'])
        if any(line in (b'ActiveState=active', b'ActiveState=activating') for line in output.splitlines()):
            raise ValueError('unpublished_service_active')
        listeners = self.commands.run('setup_TCP_listeners', ['/usr/bin/ss', '-H', '-ltnp'])
        # Match application port numbers in the local-address column, including IPv6.
        ports = {25, 80, 110, 143, 443, 465, 587, 993, 995, 4190, 3306, 6379, 11332, 11333, 11334}
        for line in listeners.decode().splitlines():
            fields = line.split()
            endpoint = fields[3]
            address, _, port = endpoint.rpartition(':')
            if port.isdigit() and int(port) in ports and address not in ('127.0.0.1', '[::1]', '::1'):
                raise ValueError('initial_public_listener_detected')

    def public_health(self):
        from policy_binding import probe
        probe(self.commands)
        for name in tuple(dict.fromkeys(BASE_SERVICES+PERSISTENT+('mail-client-cert-gate.service',))):
            self.commands.run('active_' + name.replace('.', '_').replace('-', '_'),
                              ['/usr/bin/systemctl', 'is-active', '--quiet', name])
        self.commands.run('database_health', ['/usr/bin/mariadb-admin', '--no-defaults', '--protocol=socket',
                          '--user=root', 'ping'])
        self.commands.run('web_TLS', ['/usr/bin/curl', '--fail', '--silent', '--show-error',
                          '--resolve', self.site['mail_host'] + ':443:' + self.site['public_ipv4'],
                          '--output', '/dev/null', 'https://' + self.site['mail_host'] + '/mail-admin/login'])
        # Initial publication followed by a later generation proves that the loop
        # runs without requiring mail, AUTH, import, DNS or a second old test suite.
        report = Path('/var/lib/mail-feature-runtime-v1/configuration-report.json')
        first = regular(report)[0]
        deadline = time.monotonic() + 90
        observed={}
        while time.monotonic() < deadline:
            current = regular(report)[0]
            value = json.loads(current)
            quota_path=Path('/var/lib/mail-quota-v1/private/last-result.json')
            quota=json.loads(regular(quota_path)[0]) if quota_path.exists() else {}
            observed={'publisher':value,'quota':quota}
            if (current != first and value.get('state') == 'ok' and not value.get('errors')
                    and quota.get('status')=='ok' and quota.get('capacity_within_expiry') is True
                    and quota.get('failures')==[]):
                durable_json(self.evidence/'natural-publication-health.json',observed)
                return
            time.sleep(1)
        durable_json(self.evidence/'natural-publication-health.json',observed)
        raise ValueError('natural_publication_health')

    def restore(self):
        from dkim_readiness import Reconcile
        if (self.evidence/'dkim').exists():
            Reconcile(self.files.root, self.evidence/'dkim', commands=self.commands).rollback()
        from setup_access import STATE
        if STATE.exists():
            durable_json(STATE, {'format': 1, 'phase': 'failed'})
            self.commands.run('close_setup_UI', ['/usr/bin/systemctl', 'stop', '--quiet', 'mail-platform-setup-ui-approved.service'])
        held = []
        units = plan(self.product, self.site)['units'] if self.activation_attempted else []
        sockets = [name for name in units if name.endswith('.socket')]
        services = [name for name in units if name.endswith('.service') and '@' not in name]
        order = list(dict.fromkeys(sockets + list(reversed(self.started + services))))
        for name in order:
            try:
                self.commands.run('disable_' + name.replace('.', '_').replace('-', '_'),
                                  ['/usr/bin/systemctl', 'disable', '--quiet', name], timeout=60)
                self.commands.run('restore_' + name.replace('.', '_').replace('-', '_'),
                                  ['/usr/bin/systemctl', 'stop', '--quiet', name], timeout=120)
            except Exception:
                held.append(name)
        links = PluginLinks(self.files.root, self.evidence / 'roundcube-plugin-links.json').restore()
        result = self.files.restore()
        self.commands.run('restore_systemd_definitions', ['/usr/bin/systemctl', 'daemon-reload'])
        return {'status': 'held' if held or result['held_paths'] or links['held'] else 'restored',
                'held_units': held, 'held_files': result['held_paths'],
                'held_plugin_links': links['held'], 'DB_and_credentials_preserved': True}

    def run(self, administrator):
        os.umask(0o077)
        if (set(administrator) != {'email', 'password', 'repeat'}
                or not re.fullmatch(r'[a-z0-9_.+-]{1,64}@(?:[a-z0-9-]+\.)+[a-z]{2,63}', administrator['email'])
                or administrator['password'] != administrator['repeat']
                or not 12 <= len(administrator['password'].encode()) <= 1024
                or any(ord(char) < 32 or ord(char) == 127 for char in administrator['password'])):
            raise ValueError('administrator_input')
        if os.name != 'posix' or os.geteuid() != 0:
            raise ValueError('Debian_root_required')
        import fcntl
        lock = os.open('/run/lock/mail-platform-install.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            metadata = os.fstat(lock)
            if metadata.st_uid != 0 or metadata.st_nlink != 1 or metadata.st_mode & 0o077:
                raise ValueError('installation_lock_attributes')
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.preflight()
            return self.execute_steps(administrator)
        except Exception as error:
            if self.transaction is None:
                raise
            durable_json(self.evidence / 'execution-failure.json', {
                'class': type(error).__name__, 'phase': self.transaction.value['phase'],
                'code': str(error) if isinstance(error, ValueError) else 'operation_failed',
                'frames': [{'file': Path(frame.filename).name, 'line': frame.lineno, 'function': frame.name}
                           for frame in traceback.extract_tb(error.__traceback__)]})
            command = getattr(error, 'record', {}).get('argv', [])
            if (len(command) >= 3 and command[0] == '/usr/bin/systemctl'
                    and re.fullmatch(r'[a-zA-Z0-9_.@-]+\.(?:service|socket|target|timer)', command[-1])):
                try:
                    self.commands.run('failed_unit_state', ['/usr/bin/systemctl', 'show', command[-1],
                                      '-p', 'ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,MainPID,Job'], timeout=15)
                    self.commands.run('failed_unit_journal', ['/usr/bin/journalctl', '--no-pager',
                                      '--output=json', '-n', '50', '--unit', command[-1]], timeout=15)
                except Exception as diagnostic_error:
                    durable_json(self.evidence / 'unit-diagnostic-failure.json',
                                 {'class': type(diagnostic_error).__name__})
            if hasattr(error, 'diagnostic'):
                durable_json(self.evidence / 'pure-recipe-failure.json', error.diagnostic)
            try:
                restored = self.restore()
            except Exception as recovery:
                restored = {'status': 'held', 'class': type(recovery).__name__}
            self.transaction.finish('failed', failure_class=type(error).__name__,
                                    failure_code=str(error) if isinstance(error, ValueError) else 'operation_failed',
                                    recovery=restored)
            raise
        finally:
            os.close(lock)

    def execute_steps(self, administrator):
        # Kept separate from root/OS acquisition so the complete operation order
        # and every recovery boundary can be exercised with an injected host.
        for name, operation in [('packages', self.packages), ('identities', self.identities),
                                ('assemble', self.assemble), ('database', self.database),
                                ('files', self.write_files), ('native_package', self.register_native_package),
                                ('native_validation', self.native_validation),
                                ('administrator', lambda: self.administrator(**administrator)),
                                ('start', self.start), ('health', self.health)]:
            self.transaction.step(name, operation)
        self.seal_installation()
        self.transaction.finish('complete', empty_OS_test='performed_by_this_installation')
        return {'status': 'complete', 'phase': 'isolated_setup', 'public_services_enabled': False,
                'evidence': str(self.evidence)}

    def seal_installation(self):
        code = {}
        for entry in self.files.entries:
            name = entry['path'].lstrip('/')
            if name in self.bound and not name.startswith('blueprint/'):
                code[entry['path']] = entry['after']
        schemas = {name: sha(raw) for name, raw in self.bound.items()
                   if name.startswith('blueprint/') and (name.endswith('.sql') or name.endswith('/grants.json'))}
        unit_files = {Path(entry['path']).name: entry['after'] for entry in self.files.entries
                      if entry['path'].startswith('/etc/systemd/system/')
                      and Path(entry['path']).parent == Path('/etc/systemd/system')}
        blueprints = {name: sha(raw) for name, raw in self.bound.items()
                      if name.startswith('blueprint/') and not name.startswith('blueprint/systemd/')
                      and name != 'blueprint/update-contract.json' and not name.startswith('blueprint/migrations/')}
        durable_json(Path('/var/lib/mail-platform-update/installed-code.json'),
                     {'format': 2, 'version': self.product_version, 'site': self.site, 'identities': self.ids,
                      'code': code, 'schemas': schemas, 'unit_files': unit_files, 'blueprints': blueprints})
        durable_json(Path('/var/lib/mail-platform-update/installed.json'), {'version': self.product_version, 'release': None})
