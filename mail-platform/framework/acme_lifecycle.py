"""DNS-01 acquisition and unattended renewal in a private Certbot lineage."""
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from certificate_state import trusted, private_directory, new_file, require, configuration,evidence_path, STATE
from host_transaction import Commands, Files, Transaction, durable_json

ROOT = Path('/var/lib/mail-platform-acme')
CONFIG = Path('/etc/mail-platform/acme.json')
PROVIDERS = {'cloudflare': 'python3-certbot-dns-cloudflare', 'rfc2136': 'python3-certbot-dns-rfc2136'}
SERVERS = frozenset(('https://acme-v02.api.letsencrypt.org/directory',
                     'https://acme-staging-v02.api.letsencrypt.org/directory'))


def validate(value):
    require(set(value) == {'format','profile','host','email','provider','directory','credentials','propagation_seconds',
                          'terms_agreed','server_ca'}, 'ACME_configuration_fields')
    require(value['format'] == 1 and value['provider'] in PROVIDERS and value['terms_agreed'] is True, 'ACME_provider_or_terms')
    require(re.fullmatch(r'(?:[a-z0-9][a-z0-9-]*\.)+[a-z][a-z0-9-]*', value['host']) is not None, 'ACME_hostname')
    require(re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', value['email']) is not None, 'ACME_email')
    require(type(value['propagation_seconds']) is int and 0 <= value['propagation_seconds'] <= 600, 'ACME_propagation_bound')
    if value['profile'] == 'production':
        require(value['directory'] in SERVERS and value['server_ca'] == '/etc/ssl/certs/ca-certificates.crt', 'ACME_production_server')
    else:
        require(value['profile'] == 'private-validation'
                and Path('/etc/mail-platform-validation-machine').read_text().strip() == 'mail-platform-lab-v1', 'ACME_fixture_required')
        url = urlsplit(value['directory'])
        require(url.scheme == 'https' and url.hostname in ('127.0.0.1','localhost','::1') and url.path == '/dir', 'ACME_fixture_directory')
    trusted(value['credentials'], private=True, limit=16384)
    trusted(value['server_ca'], limit=2097152)
    return value


def arguments(config, credential):
    provider = config['provider']
    return ['/usr/bin/certbot','certonly','--non-interactive','--agree-tos','--no-directory-hooks',
            '--config-dir',str(ROOT/'config'),'--work-dir',str(ROOT/'work'),'--logs-dir',str(ROOT/'logs'),
            '--server',config['directory'],'--cert-name',config['host'],'--email',config['email'],
            '--authenticator','dns-'+provider,'--dns-'+provider+'-credentials',str(credential),
            '--dns-'+provider+'-propagation-seconds',str(config['propagation_seconds']),
            '--keep-until-expiring','--key-type','rsa','--rsa-key-size','3072','-d',config['host']]


def acquire(config, evidence, credential=None):
    import fcntl
    validate(config)
    private_directory(ROOT)
    for name in ('config','work','logs'):
        private_directory(ROOT/name)
    fd = os.open(ROOT/'acquire.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require(not Path('/etc/letsencrypt/renewal', config['host']+'.conf').exists(), 'ACME_external_lineage_requires_migration')
        commands = Commands(evidence)
        # Certbot/requests honours its CA bundle without disabling HTTPS verification.
        helper = Path(evidence)/'certbot-environment.py'
        source = ('import os,sys\nos.environ["REQUESTS_CA_BUNDLE"]='+repr(config['server_ca'])+'\n'
                  'os.execv(sys.argv[1],sys.argv[1:])\n').encode()
        new_file(helper, source)
        commands.run('ACME_certonly', ['/usr/bin/python3','-I','-S','-B',str(helper),
                                     *arguments(config, credential or config['credentials'])], timeout=900)
        live = ROOT/'config/live'/config['host']
        chain, key = live/'fullchain.pem', live/'privkey.pem'
        require(chain.resolve().is_relative_to(ROOT/'config/archive')
                and key.resolve().is_relative_to(ROOT/'config/archive'), 'ACME_lineage_paths')
        trusted(chain.resolve())
        trusted(key.resolve(), private=True)
        return chain.resolve(), key.resolve()
    finally:
        os.close(fd)


def bootstrap(config_path, kit, evidence, *, install_dependencies=False):
    require(os.geteuid() == 0, 'ACME_root_required')
    value = validate(json.loads(trusted(config_path, private=True)[0]))
    kit = Path(kit)
    require(kit.is_dir() and kit.stat().st_uid == 0 and not kit.stat().st_mode & 0o077, 'ACME_private_kit')
    private_directory(ROOT)
    evidence_path(evidence).mkdir(mode=0o700)
    if install_dependencies:
        commands = Commands(evidence)
        commands.run('ACME_APT_index', ['/usr/bin/apt-get','update'])
        commands.run('ACME_APT_install', ['/usr/bin/apt-get','-y','--no-remove','install','certbot',PROVIDERS[value['provider']]], timeout=600)
    chain, key = acquire(value, evidence)
    manifest_path = kit/'kit.json'
    manifest, before = trusted(manifest_path, private=True)
    manifest = json.loads(manifest)
    for name in ('tls_certificate','tls_key'):
        entry = manifest['files'].get(name)
        require(entry is None or (entry == {'path':name+'.input','sha256':'0'*64}
                                  and not os.path.lexists(kit/entry['path'])), 'ACME_kit_TLS_already_present')
    for name, path in (('tls_certificate', chain), ('tls_key', key)):
        raw = trusted(path, private=name == 'tls_key')[0]
        filename = 'acme-'+name+'.input'
        new_file(kit/filename, raw)
        manifest['files'][name] = {'path':filename,'sha256':hashlib.sha256(raw).hexdigest()}
    require(trusted(manifest_path, private=True)[1] == before, 'ACME_kit_manifest_CAS')
    durable_json(manifest_path, manifest)
    durable_json(ROOT/'bootstrap.json', {'format':1,'host':value['host'],'configuration_sha256':hashlib.sha256(trusted(config_path, private=True)[0]).hexdigest(),
                                       'kit':str(kit),'phase':'acquired'})
    return {'status':'complete','host':value['host'],'TLS_inputs_added':True,'application_ports_opened':False}


def configure(config_path, commands, files, *, enable=True):
    value = validate(json.loads(trusted(config_path, private=True)[0]))
    from certificate_state import configuration
    require(configuration()['host'] == value['host'], 'ACME_installed_host_binding')
    credentials = trusted(value['credentials'], private=True)[0]
    files.write('/etc/mail-platform/acme-dns.ini', credentials, 0o600, preserve=True)
    value = dict(value, credentials='/etc/mail-platform/acme-dns.ini')
    files.write(str(CONFIG), (json.dumps(value,indent=2)+'\n').encode(), 0o600)
    commands.run('ACME_daemon_reload', ['/usr/bin/systemctl','daemon-reload'])
    if enable:
        commands.run('ACME_enable_timer', ['/usr/bin/systemctl','enable','--now','mail-platform-acme.timer'])


def register(config_path,evidence):
    require(os.geteuid()==0,'ACME_root_required')
    value=validate(json.loads(trusted(config_path,private=True)[0]))
    transaction=Transaction(evidence_path(evidence))
    commands,files=Commands(evidence),Files('/',evidence)
    enable_requested=False
    try:
        commands.run('ACME_dependencies',['/usr/bin/dpkg-query','-W','certbot',PROVIDERS[value['provider']]])
        from certificate_state import certificate_lock,failure
        with certificate_lock():
            private_directory(ROOT)
            private_directory(STATE)
            configure(config_path,commands,files,enable=False)
            for name,raw in units().items():
                files.write('/etc/systemd/system/'+name,raw)
            commands.run('ACME_units_verify',['/usr/bin/systemd-analyze','verify',
                '/etc/systemd/system/mail-platform-acme.service','/etc/systemd/system/mail-platform-acme.timer'])
            commands.run('ACME_reload_units',['/usr/bin/systemctl','daemon-reload'])
        enable_requested=True
        commands.run('ACME_enable_timer',['/usr/bin/systemctl','enable','--now','mail-platform-acme.timer'])
        transaction.finish('complete',provider=value['provider'])
        return {'status':'complete','provider':value['provider']}
    except Exception as error:
        recovery={'status':'held_after_timer_request'} if enable_requested else files.restore()
        from certificate_state import failure
        failure(evidence,error,'ACME_registration',recovery)
        transaction.finish('failed',recovery=recovery)
        raise


def worker():
    import time
    require(os.geteuid() == 0, 'ACME_root_required')
    status=Path('/proc/self/status').read_text().splitlines()
    protection={name:next(line.split(':',1)[1].strip() for line in status if line.startswith(name+':'))
                for name in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs')}
    require(all(int(protection[name],16)==0 for name in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
            and protection['NoNewPrivs']=='1','ACME_worker_capabilities_or_NNP')
    require(Path('/proc/self/cgroup').read_text()=='0::/system.slice/mail-platform-acme.service\n'
            and Path('/sys/fs/cgroup/system.slice/mail-platform-acme.service/memory.swap.max').read_text().strip()=='0','ACME_worker_unit_or_swap')
    config = validate(json.loads(trusted(CONFIG, private=True)[0]))
    credentials = Path(os.environ['CREDENTIALS_DIRECTORY'])/'dns'
    require(credentials.parent == Path('/run/credentials/mail-platform-acme.service'), 'ACME_credentials_unit')
    # systemd credentials can use 0400/0440; root file and parent trust still apply.
    trusted(credentials, private=False)
    evidence = private_directory(STATE/'acme-runs'/str(time.time_ns()))
    durable_json(evidence/'protection.json',protection)
    try:
        from tls_deployment import require_settled
        require_settled()
        chain, key = acquire(config, evidence, credentials)
        from tls_deployment import fingerprint, current_live, deploy
        current = current_live(config['host'])
        expected = fingerprint(chain.read_bytes())
        if expected == current['fingerprint'] and hashlib.sha256(chain.read_bytes()).hexdigest()==current['certificate_sha256']:
            result={'status':'current','fingerprint':expected}
        else:
            result=deploy(chain, key, evidence/'deployment')
        durable_json(evidence/'result.json',result)
        return result
    except Exception as error:
        from certificate_state import failure
        failure(evidence,error,'ACME_acquisition_or_deployment',{'status':'prior_TLS_retained_or_deployment_receipt'})
        durable_json(evidence/'result.json',{'status':'failed','class':type(error).__name__})
        raise


def units():
    service = '''[Unit]
Description=Mail platform ACME DNS-01 renewal
ConditionPathExists=/etc/mail-platform/acme.json
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
User=root
Group=root
ExecStart=/usr/bin/python3 -I -S -B /usr/local/lib/mail-platform-update/certificate_cli.py acme-worker
LoadCredential=dns:/etc/mail-platform/acme-dns.ini
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/var/lib/mail-platform-acme /var/lib/mail-platform-certificates /etc/letsencrypt /var/lib/mail-client-cert-public-v1 /run/lock -/var/lib/mail-platform-update/update.lock
MemorySwapMax=0
MemoryMax=768M
CPUQuota=200%
TimeoutStartSec=1200
UMask=0077
LimitCORE=0
'''
    timer = '''[Unit]
Description=Mail platform ACME renewal schedule
[Timer]
OnBootSec=15min
OnUnitInactiveSec=12h
RandomizedDelaySec=1h
Persistent=yes
Unit=mail-platform-acme.service
[Install]
WantedBy=timers.target
'''
    return {'mail-platform-acme.service':service.encode(),'mail-platform-acme.timer':timer.encode()}
