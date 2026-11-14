"""Render initial format-2 integration from the installed complete FPM/SQL site."""
from pathlib import Path
import json
import pwd
import subprocess

from generation_units import system_fpm
from release import sha
from code_update import render
from host_transaction import regular


def prepare(payload, receipt):
    payload = Path(payload)
    for parent in (payload, *payload.parents):
        metadata = parent.lstat()
        if parent.is_symlink() or not parent.is_dir() or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError('site_generation_payload_trust')
    roots=['/opt/mail-management/candidates/protection-relay-v1','/opt/roundcube-auth']
    plugins=sorted({str(Path(*Path(path).parts[:6])) for path in receipt['code'] if path.startswith('/usr/share/roundcube/plugins/')})
    roots += [path for path in plugins if Path(path).is_dir() and Path(path).name!='managesieve']
    assert '/usr/share/roundcube/plugins/mail_settings' in roots
    pool_names=['mail-platform.conf','www.conf']
    if {path.name for path in Path('/etc/php/8.4/fpm/pool.d').glob('*.conf')} != set(pool_names):
        raise ValueError('site_FPM_pool_inventory_requires_review')
    pools={name:(Path('/etc/php/8.4/fpm/pool.d')/name).read_bytes() for name in pool_names}
    runtimes={'mail-platform.conf':'/run/mail-platform-web','www.conf':'/run/mail-platform-roundcube'}
    fpm=system_fpm('/var/lib/mail-platform-generations',roots,Path('/etc/php/8.4/fpm/php-fpm.conf').read_bytes(),pools,runtimes)
    resources={}
    def resource(path,raw,mode=0o644):
     resources[path]=(raw.encode() if isinstance(raw,str) else raw,mode)
    resource('/etc/systemd/system/mail-platform-site-web@.service',fpm['unit'])
    resource('/etc/mail-platform/site-fpm.conf',fpm['fpm_config_template'],0o600)
    common={'kind':'web','roots':roots,'unit':'mail-platform-site-web@.service',
            'template':'/etc/mail-platform/site-fpm.conf','drain_seconds':60}
    components={}
    parameters={'SERVER_NAME':receipt['site']['mail_host'],'SERVER_PORT':'443','HTTPS':'on','REMOTE_ADDR':'127.0.0.1','SERVER_SOFTWARE':'nginx'}
    for name,filename,script,uri in [('web','mail-platform.conf','/var/www/mail-admin/index.php','/mail-admin/'),
                                   ('web-roundcube','www.conf','/var/lib/roundcube/index.php','/')]:
     components[name]=dict(common,route='/etc/mail-platform/'+name+'-route.json',
      control='/run/mail-platform-web-front/'+name+'.sock',runtime=runtimes[filename],
      health={'kind':'fcgi','request':script,'reply':'text/html',
              'parameters':dict(parameters,SCRIPT_NAME='/index.php',
                                REQUEST_URI='/mail-admin/login' if name=='web' else uri)})
    policy=json.loads(Path('/etc/mail-send-limits-v1/runtime.json').read_bytes())
    peer=pwd.getpwuid(policy['peer_uid'])
    components['policy']={'kind':'writer','roots':['/usr/local/lib/mail-send-limits-v1'],
     'unit':'mail-platform-site-policy@.service','template':None,'runtime':'/run/mail-platform-policy',
     'route':'/etc/mail-platform/policy-route.json','control':'/run/mail-platform-policy-front/control.sock','drain_seconds':30,
     'health':{'kind':'policy','request':'request=mail_platform_generation_health\n\n','reply':'action=DUNNO\n\n',
               'peer_uid':peer.pw_uid,'peer_gid':peer.pw_gid}}
    fronts=[{'route':components[name]['route'],'listen':listen,'control':components[name]['control'],'mode':'stream',
             'allowed_uid':pwd.getpwnam('www-data').pw_uid}
            for name,listen in [('web','/run/php/mail-platform.sock'),('web-roundcube','/run/php/php8.4-fpm.sock')]]
    resource('/etc/mail-platform/web-fronts.json',json.dumps(fronts),0o644)
    resource('/etc/systemd/system/php8.4-fpm.service.d/80-mail-platform-generations.conf','''[Service]
Type=notify
NotifyAccess=main
ExecStart=
ExecStart=/usr/bin/python3 -I -S -B /usr/local/lib/mail-platform-update/generation_entry.py front --configuration /etc/mail-platform/web-fronts.json
ExecStartPost=
ExecStopPost=
ExecReload=
ExecReload=+/usr/bin/python3 -I -S -B /usr/local/lib/mail-platform-update/site_enrollment.py reload-web
PIDFile=
User=www-data
Group=www-data
RuntimeDirectory=mail-platform-web-front
RuntimeDirectoryMode=0755
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX
ReadWritePaths=/run/php /run/mail-platform-web-front
KillSignal=SIGTERM
TimeoutStopSec=60
''')
    original=subprocess.check_output(['systemctl','cat','mail-send-limits-v1.service'])
    resource('/etc/systemd/system/mail-platform-site-policy@.service',original+b'''
[Unit]
Description=Mail SQL policy generation %i
Requires=
Requires=mail-feature-admin-v1.service
[Service]
ExecStart=
ExecStart=/usr/bin/python3 -I -S -B /usr/local/lib/mail-platform-update/policy_generation.py %i
RuntimeDirectory=mail-platform-policy/%i
RuntimeDirectoryMode=0755
ReadWritePaths=/run/mail-platform-policy/%i
BindReadOnlyPaths=/var/lib/mail-platform-generations/policy/%i/root/usr/local/lib/mail-send-limits-v1:/usr/local/lib/mail-send-limits-v1
Restart=no
''')
    resource('/etc/systemd/system/mail-send-limits-v1.service.d/80-mail-platform-generations.conf',f'''[Service]
    Type=notify
    NotifyAccess=main
    User={peer.pw_name}
    Group={peer.pw_name}
    ExecStart=
    ExecStart=/usr/bin/python3 -I -S -B /usr/local/lib/mail-platform-update/generation_entry.py front --route /etc/mail-platform/policy-route.json --listen {policy['socket']} --control /run/mail-platform-policy-front/control.sock --mode policy --allowed-uid {peer.pw_uid} --policy-nonce --activated
    LoadCredential=
    StateDirectory=
    RuntimeDirectory=mail-platform-policy-front
    RuntimeDirectoryMode=0755
    ReadWritePaths=
    ReadWritePaths=/run/mail-platform-policy-front
    Restart=no
    ''')
    resource('/etc/systemd/system/mail-platform-site-generations.service','''[Unit]
Description=Restore registered mail component generations
Requires=mariadb.service
After=mariadb.service
Before=nginx.service
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I -S -B /usr/local/lib/mail-platform-update/site_enrollment.py
NoNewPrivileges=yes
RemainAfterExit=yes
TimeoutStartSec=120
[Install]
WantedBy=multi-user.target
''')
    bound = render(payload, receipt, regular)
    adopted={}
    for source in sorted((payload/'usr/local/lib/mail-platform-update').iterdir()):
     if source.is_file():
      target='/usr/local/lib/mail-platform-update/'+source.name
      old=receipt['code'].get(target)
      raw = bound[target.lstrip('/')]
      if old is None or old['sha256']!=sha(raw):adopted[target]=raw
    adopted['/usr/local/lib/mail-send-limits-v1/runtime.py']=bound['usr/local/lib/mail-send-limits-v1/runtime.py']
    config={'format':1,'generation_root':'/var/lib/mail-platform-generations','components':components}
    return config, resources, adopted
