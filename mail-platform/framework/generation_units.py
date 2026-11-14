"""Render enrolled generation templates. Inputs come from private root-owned configuration."""
import re
import ipaddress
from pathlib import PurePosixPath
from availability_plan import path


def fpm(name, code_root, runtime, roots, user, group,
        writable_paths=('/var/lib/php/sessions', '/var/lib/roundcube')):
    if not re.fullmatch('[a-z][a-z0-9-]{0,30}', name):
        raise ValueError('generation_template_name')
    for value in (code_root, runtime, *roots, *writable_paths):
        path(value)
    if any(not re.fullmatch('[a-z_][a-z0-9_-]{0,30}', value) for value in (user, group)):
        raise ValueError('generation_template_identity')
    generation = code_root+'/'+name+'/%i'
    binds = '\n'.join('BindReadOnlyPaths='+generation+'/root'+root+':'+root for root in roots)
    writable = ' '.join('-'+value for value in writable_paths)
    unit = f'''[Unit]
Description=Mail platform {name} generation %i
[Service]
Type=notify
NotifyAccess=main
User={user}
Group={group}
ExecStart=/usr/sbin/php-fpm8.4 --nodaemonize --fpm-config {generation}/fpm.conf
RuntimeDirectory={runtime.removeprefix('/run/')}/%i
RuntimeDirectoryMode=0750
UMask=0027
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths={runtime}/%i {writable}
{binds}
KillSignal=SIGQUIT
TimeoutStopSec=60
SendSIGKILL=no
MemoryMax=512M
CPUQuota=100%
'''
    # pm.status_listen is intentionally absent; private health uses FastCGI.
    config = f'''[global]
daemonize = no
error_log = syslog
pid = {runtime}/%i/fpm.pid
[web]
user = {user}
group = {group}
listen = {runtime}/%i/backend.sock
listen.mode = 0660
pm = ondemand
pm.max_children = 4
pm.process_idle_timeout = 10s
catch_workers_output = yes
clear_env = yes
security.limit_extensions = .php
'''
    return {'unit': unit.encode(), 'fpm_config_template': config}


def certificate_front(name, gate_uid, gate_gid, gate_group, endpoint):
    """Prepare first-enrollment units without changing the running certificate gate."""
    if name not in ('submission','imaps','pop3s'):
        raise ValueError('certificate_front_protocol')
    if any(type(value) is not int or value<=0 for value in (gate_uid,gate_gid)):
        raise ValueError('certificate_front_identity')
    if not re.fullmatch('[a-z_][a-z0-9_-]{0,30}',gate_group):
        raise ValueError('certificate_front_group')
    host,port=endpoint
    if not ipaddress.ip_address(host).is_loopback or type(port) is not int or not 1024<port<65536:
        raise ValueError('certificate_front_native_endpoint')
    target=('['+host+']' if ipaddress.ip_address(host).version==6 else host)+':'+str(port)
    runtime='mail-platform-'+name
    native=runtime+'-native'
    front=f'''[Unit]
Description=Certificate {name} stable frontend
Requires=mail-client-cert-network.service
After=mail-client-cert-network.service
Wants={native}.socket
JoinsNamespaceOf=mail-client-cert-network.service
[Service]
User=root
Group={gate_group}
Type=simple
RuntimeDirectory={runtime}
RuntimeDirectoryMode=0750
ExecStart=/usr/bin/python3 -I -S -B /usr/local/lib/mail-platform-update/generation_entry.py front --route /etc/mail-platform/{name}-route.json --listen /run/{runtime}/listen.sock --control /run/{runtime}/control.sock --mode stream --allowed-uid {gate_uid} --listen-gid {gate_gid}
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/run/{runtime}
Restart=on-failure
MemoryMax=128M
CPUQuota=100%
TasksMax=64
UMask=0027
'''
    native_unit='mail-client-cert-postfix-backend.service' if name=='submission' else 'mail-client-cert-dovecot-backend.service'
    proxy=f'''[Unit]
Description=Certificate {name} initial native bridge
Requires=mail-client-cert-network.service {native_unit}
After=mail-client-cert-network.service {native_unit}
JoinsNamespaceOf=mail-client-cert-network.service
[Service]
User=mailcert-gate
Group={gate_group}
ExecStart=/usr/lib/systemd/systemd-socket-proxyd {target}
PrivateNetwork=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
MemoryMax=64M
CPUQuota=100%
'''
    listener=f'''[Unit]
Description=Certificate {name} initial bridge socket
[Socket]
ListenStream=/run/{native}/glegacy/backend.sock
SocketMode=0600
DirectoryMode=0700
Accept=no
'''
    return {runtime+'-front.service':front,native+'.service':proxy,native+'.socket':listener}


def system_fpm(code_root, roots, main, pools, runtimes):
    """Retain every installed pool directive in an isolated root-master generation."""
    path(code_root)
    if set(pools) != set(runtimes) or not pools:
        raise ValueError('site_FPM_pool_inventory')
    if (main.count(b'include=/etc/php/8.4/fpm/pool.d/*.conf') != 1
            or len(re.findall(rb'(?m)^\s*include\s*=', main)) != 1):
        raise ValueError('site_FPM_include_requires_review')
    main = main.replace(b'include=/etc/php/8.4/fpm/pool.d/*.conf', b'')
    main, count = re.subn(rb'(?m)^pid\s*=\s*[^\r\n]+', b'pid = /run/mail-platform-web/%i/master.pid', main)
    if count != 1:
        raise ValueError('site_FPM_pid_requires_review')
    for name, raw in sorted(pools.items()):
        runtime = path(runtimes[name])
        if not re.fullmatch('[a-zA-Z0-9_.-]+', name) or re.search(rb'(?m)^\s*include\s*=', raw):
            raise ValueError('site_FPM_pool_requires_review')
        raw, count = re.subn(rb'(?m)^listen\s*=\s*[^\r\n]+', ('listen = '+runtime+'/%i/backend.sock').encode(), raw)
        if count != 1:
            raise ValueError('site_FPM_listener_requires_review')
        main += b'\n'+raw+b'\n'
    binds=[]
    for root in roots:
        path(root)
        binds.append('BindReadOnlyPaths='+code_root+'/web/%i/root'+root+':'+root)
    directories=' '.join(PurePosixPath(value).relative_to('/run').as_posix()+'/%i' for value in runtimes.values())
    writable=' '.join(value+'/%i' for value in runtimes.values())
    unit='''[Unit]
Description=Mail platform complete FPM generation %i
After=mariadb.service
[Service]
Type=notify
NotifyAccess=main
User=root
Group=www-data
ExecStart=/usr/sbin/php-fpm8.4 --nodaemonize --fpm-config '''+code_root+'''/web/%i/fpm.conf
ExecReload=/bin/kill -USR2 $MAINPID
RuntimeDirectory='''+directories+'''
RuntimeDirectoryMode=0755
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETUID CAP_SETGID
AmbientCapabilities=CAP_SETUID
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths='''+writable+''' -/var/lib/php/sessions /var/lib/mail-management /var/lib/roundcube /var/log
'''+ '\n'.join(binds)+'''
KillSignal=SIGQUIT
TimeoutStopSec=90
SendSIGKILL=no
MemoryMax=1G
CPUQuota=200%
'''
    return {'unit':unit.encode(),'fpm_config_template':main}
