"""Concrete, uninstalled production units. All effects require later apply approval."""
import ipaddress
from safety import need
ROOT='/usr/local/lib/mail-client-certificates-v1'
RUN='/run/mail-client-certificates-v1'
PREFIX='mail-client-cert-'
ACTORS=('owner','lifecycle','verifier','issuer','gate')
CREDENTIALS={'owner':('identity_reader','orchestrator','gateway_reader','session_reader'),
    'lifecycle':('lifecycle_provisioner',),'verifier':('webauthn_verifier',),
    'issuer':('issuer_journal','issuer_certificate','issuer_key','issuer_password'),
    'gate':('gateway_reader','server_certificate','server_key')}
HARDEN=['NoNewPrivileges=yes','CapabilityBoundingSet=','AmbientCapabilities=','ProtectSystem=strict','ProtectHome=yes',
    'PrivateTmp=yes','PrivateDevices=yes','ProtectControlGroups=yes','ProtectKernelTunables=yes','ProtectKernelModules=yes',
    'RestrictSUIDSGID=yes','LockPersonality=yes','RestrictRealtime=yes','SystemCallArchitectures=native','KeyringMode=private',
    'MemorySwapMax=0','MemoryMax=512M','LimitMEMLOCK=256M','LimitCORE=0','TasksMax=128','UMask=0077',
    'Restart=on-failure','RestartSec=5','TimeoutStartSec=240','TimeoutStopSec=20','KillMode=mixed','StandardOutput=journal','StandardError=journal']
def service(actor):return PREFIX+actor+'.service'
def render(addresses):
    need(type(addresses)is frozenset and addresses and all(str(ipaddress.ip_address(v))==v and ipaddress.ip_address(v).is_global for v in addresses),'units_fixed_public_addresses')
    units={};common=['[Unit]','ConditionPathExists=/etc/mail-client-certificates-v1/activation-approved.json']
    for actor in ACTORS:
        lines=common+['Description=Mail device certificates '+actor,'Requires=mariadb.service','After=mariadb.service']
        deps={'owner':('lifecycle','verifier','issuer','gate'),'gate':('issuer','network','postfix-backend','dovecot-backend','coordination')}.get(actor,())
        if deps:lines+=['Requires='+' '.join(service(v)for v in deps),'After='+' '.join(service(v)for v in deps)]
        if actor=='gate':lines+=['JoinsNamespaceOf='+service('network'),'Requires='+PREFIX+'gate.socket']
        group='www-data'if actor=='owner'else'mailcert-gate'if actor=='gate'else'mailcert-owner'
        lines+=['[Service]','Type=notify','NotifyAccess=main','User=mailcert-'+actor,'Group='+group,
            'ExecStart=/usr/bin/python3 -I -S -B '+ROOT+'/client-certificates/runtime-completion-v1/start.py '+actor+' --config /etc/mail-client-certificates-v1/'+actor+'.json',
            'RuntimeDirectory=mail-client-certificates-v1/'+actor,'RuntimeDirectoryMode=0750','PrivateNetwork=yes',
            'RestrictAddressFamilies=AF_UNIX'+(' AF_INET AF_INET6'if actor=='gate'else'')]+HARDEN
        groups={'owner':'mailcert-owner','issuer':'mailcert-gate','gate':'mailcert-owner'}.get(actor)
        if groups:lines+=['SupplementaryGroups='+groups]
        if actor=='issuer':lines+=['StateDirectory=mail-client-cert-issuer-v1','StateDirectoryMode=0700']
        if actor=='gate':lines+=['OpenFile=/proc/1/ns/net:host-net:read-only']
        for credential in CREDENTIALS[actor]:lines+=['LoadCredential='+credential+':/var/lib/mail-client-certificates-v1/credentials/'+actor+'/'+credential]
        units[service(actor)]='\n'.join(lines)+'\n'
    sockets=['[Unit]','Description=Mail client certificate public entrances','ConditionPathExists=/etc/mail-client-certificates-v1/activation-approved.json',
        '[Socket]','Accept=no','Service='+service('gate'),'BindIPv6Only=ipv6-only','Backlog=128']
    for address in sorted(addresses):
        for port in (993,995,587):sockets+=['ListenStream='+('['+address+']'if':'in address else address)+':'+str(port)]
    units[PREFIX+'gate.socket']='\n'.join(sockets)+'\n'
    units[service('network')]='\n'.join(common+['Description=Mail client private network','[Service]','Type=simple','User=mailcert-gate','Group=mailcert-gate',
        'ExecStart=/usr/bin/sleep infinity','PrivateNetwork=yes','RestrictAddressFamilies=AF_UNIX']+HARDEN)+'\n'
    units[service('dovecot-backend')]='\n'.join(common+['Description=Private certificate Dovecot backend','Requires='+service('network'),
        'After='+service('network'),'JoinsNamespaceOf='+service('network'),'[Service]','Type=simple','User=root','Group=root',
        'ExecStart=/usr/sbin/dovecot -F -c /etc/mail-client-certificates-v1/dovecot-backend.conf','PrivateNetwork=yes',
        'ProtectSystem=strict','ProtectHome=yes','PrivateTmp=yes','ProtectKernelTunables=yes','ProtectKernelModules=yes','ProtectControlGroups=yes',
        'NoNewPrivileges=yes','CapabilityBoundingSet=CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_OVERRIDE CAP_KILL CAP_SYS_CHROOT',
        'AmbientCapabilities=','RestrictAddressFamilies=AF_UNIX AF_INET','ReadWritePaths=/var/vmail '+RUN+'/native',
        'RuntimeDirectory=mail-client-certificates-v1/native','RuntimeDirectoryMode=0755','LimitCORE=0','Restart=on-failure','RestartSec=5'])+'\n'
    # smtpd uses its tested single-connection mode, never a second queue manager.
    lines=common+['Description=Private certificate Postfix smtpd','Requires='+service('network')+' '+service('coordination'),
        'After='+service('network')+' '+service('coordination'),'JoinsNamespaceOf='+service('network'),'[Service]',
        'Type=notify','User=postfix','Group=postfix','PrivateNetwork=yes','RestrictAddressFamilies=AF_UNIX AF_INET',
        'RuntimeDirectory=mail-client-certificates-v1/postfix','RuntimeDirectoryMode=0755',
        'ExecStartPre=+/usr/bin/python3 -I -S -B '+ROOT+'/client-certificates/runtime-completion-v1/coordination.py --snapshot',
        'ExecStart=/usr/bin/python3 -I -S -B '+ROOT+'/client-certificates/runtime-completion-v1/native_smtpd.py']+HARDEN
    for source,target in (('/var/spool/postfix/public/cleanup','public/cleanup'),('/var/spool/postfix/private/rewrite','private/rewrite'),('/var/spool/postfix/private/auth','private/auth')):
        lines+=['BindReadOnlyPaths='+source+':'+RUN+'/postfix/'+target]
    lines+=['BindReadOnlyPaths='+RUN+'/milter/milter.sock:'+RUN+'/native/milter.sock','ReadWritePaths='+RUN+'/coordination']
    units[service('postfix-backend')]='\n'.join(lines)+'\n'
    units[service('milter')]='\n'.join(common+['Description=Fixed Postfix to Rspamd IPC','Requires=rspamd.service','After=rspamd.service',
        '[Service]','Type=notify','User=postfix','Group=postfix','RestrictAddressFamilies=AF_UNIX AF_INET',
        'RuntimeDirectory=mail-client-certificates-v1/milter','RuntimeDirectoryMode=0750',
        'ExecStart=/usr/bin/python3 -I -S -B '+ROOT+'/client-certificates/runtime-completion-v1/milter_service.py']+HARDEN)+'\n'
    units[service('coordination')]='\n'.join(common+['Description=Fixed delivery socket generation watcher','After=postfix.service dovecot.service',
        '[Service]','Type=notify','User=root','Group=root','RuntimeDirectory=mail-client-certificates-v1/coordination','RuntimeDirectoryMode=0755',
        'ExecStart=/usr/bin/python3 -I -S -B '+ROOT+'/client-certificates/runtime-completion-v1/coordination.py --watch',
        'NoNewPrivileges=yes','CapabilityBoundingSet=CAP_DAC_READ_SEARCH','AmbientCapabilities=','ProtectSystem=strict','ProtectHome=yes',
        'PrivateTmp=yes','PrivateDevices=yes','RestrictAddressFamilies=AF_UNIX','ReadWritePaths='+RUN+'/coordination',
        'LimitCORE=0','MemorySwapMax=0','Restart=on-failure','RestartSec=5','UMask=0077'])+'\n'
    # Dependencies bind the relay and mounted IPC startup to the private backend.
    units[service('postfix-backend')]=units[service('postfix-backend')].replace('Description=Private certificate Postfix smtpd',
        'Description=Private certificate Postfix smtpd\nRequires='+service('milter')+'\nAfter='+service('milter'))
    return units
