"""Final inherited-config backend renderer. No activation or host connections."""
import ipaddress
import re
from pathlib import PurePosixPath
def need(value,code):
    if value is not True:raise ValueError(code)
def path(value):
    need(type(value)is str and value.startswith('/')and str(PurePosixPath(value))==value
        and re.fullmatch('/[A-Za-z0-9_./-]+',value)is not None and '..'not in value.split('/'),'backend_absolute_path');return value
def dovecot(root,runtime,inventory,source='/etc/dovecot/dovecot.conf',config_version=None):
    root,runtime,source=path(root),path(runtime),path(source)
    need(type(inventory)is dict and type(inventory.get('listeners'))is list,'backend_native_inventory')
    need(config_version in {'2.4.0','2.4.1'},'existing_dovecot_config_version_required')
    # Inherit actual SQL/AppPassword/userdb, canonical home, maildir and plugin
    # settings. No copy of SQL credentials or reimplemented mailbox mapping.
    lines=['dovecot_config_version = '+config_version,'!include '+source,'base_dir = '+runtime+'/dovecot',
        'state_dir = '+runtime+'/state','instance_name = device-certificate-backend-v1','protocols = imap pop3',
        'listen = 127.0.0.1','ssl = no','auth_ssl_username_from_cert = yes','auth_ssl_require_client_cert = no',
        # Certificate presence is enforced by TLSGate.CERT_REQUIRED BEFORE opening
        # this private-netns backend. Native direct-TLS cert flags are unavailable
        # on a PROXY connection; setting auth_ssl_require_client_cert=yes denies
        # legitimate forwarded connections too. Never expose these ports.
        'haproxy_trusted_networks = 127.0.0.1/32','login_trusted_networks =','auth_cache_size = 0',
        'log_path = '+runtime+'/dovecot.log','info_log_path = '+runtime+'/dovecot.log']
    disabled=[]
    for listener in inventory['listeners']:
        service,name,kind=(listener.get(k)for k in ('service','name','kind'))
        need(type(service)is str and re.fullmatch('[A-Za-z0-9_-]{1,64}',service)is not None,'backend_service_label')
        need(type(name)is str and re.fullmatch('[A-Za-z0-9_./:-]{1,256}',name)is not None,'backend_listener_label')
        if kind=='inet_listener' or(kind in {'unix_listener','fifo_listener'}and name.startswith('/')):
            key='port'if kind=='inet_listener'else'mode'
            lines+=['service '+service+' {',' '+kind+' '+name+' {','  '+key+' = 0',' }','}'];disabled.append((service,kind,name))
    for service,name,port in (('imap-login','imap',14300),('pop3-login','pop3',11000)):
        lines+=['service '+service+' {',' inet_listener '+name+' {','  port = '+str(port),'  haproxy = yes',' }','}']
    return '\n'.join(lines)+'\n',disabled
def host_dovecot_overlay():
    return ('service imap-login {\n inet_listener imaps {\n  port = 0\n }\n}\n'
        'service pop3-login {\n inet_listener pop3s {\n  port = 0\n }\n}\n')
def postfix(runtime,queue,policy_port=15871):
    runtime,queue=path(runtime),path(queue);need(type(policy_port)is int and 1024<policy_port<65536,'policy_port')
    # Existing main.cf is cloned privately then these named values are replaced
    # with native postconf -e. Actual maps/domains/limits remain inherited.
    return {'queue_directory':queue,'data_directory':runtime+'/postfix-data','inet_interfaces':'loopback-only',
        'smtpd_upstream_proxy_protocol':'haproxy','smtpd_upstream_proxy_timeout':'5s',
        'smtpd_sasl_auth_enable':'yes','smtpd_sasl_type':'dovecot','smtpd_sasl_path':queue+'/private/auth',
        'smtpd_tls_security_level':'none','smtpd_tls_auth_only':'no','smtpd_peername_lookup':'no',
        'smtpd_milters':'unix:'+runtime+'/milter.sock','smtpd_authorized_xclient_hosts':'','smtpd_authorized_xforward_hosts':'',
        'smtpd_relay_restrictions':'check_policy_service inet:127.0.0.1:'+str(policy_port)+', permit_sasl_authenticated, reject',
        'smtpd_policy_service_policy_context':'device_certificate_gateway_v1','smtpd_policy_service_try_limit':'1',
        'smtpd_policy_service_timeout':'3s','smtpd_policy_service_default_action':'451 4.3.5 Device authorization unavailable',
        'multi_instance_directories':'','syslog_name':'postfix/device-certificates'}
def master():
    return '127.0.0.1:15870 inet n - n - - smtpd\n'
def close_public_submission(raw,public_addresses):
    need(type(raw)is bytes and type(public_addresses)is frozenset,'host_master_input')
    targets={str(ipaddress.ip_address(v))+':587'for v in public_addresses if ':'not in v}
    targets|={'['+str(ipaddress.ip_address(v))+']:587'for v in public_addresses if ':'in v}
    result=[];removed=[];skip=False
    for line in raw.decode('utf-8','strict').splitlines(keepends=True):
        if line[:1]in(' ','\t'):
            if not skip:result.append(line)
            continue
        skip=False
        if line.strip()and not line.lstrip().startswith('#'):
            fields=line.split()
            if len(fields)>=8 and fields[0]in targets and fields[1]=='inet':skip=True;removed.append(fields[0]);continue
        result.append(line)
    need(set(removed)==targets and len(removed)==len(targets),'exact_public_submission_entry_not_found')
    return ''.join(result).encode(),removed
