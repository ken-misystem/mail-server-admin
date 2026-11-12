"""Concrete actor configuration from supplied verified identities/CA/pins only."""
from safety import need
from units import ROOT,RUN
def render(*,release,manifest_pin,peers,groups,sql_socket,ca,listeners,host_namespace,principals,executables,readiness,profile='production',runtime_root=RUN,state_directory='/var/lib/mail-client-cert-issuer-v1'):
    need(profile in {'production','private-validation'}and set(peers)=={'owner','lifecycle','verifier','issuer','gate','fpm'},'configuration_actor_inventory')
    need(profile!='production'or release==ROOT,'production_configuration_release')
    need(all(set(v)=={'uid','gid','cgroup'}and type(v['uid'])is int and v['uid']>0 and type(v['gid'])is int and v['gid']>0
        and type(v['cgroup'])is str and v['cgroup'].startswith('/system.slice/')for v in peers.values()),'configuration_peer_fields')
    need(set(groups)=={'owner','gate','fpm'}and all(type(v)is int and v>0 for v in groups.values()),'configuration_socket_groups')
    sockets={'owner':runtime_root+'/owner/owner.sock','lifecycle':runtime_root+'/lifecycle/lifecycle.sock','verifier':runtime_root+'/verifier/verifier.sock',
        'broker':runtime_root+'/issuer/broker.sock','crl':runtime_root+'/issuer/crl.sock','crl_owner':runtime_root+'/issuer/crl-owner.sock','gate_control':runtime_root+'/gate/control.sock'}
    socket_groups={k:groups['fpm']if k=='owner'else groups['gate']if k=='crl'else groups['owner']for k in sockets}
    common={'version':1,'profile':profile,'release':release,'manifest_sha256':manifest_pin,'peers':peers,'sockets':sockets,'socket_groups':socket_groups,
        'principals':principals,'sql_socket':sql_socket,'ca':ca,'state_directory':state_directory,'executables':executables,'readiness':readiness,
        'listeners':listeners,'public_addresses':sorted({v['address'][0]for v in listeners}),
        'backends':{'imaps':['127.0.0.1',14300],'pop3s':['127.0.0.1',11000],'submission':['127.0.0.1',15870]},
        'policy_endpoint':['127.0.0.1',15871],'host_namespace':host_namespace,
        'php_extensions':['/usr/lib/php/20240924/mbstring.so','/usr/lib/php/20240924/tokenizer.so','/usr/lib/php/20240924/ctype.so']}
    return {name:dict(common,actor=name,runtime_directory=runtime_root+'/'+name)for name in ('owner','lifecycle','verifier','issuer','gate')}
