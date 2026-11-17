"""Add the session lock without replacing an existing include-based layout."""
import re
from release import sha,canonical
PATH='/etc/dovecot/97-mail-platform-sieve-lock.conf'
INCLUDE=b'!include '+PATH.encode()+b'\n'
def content(layout):
    effective=layout['effective']
    if set(effective)!={'global','imap','pop3','lmtp'} or sha(canonical(effective))!=layout['effective_sha256']:
        raise ValueError('adoption_Sieve_effective_binding')
    blocks=[]
    for protocol in ('global','imap','pop3','lmtp'):
        lines=effective[protocol].splitlines()
        if any(not re.fullmatch(r'[a-z][a-z0-9_]* = (yes|no)',line) for line in lines):
            raise ValueError('adoption_Sieve_plugin_value')
        if any(line.startswith('mail_sieve_session_lock ') for line in lines):
            raise ValueError('adoption_Sieve_plugin_collision')
        block='mail_plugins {\n'+'\n'.join(' '+line for line in lines)+'\n mail_sieve_session_lock = yes\n}\n'
        if protocol!='global':block='protocol '+protocol+' {\n'+block+'}\n'
        blocks.append(block)
    return ('# Mail platform: preserve reviewed effective lists, including inherited values.\n'+''.join(blocks)).encode()

def verify_effective(layout,commands,stage,*,installed=False):
    content(layout)
    observed={}
    for protocol in ('global','imap','pop3','lmtp'):
        args=['/usr/bin/doveconf']
        if protocol!='global':args+=['-f','protocol='+protocol]
        raw=commands.run('Sieve_'+stage+'_'+protocol,args+['-h','mail_plugins'])
        observed[protocol]=raw.decode()
        expected=set(layout['effective'][protocol].splitlines())
        if installed:expected.add('mail_sieve_session_lock = yes')
        if set(observed[protocol].splitlines())!=expected:
            raise ValueError('adoption_Sieve_effective_drift:'+protocol)
    return {'status':'PASS','effective_sha256':sha(canonical(observed))}

def render(raw,layout):
    if (not isinstance(layout,dict) or set(layout)!={'format','kind','source_sha256','effective_sha256','effective'}
            or layout['format']!=1 or layout['kind']!='reviewed-include-tree' or sha(raw)!=layout['source_sha256']):
        raise ValueError('adoption_Sieve_layout_binding')
    if raw.count(b'!include conf.d/*.conf')!=1 or INCLUDE.strip() in raw or b'mail_sieve_session_lock' in raw:
        raise ValueError('adoption_Sieve_include_collision')
    content(layout)
    return raw+(b'' if raw.endswith(b'\n') else b'\n')+INCLUDE
