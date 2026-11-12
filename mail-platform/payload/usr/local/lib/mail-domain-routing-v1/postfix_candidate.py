"""Pure candidate generation. Never writes/reloads Postfix; refuse unknown profiles."""
import re
from routing import need

SOCKET = 'socketmap:unix:private/mail-domain-routing-v1:'


def build(main, master, effective):
    need(type(main) is bytes and type(master) is bytes and b'\r' not in main+master
         and main.endswith(b'\n') and master.endswith(b'\n'), 'native_lf_profile')
    line = b'transport_maps = ' + (SOCKET+'route').encode()
    matches = list(re.finditer(rb'(?m)^transport_maps[ \t]*=[^\n]*(?:\n[ \t]+[^\n]*)*',main))
    need(len(matches)==1, 'one_current_transport_map_required')
    current = matches[0]
    need(current[0].split(b'=',1)[1].strip()==b'texthash:/etc/postfix/transport-yukido-old-overlap-v1',
         'current_approved_old_route_required')
    after = main[:current.start()]+line+main[current.end():]
    rows=[]
    for value in master.decode('ascii','strict').splitlines():
        if not value.strip() or value.lstrip().startswith('#'):
            continue
        if value[:1].isspace():
            need(bool(rows),'master_orphan');rows[-1]+=' '+value.strip()
        else:rows.append(value)
    need(not any(v.split()[0]=='mx-follow-smtp' for v in rows),'transport_already_present')
    smtp=[v.split() for v in rows if v.split()[0]=='smtp' and len(v.split())>1 and v.split()[1]=='unix']
    need(len(smtp)==1 and len(smtp[0])>=8 and smtp[0][7]=='smtp','native_smtp_transport_required')
    row=smtp[0]; row[0]='mx-follow-smtp'
    need(len(row[8:])%2==0,'smtp_override_shape')
    forbidden={'smtp_host_lookup','smtp_dns_reply_filter','smtp_delivery_status_filter','smtp_dns_support_level'}
    for flag,value in zip(row[8::2],row[9::2]):
        need(flag=='-o' and '=' in value and value.split('=',1)[0] not in forbidden,'smtp_override_not_supported')
    # Preserve all existing smtp privilege/chroot/process-limit fields and safe overrides.
    # No TLS security/certificate/DANE or SMTP authentication settings are weakened.
    appended=' '.join(row)+'\n'
    filters={}
    for key in ('smtp_dns_reply_filter','smtp_delivery_status_filter'):
        need(key in effective and type(effective[key]) is str
             and re.fullmatch(r'[A-Za-z0-9_:/.,-]*',effective[key]) is not None,'expanded_filter_profile')
        filters[key]=effective[key]
    need(effective.get('smtp_host_lookup','dns') in ('dns','dns, native','dns,native')
         and effective.get('smtp_dns_support_level','') in ('','enabled','dnssec')
         and effective.get('disable_dns_lookups','no')=='no','current_dns_profile')
    for key,value in (
        ('smtp_host_lookup','dns'),
        ('smtp_dns_reply_filter',SOCKET+'dns'+(','+filters['smtp_dns_reply_filter'] if filters['smtp_dns_reply_filter'] else '')),
        ('smtp_delivery_status_filter',SOCKET+'status'+(','+filters['smtp_delivery_status_filter'] if filters['smtp_delivery_status_filter'] else ''))):
        appended+='  -o '+key+'='+value+'\n'
    return after,master+b'\n# Domain MX-following transport; generated candidate only\n'+appended.encode()


def verify_effective(before,after):
    """Native postconf profile guard, to be exercised by private Linux validation."""
    need(before.get('smtp_host_lookup','dns') in ('dns','dns, native','dns,native'), 'host_lookup_profile')
    need(before.get('smtp_dns_support_level','') in ('','enabled','dnssec'), 'dns_support_profile')
    need(before.get('disable_dns_lookups','no')=='no','dns_disabled')
    changed={k for k in before.keys()|after.keys() if before.get(k)!=after.get(k)}
    need(changed=={'transport_maps'} and after['transport_maps']==SOCKET+'route','only_transport_delta')
