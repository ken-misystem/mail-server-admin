"""Standard fetchmail 6.4 UIDL framing/binding; no files, processes or network."""
import ipaddress
import re


def need(value, reason):
    if not value:
        raise ValueError(reason)


def public_ip(value):
    need(isinstance(value, str) and '%' not in value, 'queryname_invalid')
    address = ipaddress.ip_address(value)
    need(address.is_global and not address.is_multicast and not address.is_reserved
         and getattr(address, 'ipv4_mapped', None) is None, 'queryname_not_public')
    need(str(address) == value, 'queryname_not_canonical')
    return value


def binding(account_id, host, port, username, queryname):
    need(isinstance(account_id, str) and re.fullmatch(r'[1-9][0-9]{0,19}', account_id)
         and int(account_id) <= 18446744073709551615, 'binding_account')
    need(isinstance(host, str) and host == host.lower() and 0 < len(host) <= 253
         and '.' in host and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x)
                                 for x in host.split('.')), 'binding_host')
    need(type(port) is int and 0 < port <= 65535, 'binding_port')
    # Match the standard reader: spaces before the first @ are supported, not after it.
    need(isinstance(username, str) and 0 < len(username) <= 320 and username.strip(' ') == username
         and all(32 <= ord(c) <= 126 for c in username)
         and ('@' not in username or ' ' not in username.split('@', 1)[1]), 'binding_username')
    public_ip(queryname)
    return {'version': 1, 'format': 'fetchmail-6.4', 'account_id': account_id,
            'host': host, 'port': port, 'username': username, 'queryname': queryname}


def require_binding(saved, account_id, host, port, username, queryname):
    """Call before rendering rcfile/retrieval. IP/source drift stops; never clear old IDs."""
    expected = binding(account_id, host, port, username, queryname)
    need(isinstance(saved, dict) and saved == expected, 'history_binding_changed')
    return expected


def encode_seen(saved, uidls):
    require_binding(saved, saved['account_id'], saved['host'], saved['port'],
                    saved['username'], saved['queryname'])
    need(isinstance(uidls, set) and 0 < len(uidls) <= 2000000, 'history_count')
    prefix = saved['username'] + '@' + saved['queryname'] + ' '
    for uidl in uidls:
        # RFC1939 UIDL: 1..70 printable non-space ASCII bytes; never truncate.
        need(isinstance(uidl, str) and 0 < len(uidl) <= 70
             and all(33 <= ord(c) <= 126 for c in uidl), 'history_uidl')
        need(len(prefix) + len(uidl) + 1 < 512, 'history_line_bound')
    data = ''.join(prefix + uidl + '\n' for uidl in sorted(uidls)).encode('ascii')
    need(len(data) <= 128 * 1024 * 1024, 'history_size')
    return data
