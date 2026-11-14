"""Drop to the configured policy peer before a bounded Unix health request."""
import ctypes
import json
import os
from pathlib import Path
import socket
import sys

def main():
    raw=sys.stdin.buffer.read(32769)
    if len(raw)>32768:
        raise ValueError('probe_input_limit')
    value=json.loads(raw)
    fields={'kind','request','reply','peer_uid','peer_gid','socket'}
    if set(value)!=fields or value['kind']!='policy':
        raise ValueError('probe_fields')
    if any(type(value[key]) is not int or value[key]<=0 for key in ('peer_uid','peer_gid')):
        raise ValueError('probe_identity')
    if (type(value['socket']) is not str or not value['socket'].startswith('/') or '..' in Path(value['socket']).parts or
            any(type(value[key]) is not str or not 0<len(value[key])<=16384 for key in ('request','reply'))):
        raise ValueError('probe_values')
    os.setgroups([])
    os.setgid(value['peer_gid'])
    os.setuid(value['peer_uid'])
    if ctypes.CDLL(None,use_errno=True).prctl(38,1,0,0,0)!=0:
        raise OSError(ctypes.get_errno(),'probe_no_new_privileges')
    status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if any(int(status[key].strip(),16) for key in ('CapEff','CapPrm','CapAmb')):
        raise ValueError('probe_capabilities')
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(3)
        connection.connect(value['socket'])
        connection.sendall(value['request'].encode())
        received=bytearray()
        while len(received)<65536:
            block=connection.recv(4096)
            if not block:break
            received.extend(block)
            if value['reply'].encode() in received:
                print(json.dumps({'status':'PASS','uid':os.geteuid(),'gid':os.getegid(),
                                  'capabilities_zero':True,'NoNewPrivileges':True}))
                return
        print(json.dumps({'observed_reply_hex':bytes(received[:4096]).hex(),
                          'observed_bytes':len(received)}))
    raise ValueError('policy_health_reply')

if __name__=='__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status':'FAIL','class':type(error).__name__,'reason':str(error),
                          'errno':getattr(error,'errno',None)}))
        raise SystemExit(1)
