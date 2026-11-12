"""New nonroot IPC/DB proof and TLS-only public listener observation; never mail."""
import json
import os
import socket
import ssl

def auth_probe():
    import base64
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(35);s.connect('/var/spool/postfix/private/mail-legacy-smtp-v1/auth')
        s.sendall(b'VERSION\t1\t2\nCPID\t'+str(os.getpid()).encode()+b'\n')
        with s.makefile('rb',buffering=0) as f:
            for _ in range(20):
                line=f.readline(8193)
                if not line or len(line)>8192:raise ValueError('auth_handshake_bound')
                if line.startswith(b'DONE'):break
            else:raise ValueError('auth_handshake_missing')
            response=base64.b64encode(b'\0DeploymentProbeAbsent\0Synthetic-Only-Never-A-Real-Credential')
            s.sendall(b'AUTH\t1\tPLAIN\tservice=legacy-smtp\tsecured\tresp='+response+b'\n')
            line=f.readline(8193);parts=line.strip().split(b'\t')
            if parts[:2]!=[b'FAIL',b'1'] or b'code=temp_fail' in parts:raise ValueError('empty_table_DB_lookup_not_verified')
    return {'empty_table_only':True,'expected_unknown_ID_rejected':True,'internal_failure':False,'actual_account_used':False}

def tls_probe():
    codes=[]
    with socket.create_connection(('162.43.6.80',465),timeout=15) as raw:
        with ssl.create_default_context().wrap_socket(raw,server_hostname='mx.mi-sys.jp') as s:
            s.settimeout(15)
            with s.makefile('rb',buffering=0) as f:
                def reply():
                    result=[]
                    for _ in range(40):
                        line=f.readline(4097)
                        if len(line)>4096 or len(line)<5 or not line[:3].isdigit():raise ValueError('smtp_response_framing')
                        result.append(line)
                        if line[3:4]==b' ':return int(line[:3]),result
                    raise ValueError('smtp_response_bound')
                code,_=reply();codes.append(code)
                if code!=220:raise ValueError('smtp_greeting')
                s.sendall(b'EHLO mx.mi-sys.jp\r\n');code,lines=reply();codes.append(code)
                if code!=250 or not any(b'AUTH ' in line for line in lines):raise ValueError('TLS_AUTH_advertisement')
                s.sendall(b'QUIT\r\n');code,_=reply();codes.append(code)
                if code!=221:raise ValueError('smtp_QUIT')
    return {'server_certificate_and_hostname_verified':True,'client_certificate_used':False,'SMTP_codes':codes,'AUTH_executed':False,'DATA_sent':False}

if __name__=='__main__':
    import sys
    try:
        if sys.argv[1:]==['--auth-empty-table']:value=auth_probe()
        elif sys.argv[1:]==['--TLS-only']:value=tls_probe()
        else:raise ValueError('fixed_probe_argument')
        print(json.dumps({'status':'ok',**value}))
    except Exception as e:
        print(json.dumps({'status':'fail','class':type(e).__name__,'errno':getattr(e,'errno',None),'reason':str(e) if type(e)is ValueError else 'runtime_probe_failure','raw_error_output':False}));sys.exit(1)
