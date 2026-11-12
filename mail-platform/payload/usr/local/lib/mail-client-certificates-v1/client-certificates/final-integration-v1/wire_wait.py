"""New real-PHP timeout-vs-EOF cases, synthetic socket and no account access."""
import json
import socket
import struct
import subprocess
import threading
import time
def check(public,runtime):
    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    listener.bind(str(runtime/'wait.sock'));listener.listen(1);listener.settimeout(5)
    rows={}
    try:
        for name,delay,reply in (('delayed_reply',1.25,True),('true_eof',0,False),('absolute_deadline',3.6,False)):
            errors=[]
            def serve():
                try:
                    channel,_=listener.accept()
                    with channel:
                        time.sleep(delay)
                        if reply:
                            raw=b'{"fixture":true}';channel.sendall(struct.pack('!I',len(raw))+raw)
                except Exception as e:errors.append(type(e).__name__)
            worker=threading.Thread(target=serve);worker.start()
            done=subprocess.run(['/usr/bin/php8.4',str(public/'wire_wait_fixture.php')],capture_output=True,timeout=6)
            worker.join(5)
            if done.returncode or done.stderr or errors or worker.is_alive():raise ValueError('php_wait_fixture_execution')
            value=json.loads(done.stdout);rows[name]=value
            if name=='delayed_reply':valid=value['ok']and value['reply_matches']and 1100<=value['elapsed_ms']<2900
            elif name=='true_eof':valid=not value['ok']and value['reason']=='packet_wire_eof'and value['elapsed_ms']<1000
            else:valid=not value['ok']and value['reason']=='packet_wire_deadline'and 2900<=value['elapsed_ms']<3500
            if not valid:
                error=ValueError('php_wait_timeout_eof_or_deadline');error.details={'case':name,'observation':value};raise error
        return rows
    finally:listener.close()
