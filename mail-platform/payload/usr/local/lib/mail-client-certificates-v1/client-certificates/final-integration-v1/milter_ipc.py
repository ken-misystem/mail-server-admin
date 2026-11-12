"""Postfix-UID-only Unix IPC to the existing fixed loopback Rspamd endpoint.

No caller-controlled host/port, message logging or protocol modification. The
existing localhost Milter service remains a trusted server dependency; TCP does
not provide SO_PEERCRED for that destination. Source IPC IS kernel authenticated.
"""
import selectors
import socket
import time
from peer import need,identity
def relay(left,right,clock,deadline,idle=30):
    selector=selectors.DefaultSelector();selector.register(left,selectors.EVENT_READ,right);selector.register(right,selectors.EVENT_READ,left)
    last=clock()
    try:
        while selector.get_map():
            now=clock();need(now<deadline and now-last<idle,'milter_relay_deadline')
            for key,_ in selector.select(min(.25,deadline-now)):
                source,destination=key.fileobj,key.data;source.settimeout(min(idle,deadline-clock()));raw=source.recv(65536)
                if not raw:
                    selector.unregister(source)
                    try:destination.shutdown(socket.SHUT_WR)
                    except OSError:pass
                else:
                    destination.settimeout(min(idle,deadline-clock()));destination.sendall(raw);last=clock()
    finally:selector.close()
class MilterIPC:
    def __init__(self,runtime,postfix_uid,postfix_gid,service_guard,audit):
        need(type(postfix_uid)is int and postfix_uid>0 and type(postfix_gid)is int and postfix_gid>0,'milter_postfix_identity')
        self.runtime,self.uid,self.gid,self.service_guard,self.audit=runtime,postfix_uid,postfix_gid,service_guard,audit
    def one(self,channel):
        upstream=None
        try:
            self.runtime.require_armed();pid,uid,gid=identity(channel);need(pid>0 and(uid,gid)==(self.uid,self.gid),'milter_unix_peer')
            self.service_guard();upstream=socket.socket(socket.AF_INET,socket.SOCK_STREAM);upstream.settimeout(5);upstream.connect(('127.0.0.1',11332))
            self.service_guard();relay(channel,upstream,time.monotonic,time.monotonic()+300);return True
        except Exception as error:self.audit.failure(error,'milter_ipc');return False
        finally:
            channel.close()
            if upstream is not None:upstream.close()
