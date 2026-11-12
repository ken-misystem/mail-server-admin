"""Bounded actor-owned Unix listener, standard-library dependencies only."""
import os
import socket
import threading
from safety import need

class Listener:
    def __init__(self,path,group,handler,mode=0o660):
        need(type(path)is str and type(group)is int and group>0 and mode==0o660,'actor_listener_contract')
        self.path,self.handler=path,handler;self.stop=threading.Event();self.slots=threading.BoundedSemaphore(32);self.children=[]
        self.socket=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            # Never unlink an earlier actor's socket or uncertain evidence.
            need(not os.path.lexists(path),'actor_listener_exists');self.socket.bind(path);os.chown(path,-1,group);os.chmod(path,mode)
            self.socket.listen(32);self.socket.settimeout(.25)
        except BaseException:self.socket.close();raise
    def loop(self):
        while not self.stop.is_set():
            try:channel,_=self.socket.accept()
            except socket.timeout:continue
            except OSError:
                if self.stop.is_set():break
                raise
            if not self.slots.acquire(False):channel.close();continue
            def serve(ch):
                try:self.handler(ch)
                finally:self.slots.release()
            thread=threading.Thread(target=serve,args=(channel,),daemon=True);self.children=[t for t in self.children if t.is_alive()];self.children.append(thread);thread.start()
    def close(self):
        self.stop.set();self.socket.close()
        for child in self.children:child.join(6)
        need(not any(c.is_alive()for c in self.children),'actor_connections_not_drained')
