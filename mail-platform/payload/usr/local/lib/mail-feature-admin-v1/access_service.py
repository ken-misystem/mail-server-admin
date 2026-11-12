"""Nonroot socket-activated readonly RCPT policy, bounded peers/frames/concurrency."""
import hashlib,json,os,re,signal,socket,stat,struct,threading,time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from forwarding import need
from access_index import RuleIndex
from access_policy import decide,snapshot

SOCKET='/var/spool/postfix/private/mail-feature-access-v1.sock'
SNAPSHOT=Path('/run/mail-feature-policy-v1/access.json')

def parse(raw):
    need(type(raw)is bytes and len(raw)<=32768 and raw.endswith(b'\n\n')and raw.count(b'\n\n')==1,'policy_frame')
    result={}
    for line in raw[:-2].decode('utf-8','strict').split('\n'):
        key,separator,value=line.partition('=');need(separator and re.fullmatch('[a-z][a-z0-9_]{0,63}',key)is not None and key not in result and len(value)<=8192 and '\r'not in value and '\x00'not in value,'policy_attribute')
        result[key]=value;need(len(result)<=128,'policy_attribute_bound')
    return result

class CurrentSnapshot:
    def __init__(self,path,group):
        self.path=path;self.group=group;self.lock=threading.Lock();self.meta=None;self.value=None;self.index=None;self.pin=None
        opened=[os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)]
        try:
            for part in path.parts[1:-1]:
                opened.append(os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=opened[-1]));info=os.fstat(opened[-1]);need(info.st_uid==0 and not info.st_mode&0o022,'policy_snapshot_parent')
            info=os.fstat(opened[-1]);need(info.st_gid==group and stat.S_IMODE(info.st_mode)==0o750,'policy_snapshot_directory');self.directory=os.dup(opened[-1])
        finally:
            for fd in reversed(opened):os.close(fd)
    def load(self):
        with self.lock:
            fd=os.open(self.path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.directory)
            try:
                info=os.fstat(fd);need(stat.S_ISREG(info.st_mode)and info.st_uid==0 and info.st_gid==self.group and stat.S_IMODE(info.st_mode)==0o640 and info.st_nlink==1 and 0<info.st_size<=2097152,'policy_snapshot_file')
                key=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
                metadata=key(info)
                if metadata!=self.meta:
                    raw=os.pread(fd,info.st_size+1,0);need(len(raw)==info.st_size,'policy_snapshot_size')
                    def unique(pairs):
                        result={}
                        for k,v in pairs:need(k not in result,'policy_snapshot_duplicate_key');result[k]=v
                        return result
                    value=json.loads(raw,object_pairs_hook=unique)
                    need(type(value)is dict and set(value)=={'version','revision','observed_at','expires_at','rules','domain_ids','domain_aliases'}and type(value['version'])is int and value['version']==1,'policy_snapshot_schema')
                    reconstructed=snapshot({'rules':[dict(row,reason='operator')for row in value['rules']]},value['domain_ids'],value['domain_aliases'],value['revision'],value['observed_at'])
                    need(reconstructed==value,'policy_snapshot_semantics');pin=hashlib.sha256(raw).hexdigest()
                    if self.value is not None:need(value['revision']>=self.value['revision']and(value['revision']!=self.value['revision']or pin==self.pin),'policy_snapshot_rollback_or_reuse')
                    index=RuleIndex(value['rules'])
                else:value=self.value;index=self.index;pin=self.pin
                need(metadata==key(os.fstat(fd))==key(os.stat(self.path.name,dir_fd=self.directory,follow_symlinks=False)),'policy_snapshot_replaced_during_read')
                self.meta=metadata;self.value=value;self.index=index;self.pin=pin
                return value,index
            finally:os.close(fd)
    def close(self):os.close(self.directory)

def capabilities():
    fields=dict(line.split(':',1)for line in Path('/proc/self/status').read_text().splitlines()if':'in line)
    need(all(int(fields[key].strip(),16)==0 for key in ('CapEff','CapPrm','CapAmb'))and fields['NoNewPrivs'].strip()=='1','policy_capability_boundary')

def main():
    import pwd
    role=pwd.getpwnam('mailsendlimits');peer=pwd.getpwnam('postfix');need(os.geteuid()==role.pw_uid and os.getegid()==role.pw_gid and role.pw_uid>0 and peer.pw_uid>0 and role.pw_uid!=peer.pw_uid,'policy_roles');capabilities()
    need(os.environ.get('LISTEN_PID')==str(os.getpid())and os.environ.get('LISTEN_FDS')=='1','policy_socket_activation')
    listener=socket.socket(fileno=3);need(listener.family==socket.AF_UNIX and listener.getsockname()==SOCKET and listener.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN)==1,'policy_listener_identity');listener.set_inheritable(False);listener.settimeout(1)
    cache=CurrentSnapshot(SNAPSHOT,role.pw_gid);stop=threading.Event();limit=threading.BoundedSemaphore(32);active=set();active_lock=threading.Lock();pool=ThreadPoolExecutor(max_workers=16,thread_name_prefix='access-policy')
    signal.signal(signal.SIGTERM,lambda *_:stop.set());signal.signal(signal.SIGINT,lambda *_:stop.set())
    def serve(channel):
        try:
            channel.settimeout(2);pid,uid,gid=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));need(pid>0 and uid==peer.pw_uid,'policy_peer_uid')
            raw=bytearray();deadline=time.monotonic()+2
            while b'\n\n'not in raw:
                need(time.monotonic()<deadline and len(raw)<32768,'policy_input_bound');part=channel.recv(min(4096,32768-len(raw)));need(bool(part),'policy_input_eof');raw.extend(part)
            request=parse(bytes(raw));value,index=cache.load();action=decide(value,request,int(time.time()),index)
        except Exception:action='451 4.3.0 Administrative policy temporarily unavailable'
        try:channel.settimeout(1);channel.sendall(('action='+action+'\n\n').encode('ascii'))
        except OSError:pass
        finally:
            channel.close()
            with active_lock:active.discard(channel)
            limit.release()
    try:
        while not stop.is_set():
            try:channel,_=listener.accept()
            except socket.timeout:continue
            if not limit.acquire(blocking=False):
                try:channel.settimeout(.1);channel.sendall(b'action=451 4.3.0 Administrative policy busy\n\n')
                except OSError:pass
                finally:channel.close()
                continue
            with active_lock:active.add(channel)
            try:pool.submit(serve,channel)
            except Exception:
                channel.close()
                with active_lock:active.discard(channel)
                limit.release();raise
    finally:
        listener.close();pool.shutdown(wait=True,cancel_futures=True)
        with active_lock:
            for channel in active:channel.close()
        cache.close()
if __name__=='__main__':main()
