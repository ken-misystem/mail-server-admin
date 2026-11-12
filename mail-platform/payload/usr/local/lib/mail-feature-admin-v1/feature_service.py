"""Socket-activated root queue/control broker; never executes frontend commands."""
import contextlib,hashlib,json,os,pwd,signal,socket,sqlite3,stat,struct,time,traceback,uuid
from pathlib import Path
from feature_broker import FeatureBroker
from bridge import ProtectionBridge
from native_queue import NativeQueue
from owner_directory import Directory
from queue_admin import need
from owner_stop_file import decode
from load_credential import credential
from process_lease import ProcessLease

STATE=Path('/var/lib/mail-feature-admin-v1')
SOCKET='/run/mail-feature-admin-v1/control.sock'
LEDGER=Path('/var/lib/mail-send-limits-v1/ledger.sqlite')

def atomic(path,raw,group,mode=0o640):
    need(path.parent==STATE/'public-stops','public_stop_boundary')
    info=path.parent.lstat();need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and info.st_gid==group and stat.S_IMODE(info.st_mode)==0o750,'public_stop_directory')
    temporary=path.with_name('.'+uuid.uuid4().hex)
    with temporary.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno());os.fchown(f.fileno(),0,group);os.fchmod(f.fileno(),mode)
    os.replace(temporary,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
    named=path.lstat();need(named.st_uid==0 and named.st_gid==group and stat.S_IMODE(named.st_mode)==mode,'public_stop_readback')
    need(path.read_bytes()==raw,'public_stop_readback')

def unique(pairs):
    value={}
    for key,item in pairs:need(key not in value,'duplicate_request_key');value[key]=item
    return value

def terminate(signum,frame):
    # SystemExit runs the finally blocks; an interrupted intent stays pending.
    raise SystemExit(0)

def main(driver):
    signal.signal(signal.SIGTERM,terminate)
    need(os.geteuid()==0 and os.environ.get('LISTEN_PID')==str(os.getpid()) and os.environ.get('LISTEN_FDS')=='1','feature_socket_activation')
    actor=pwd.getpwnam('mailadmin');policy=pwd.getpwnam('mailsendlimits')
    need(actor.pw_uid>0 and policy.pw_uid>0 and actor.pw_uid!=policy.pw_uid,'feature_roles')
    st=STATE.lstat();need(stat.S_ISDIR(st.st_mode) and st.st_uid==0 and stat.S_IMODE(st.st_mode)==0o700,'feature_private_state')
    lease=ProcessLease(STATE/'control.lock');db=None;listener=None
    def private_failure(metadata,out=b'',err=b''):
        # Private bounded per-failure evidence, with a capped number of records.
        directory=STATE/'diagnostics';info=directory.lstat();need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700,'diagnostic_directory')
        if len(list(directory.iterdir()))>=300:return
        name=uuid.uuid4().hex
        for suffix,raw in (('json',(json.dumps(metadata,sort_keys=True)+'\n').encode()),('stdout',out),('stderr',err)):
            with (directory/(name+'.'+suffix)).open('xb') as f:
                os.fchmod(f.fileno(),0o600);f.write(raw[:8*1024*1024]);f.flush();os.fsync(f.fileno())
    try:
        path=STATE/'controls.sqlite';info=path.lstat();need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600,'control_database')
        db=sqlite3.connect(path.as_uri()+'?mode=rw',uri=True,timeout=1)
        need(db.execute('PRAGMA quick_check').fetchall()==[('ok',)],'control_database_integrity')
        secret=credential(os.environ['CREDENTIALS_DIRECTORY'])
        need(secret['user']=='mail_feature_reader' and type(secret['password'])is str and 16<=len(secret['password'])<=256,'feature_DB_credential')
        def connect():return driver.connect(unix_socket='/run/mysqld/mysqld.sock',user=secret['user'],password=secret['password'],charset='utf8mb4',
            connect_timeout=2,read_timeout=3,write_timeout=3,autocommit=False,local_infile=False,client_flag=0)
        directory=Directory(connect)
        @contextlib.contextmanager
        def ledger_read():
            info=LEDGER.lstat();need(stat.S_ISREG(info.st_mode) and info.st_uid==policy.pw_uid and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600,'existing_send_ledger')
            connection=sqlite3.connect(LEDGER.as_uri()+'?mode=ro',uri=True,timeout=.1)
            try:yield connection
            finally:connection.close()
        def publish(value):
            if value.get('state')!='updating':decode(json.dumps(value).encode())
            atomic(STATE/'public-stops/stops.json',(json.dumps(value,sort_keys=True)+'\n').encode(),policy.pw_gid)
        runner=NativeQueue(private_failure);broker=ProtectionBridge(FeatureBroker(runner,db,directory,publish,ledger_read,time.time),db,directory,time.time);broker.start()
        listener=socket.socket(fileno=3)
        need(listener.family==socket.AF_UNIX and listener.getsockname()==SOCKET and listener.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN)==1,'feature_socket_identity')
        listener.set_inheritable(False)
        while True:
            channel,_=listener.accept()
            try:
                channel.settimeout(3);pid,uid,gid=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                need(pid>0 and uid in (0,actor.pw_uid),'feature_peer_UID')
                raw=bytearray();deadline=time.monotonic()+3
                while b'\n' not in raw:
                    need(time.monotonic()<deadline and len(raw)<32768,'feature_request_bound');part=channel.recv(min(4096,32768-len(raw)))
                    need(bool(part),'feature_request_EOF');raw.extend(part)
                need(raw.endswith(b'\n') and raw.count(b'\n')==1,'feature_request_frame')
                request=json.loads(raw,object_pairs_hook=unique)
                runner.deadline=time.monotonic()+10
                data=broker.handle(request,peer='collector' if uid==0 else 'frontend');reply={'status':'ok','data':data}
            except Exception as error:
                try:private_failure({'class':type(error).__name__,'trace_private':True},err=traceback.format_exc().encode()[:131072])
                except Exception:
                    # Do not continue after loss of diagnostic storage.
                    raise RuntimeError('feature_diagnostic_storage_unavailable') from None
                reply={'status':'error','reason':'feature_operation_unavailable'}
            try:channel.settimeout(2);channel.sendall(json.dumps(reply,separators=(',',':')).encode()+b'\n')
            except OSError:pass
            finally:channel.close()
    finally:
        if listener is not None:listener.close()
        if db is not None:db.close()
        lease.close()

if __name__=='__main__':
    import pymysql
    main(pymysql)
