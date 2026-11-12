"""Nonroot socket-activated policy worker with systemd credentials and FULL ledger."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import stat
import sys
import threading
import time
import uuid
from batch_ledger import BatchLedger
from batch_writer import BatchWriter
from process_lease import ProcessLease
from profile_connection import Service
from policy_database import Reader, connector
from policy import UNAVAILABLE, need
from rollup import migrate, validate


def credential(directory, on_metadata=None):
    descriptor=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        file=os.open('db.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=descriptor)
        try:
            info=os.fstat(file)
            facts={'uid':info.st_uid,'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode),
                'nlink':info.st_nlink,'bytes':info.st_size,'euid':os.geteuid(),'egid':os.getegid(),
                'regular':stat.S_ISREG(info.st_mode)}
            if on_metadata is not None:
                on_metadata(facts)
            need(facts['regular'] and info.st_nlink==1 and info.st_uid in (0,os.geteuid())
                 and stat.S_IMODE(info.st_mode) in (0o400,0o440) and info.st_gid in (0,os.getegid())
                 and 0<info.st_size<=4096,'credential_metadata')
            raw=os.pread(file,info.st_size+1,0)
            final=os.fstat(file)
            named=os.stat('db.json',dir_fd=descriptor,follow_symlinks=False)
            key=lambda value:(value.st_dev,value.st_ino,value.st_uid,value.st_gid,value.st_mode,
                              value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
            need(len(raw)==info.st_size and key(info)==key(final)==key(named),'credential_changed')
            value=json.loads(raw)
            need(type(value) is dict and set(value)=={'user','password'},'credential_fields')
            return value
        finally:
            os.close(file)
    finally:
        os.close(descriptor)


def security(config):
    need(type(config) is dict and set(config)=={'uid','peer_uid','socket','state','database_socket'},'runtime_config')
    need(type(config['uid']) is int and config['uid']>0 and os.geteuid()==config['uid'],'nonroot_identity')
    need(type(config['peer_uid']) is int and config['peer_uid']>0,'peer_identity')
    need(all(type(config[key]) is str and config[key].startswith('/') and '\0' not in config[key]
             for key in ('socket','state','database_socket')),'runtime_paths')
    proc=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    need(all(int(proc[key].strip(),16)==0 for key in ('CapEff','CapPrm','CapAmb'))
         and proc['NoNewPrivs'].strip()=='1','runtime_privileges')
    info=os.stat(config['state'],follow_symlinks=False)
    need(stat.S_ISDIR(info.st_mode) and info.st_uid==config['uid'] and stat.S_IMODE(info.st_mode)==0o700,'state_directory')
    return {'uid':os.geteuid(),'gid':os.getegid(),'capabilities_zero':True,'no_new_privileges':True}


@contextmanager
def ledger(state):
    lease=ProcessLease(state/'writer.lock')
    database=None
    try:
        path=state/'ledger.sqlite'
        fresh=False
        try:
            fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        except FileExistsError:
            info=os.stat(path,follow_symlinks=False)
            need(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and info.st_nlink==1
                 and stat.S_IMODE(info.st_mode)==0o600,'ledger_metadata')
        else:
            os.close(fd)
            fresh=True
        database=sqlite3.connect(path.as_uri()+'?mode=rw',uri=True,isolation_level=None)
        need(database.execute('PRAGMA journal_mode=WAL').fetchone()==('wal',),'ledger_WAL')
        if fresh:
            database.executescript((Path(__file__).parent/'ledger-schema.sql').read_text())
            migrate(database)
        validate(database)
        yield BatchLedger(database)
    finally:
        try:
            if database is not None:
                database.close()
        finally:
            lease.close()


def activated_listener(config):
    need(os.environ.get('LISTEN_PID')==str(os.getpid()) and os.environ.get('LISTEN_FDS')=='1','activation_contract')
    listener=socket.socket(fileno=3)
    try:
        need(listener.family==socket.AF_UNIX and listener.type==socket.SOCK_STREAM
             and listener.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN)==1
             and listener.getsockname()==config['socket'],'activation_socket')
        listener.set_inheritable(False)
        listener.settimeout(0.2)
        return listener
    except BaseException:
        listener.close()
        raise


def run(config,driver):
    facts=security(config)
    os.umask(0o077)
    state=Path(config['state'])
    db_credentials=credential(os.environ['CREDENTIALS_DIRECTORY'],
        lambda facts:print(json.dumps({'credential_metadata':facts}),file=sys.stderr,flush=True))
    stop=threading.Event()
    channels=set()
    lock=threading.Lock()
    counters={'connections':0,'capacity_rejected':0,'database_failures':0}
    last_failure={}
    def failed(row):
        with lock:
            counters['database_failures']+=1
            last_failure.clear()
            last_failure.update(row)
    reader=Reader(connector(driver,config['database_socket'],db_credentials),failed)
    writer=BatchWriter(lambda:ledger(state))
    service=Service(reader,writer)
    listener=None
    def publish(final=False):
        with lock:
            value={'security':facts,'counters':dict(counters),'database_failure':dict(last_failure),
                'writer':writer.snapshot(),'final':final,'at':int(time.time())}
        temporary=state/('status-'+uuid.uuid4().hex+'.tmp')
        with temporary.open('xb') as stream:
            stream.write((json.dumps(value)+'\n').encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary,state/'status.json')
    def handle(channel):
        try:
            service.serve(channel,config['peer_uid'])
        finally:
            with lock:
                channels.discard(channel)
    signal.signal(signal.SIGTERM,lambda *_:stop.set())
    signal.signal(signal.SIGINT,lambda *_:stop.set())
    try:
        listener=activated_listener(config)
        publish()
        with ThreadPoolExecutor(max_workers=32) as pool:
            try:
                updated=time.monotonic()
                while not stop.is_set():
                    try:
                        channel,_=listener.accept()
                    except socket.timeout:
                        if time.monotonic()-updated>=1:
                            publish()
                            updated=time.monotonic()
                        continue
                    with lock:
                        counters['connections']+=1
                        accepted=len(channels)<32
                        if accepted:
                            channels.add(channel)
                        else:
                            counters['capacity_rejected']+=1
                    if accepted:
                        pool.submit(handle,channel)
                    else:
                        try:
                            channel.settimeout(1)
                            channel.sendall(UNAVAILABLE)
                        finally:
                            channel.close()
            finally:
                with lock:
                    active=list(channels)
                for channel in active:
                    try:
                        channel.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
    finally:
        if listener is not None:
            listener.close()
        try:
            writer.close()
        finally:
            publish(final=True)


def main():
    import sys
    need(len(sys.argv)==2,'config_argument')
    import pymysql
    run(json.loads(Path(sys.argv[1]).read_bytes()),pymysql)


if __name__=='__main__':
    main()
