"""Incremental bounded collector. Root-private SQLite, immutable public JSON pages.
Web processes never run journalctl, read source logs, or require SQLite extensions.
"""
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import sqlite3
import stat
import subprocess
import sys
import time
import traceback
from events import CATEGORIES,UNITS,decode_json,event,sanitize

ROOT=Path('/var/lib/mail-management-log-viewer-v1')
MAX_EVENTS=20000;MAX_AGE=7*86400;PAGE_SIZE=25
MAX_READ=2*1024*1024;MAX_BATCH=1000;DEADLINE=4
GROUP=113

class NativeFailure(RuntimeError):
    def __init__(self,exit,reason):
        self.exit=exit;super().__init__('journal_failed exit='+str(exit)+' reason='+reason)

def need(ok,reason):
    if not ok:raise ValueError(reason)
def encode(data):return (json.dumps(data,ensure_ascii=False,separators=(',',':'))+'\n').encode()
def guarded(path,directory=False):
    s=path.lstat();need(not path.is_symlink()and s.st_uid==0 and not s.st_mode&0o022,'unsafe_owner_mode')
    need(stat.S_ISDIR(s.st_mode)if directory else stat.S_ISREG(s.st_mode)and s.st_nlink==1,'unsafe_type')
    return s
def setup_db(path):
    db=sqlite3.connect(path,timeout=.1)
    db.execute('PRAGMA journal_mode=WAL');db.execute('PRAGMA synchronous=FULL')
    db.execute('CREATE TABLE IF NOT EXISTS state(name TEXT PRIMARY KEY,value TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,origin TEXT UNIQUE NOT NULL,ts INTEGER NOT NULL,data TEXT NOT NULL)')
    db.execute('CREATE INDEX IF NOT EXISTS event_time ON events(ts)');db.commit();return db
def value(db,key,default=''):
    row=db.execute('SELECT value FROM state WHERE name=?',(key,)).fetchone();return row[0]if row else default
def state(db,key,text):db.execute('INSERT INTO state VALUES(?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value',(key,str(text)))

def roundcube_stamp(value):
    # PHP date('M') is English; do not depend on the collector process locale.
    months={name:i+1 for i,name in enumerate(('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'))}
    parts=value.split('-',2);need(len(parts)==3 and parts[1]in months,'roundcube_month')
    return dt.datetime.strptime(parts[0]+'-'+str(months[parts[1]])+'-'+parts[2],'%d-%m-%Y %H:%M:%S %z').timestamp()

def ingest(db,rows,now_us,cursor_key='cursor'):
    """Advance position for every valid record, including intentionally hidden debug/binary."""
    saved=skipped=0;last=None
    with db:
        for raw in rows:
            row=decode_json(raw);item=event(row,now_us)
            if item is None:skipped+=1
            else:
                cur=db.execute('INSERT OR IGNORE INTO events(origin,ts,data) VALUES(?,?,?)',(item.pop('origin'),item['ts'],encode(item).decode()))
                saved+=cur.rowcount
            last=row['__CURSOR']
        if last:state(db,cursor_key,last)
        state(db,'skipped_total',int(value(db,'skipped_total','0'))+skipped)
        db.execute('DELETE FROM events WHERE ts<?',(now_us-MAX_AGE*1000000,))
        db.execute('DELETE FROM events WHERE id <= COALESCE((SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?),-1)',(MAX_EVENTS,))
    return {'inserted':saved,'hidden':skipped,'rows':len(rows)}

def argv(cursor,now,worker=False):
    args=['/usr/bin/journalctl','--quiet','--no-pager','--no-tail','--output=json',
          '--output-fields=__CURSOR,__REALTIME_TIMESTAMP,MESSAGE,PRIORITY,SYSLOG_IDENTIFIER,_SYSTEMD_UNIT',
          '--after-cursor='+cursor if cursor else'--since=@'+str(int(now)-900)]
    # Exact mail facility OR fixed units. No unbounded all-system journal access.
    if worker:return args+['--unit=mail-pop-source@*.service']
    args+=['SYSLOG_FACILITY=2']
    for unit in UNITS:args+=['+','_SYSTEMD_UNIT='+unit]if '*'not in unit else []
    return args

def read_journal(cursor,now,worker=False):
    command=argv(cursor,now,worker)
    p=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        env={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C'},start_new_session=True)
    select=selectors.DefaultSelector();select.register(p.stdout,selectors.EVENT_READ,'out');select.register(p.stderr,selectors.EVENT_READ,'err')
    rows=[];buffer=bytearray();stderr=bytearray();bytes_read=0;reason='complete';start=time.monotonic()
    try:
        while select.get_map():
            if time.monotonic()-start>DEADLINE:reason='time_budget';break
            for key,_ in select.select(.1):
                chunk=os.read(key.fileobj.fileno(),8192)
                if not chunk:select.unregister(key.fileobj);continue
                if key.data=='err':
                    stderr.extend(chunk[:max(0,8192-len(stderr))]);continue
                bytes_read+=len(chunk);buffer.extend(chunk)
                while b'\n'in buffer:
                    line,_,rest=buffer.partition(b'\n');buffer=bytearray(rest)
                    need(len(line)<=65536,'journal_line_limit')
                    if line:rows.append(bytes(line))
                    if len(rows)>=MAX_BATCH:reason='row_budget';break
                if reason!='complete':break
                if len(buffer)>65536:raise ValueError('journal_line_limit')
                if bytes_read>=MAX_READ:reason='byte_budget';break
            if reason!='complete':break
        if reason!='complete':os.killpg(p.pid,signal.SIGTERM)
        try:rc=p.wait(timeout=1)
        except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);rc=p.wait(timeout=1)
        if stderr or (rc!=0 and reason=='complete'):
            # No fallback/reset on a missing/invalid cursor. Retain old state and show error.
            raise NativeFailure(rc,sanitize(stderr.decode('utf-8','replace')))
        if buffer and reason=='complete':raise ValueError('journal_incomplete_line')
        return rows,{'status':'ok','exit':rc,'reason':reason,'bytes':bytes_read,'rows':len(rows),'backlog':reason!='complete','last_success':int(now)}
    finally:
        if p.poll()is None:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=1)
        select.close();p.stdout.close();p.stderr.close()

def read_roundcube(db,now):
    """One fixed physical log, bounded increment; never visit the /var/lib alias."""
    import re
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for piece in ('var','log','roundcube'):
            new=os.open(piece,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=new
            ps=os.fstat(fd);need(ps.st_uid in ((0,33)if piece=='roundcube'else(0,))and not ps.st_mode&0o022,'roundcube_parent_mode')
        ps=os.fstat(fd);need(ps.st_uid in (0,33)and not ps.st_mode&0o022,'roundcube_parent_mode')
        candidates=[]
        for leaf in ('errors','errors.log'):
            try:s=os.stat(leaf,dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError:continue
            need(stat.S_ISREG(s.st_mode)and s.st_uid in (0,33)and not s.st_mode&0o022 and s.st_nlink==1,'roundcube_log_type')
            candidates.append((leaf,s))
        need(len(candidates)==1,'roundcube_log_not_unique_or_missing')
        leaf,s=candidates[0];log=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
        try:
            held=os.fstat(log);need((s.st_dev,s.st_ino)==(held.st_dev,held.st_ino),'roundcube_open_race')
            inode=str(held.st_dev)+':'+str(held.st_ino);prior_inode=value(db,'file_inode')
            previous=int(value(db,'file_offset','0'))
            first=prior_inode!=inode or previous>held.st_size
            offset=max(0,held.st_size-65536)if first else previous
            os.lseek(log,offset,os.SEEK_SET);raw=os.read(log,min(65536,held.st_size-offset))
            end=raw.rfind(b'\n')+1;complete=raw[:end];rows=[];position=offset
            need(end>0 or len(raw)<65536,'roundcube_line_exceeds_read_budget')
            lines=complete.splitlines(keepends=True);continuations=0
            if first and offset>0 and lines and os.pread(log,1,offset-1)!=b'\n':position+=len(lines.pop(0))
            for line in lines:
                position+=len(line);text=line.decode('utf-8','replace').rstrip('\r\n')
                m=re.match(r'^\[([0-9]{2}-[A-Za-z]{3}-[0-9]{4} [0-9:]{8} [+-][0-9]{4})\]:?\s*(?:<[A-Za-z0-9_-]{1,128}>\s*)?(.*)$',text)
                if m is None:
                    # Never render stack argument dumps; retain the timestamped error
                    # header/primary reason and keep subsequent collection progressing.
                    need(not text.startswith('['),'roundcube_timestamp_unrecognized')
                    continuations+=1;continue
                stamp=roundcube_stamp(m[1])
                if not first or stamp>=now-900:
                    rows.append(encode({'__CURSOR':'file:'+inode+':'+str(position),'__REALTIME_TIMESTAMP':str(int(stamp*1e6)),
                        'SYSLOG_IDENTIFIER':'roundcube','MESSAGE':m[2],'PRIORITY':'3'}))
            need(os.fstat(log).st_size>=held.st_size,'roundcube_truncated_during_read')
            return rows,{'status':'ok','reason':'incomplete_line'if len(raw)>end else'rotation_observed'if first and prior_inode else'complete','exit':None,
                'bytes':len(raw),'rows':len(rows),'last_success':int(now),'backlog':(position if end else offset)<held.st_size,
                'suppressed_continuation_lines':continuations},(inode,position if end else offset)
        finally:os.close(log)
    finally:os.close(fd)

def atomic(path,raw,group=None):
    temp=path.with_name('.'+path.name+'.tmp-'+str(os.getpid()))
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
    try:
        if group is not None:os.fchown(fd,0,group)
        with os.fdopen(fd,'wb',closefd=False)as f:f.write(raw);f.flush();os.fsync(f.fileno())
        os.fchmod(fd,0o640)
    finally:os.close(fd)
    if path.exists():guarded(path)
    os.replace(temp,path)

def publish(db,directory,now,status,group=None):
    pages=directory/'pages';need(pages.is_dir()and not pages.is_symlink(),'pages_directory')
    prior_path=directory/'index.json';prior=None
    if prior_path.exists():
        need(prior_path.stat().st_size<=262144,'prior_index_bound');prior=decode_json(prior_path.read_bytes())
    count,oldest,latest=db.execute('SELECT COUNT(*),MIN(id),MAX(id) FROM events').fetchone()
    need(count<=MAX_EVENTS,'event_retention_limit')
    version=[count,oldest,latest]
    if prior and prior.get('version')==version:
        entries=prior['pages'] # No repeated JSON export/hash when only health time changes.
    else:
        entries=[];current=[]
        prior_pages={(p['min'],p['max']):p for p in prior['pages']}if prior else{}
        def flush():
            if not current:return
            raw=encode(current);need(len(raw)<=65536,'page_byte_limit')
            digest=hashlib.sha256(raw).hexdigest();dest=pages/(digest+'.json')
            if dest.exists():
                need(not dest.is_symlink()and dest.stat().st_size==len(raw)and hashlib.sha256(dest.read_bytes()).hexdigest()==digest,'existing_page_drift')
            else:atomic(dest,raw,group)
            entries.append({'hash':digest,'min':current[0]['id'],'max':current[-1]['id'],
                'start':min(e['ts']for e in current),'end':max(e['ts']for e in current),
                'categories':sorted({e['category']for e in current}),'levels':sorted({e['level']for e in current})})
        # Scan compact indexed IDs, not every payload; unchanged immutable pages need
        # no JSON decode, hash calculation or rewrite on each collection cycle.
        for low,high in db.execute('SELECT MIN(id),MAX(id) FROM events GROUP BY ((id-1)/?) ORDER BY MIN(id)',(PAGE_SIZE,)):
            if (low,high)in prior_pages:entries.append(prior_pages[(low,high)]);continue
            current=[{'id':ident,**decode_json(raw)}for ident,raw in db.execute('SELECT id,data FROM events WHERE id BETWEEN ? AND ? ORDER BY id',(low,high))]
            flush()
    catalog={'schema':1,'generated':int(now),'retention_days':7,'retention_limit':MAX_EVENTS,'retained':count,
        'version':version,'collector':status,'pages':list(reversed(entries)),
        'coverage':{'journal':True,'initial_window_minutes':15,'earlier_history_imported':False,
            'pop_source_template_logs':True,'roundcube_file_log':any(p.get('source')=='roundcube'and p.get('status')=='ok'for p in status.get('sources',[])),'admin_audit_database':False},
        'hidden_total':int(value(db,'skipped_total','0'))}
    # Cached entries were stored newest first; do not reverse the reused catalog twice.
    if prior and prior.get('version')==version:catalog['pages']=entries
    raw=encode(catalog);need(len(raw)<=262144 and len(catalog['pages'])<=801,'catalog_limit')
    # Only derived cache pages, never source logs. Grace protects concurrent readers.
    keep={p['hash']+'.json'for p in catalog['pages']};removed=0
    for index,path in enumerate(pages.iterdir()):
        need(index<4096,'page_inventory_limit')
        import re
        need(path.is_file()and not path.is_symlink(),'page_inventory')
        if re.fullmatch(r'\.[a-f0-9]{64}\.json\.tmp-[0-9]+',path.name):
            if path.stat().st_mtime<now-600 and removed<200:path.unlink();removed+=1
            continue
        need(re.fullmatch(r'[a-f0-9]{64}\.json',path.name)is not None,'page_inventory')
        if path.name not in keep and path.stat().st_mtime<now-600 and removed<200:
            path.unlink();removed+=1
    atomic(prior_path,raw,group)
    return catalog

def run():
    need(sys.argv[1:]==['--collect']and os.geteuid()==0,'fixed_root_collect');os.umask(0o077)
    for path in (Path('/'),Path('/var'),Path('/var/lib'),ROOT,ROOT/'private',ROOT/'published',ROOT/'published/pages'):guarded(path,True)
    lock=os.open(ROOT/'private/collector.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    db=None
    try:
        s=os.fstat(lock);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600,'collector_lock_type')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        path=ROOT/'private/events.sqlite'
        if path.exists():guarded(path)
        db=setup_db(path);os.chmod(path,0o600);now=time.time();status=None
        parts=[]
        for kind in ('main','worker'):
            try:
                rows,part=read_journal(value(db,'cursor_'+kind),now,kind=='worker');ingest(db,rows,int(now*1e6),'cursor_'+kind)
                with db:state(db,'last_success_'+kind,int(now))
            except Exception as e:
                f=traceback.extract_tb(e.__traceback__)[-1]
                part={'status':'failed','exit':getattr(e,'exit',None),'reason':sanitize(str(e)),'class':type(e).__name__,
                    'component':Path(f.filename).name,'line':f.lineno,'last_success':int(value(db,'last_success_'+kind,'0')),'backlog':False}
            parts.append({'source':kind,**part})
        try:
            rows,part,position=read_roundcube(db,now);ingest(db,rows,int(now*1e6),'file_cursor')
            with db:state(db,'file_inode',position[0]);state(db,'file_offset',position[1]);state(db,'last_success_roundcube',int(now))
        except Exception as e:
            f=traceback.extract_tb(e.__traceback__)[-1]
            part={'status':'failed','reason':sanitize(str(e)),'class':type(e).__name__,'component':Path(f.filename).name,
                'line':f.lineno,'last_success':int(value(db,'last_success_roundcube','0')),'backlog':False}
        parts.append({'source':'roundcube',**part})
        status={'status':'ok'if all(p['status']=='ok'for p in parts)else'failed','sources':parts,
            'backlog':any(p['backlog']for p in parts),'last_success':min(p['last_success']for p in parts)}
        publish(db,ROOT/'published',now,status,GROUP)
        print(json.dumps({'status':status['status'],'snapshot_published':True,'manual_pop':False,'source_logs_changed':False}))
        return 0 if status['status']=='ok'else 1
    finally:
        if db:db.close()
        os.close(lock)

def main():
    try:return run()
    except BlockingIOError:print('{"status":"busy","source_logs_changed":false}');return 0
    except Exception as e:
        frame=traceback.extract_tb(e.__traceback__)[-1]
        print(json.dumps({'status':'failed','class':type(e).__name__,'reason':sanitize(str(e)),'component':Path(frame.filename).name,'line':frame.lineno}))
        return 2
if __name__=='__main__':raise SystemExit(main())
