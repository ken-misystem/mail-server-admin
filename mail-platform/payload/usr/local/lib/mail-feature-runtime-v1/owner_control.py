"""Per-owner status and expiring send stops; never resets the existing send ledger."""
import hashlib,re,sqlite3
STOPPED=b'action=451 4.7.1 Sending temporarily suspended by administrator\n\n'
UNAVAILABLE=b'action=451 4.3.0 Send control unavailable\n\n'

def need(ok,reason):
    if not ok:raise ValueError(reason)

def principal(kind,owner_id):
    need(kind in ('mailbox','legacy') and type(owner_id)is int and 1<=owner_id<2**64,'owner_identity')
    return hashlib.sha256((kind+':'+str(owner_id)).encode()).hexdigest()

def gate(record,now):
    """None means no stop. Malformed/failed reads are unavailable, never allowed."""
    need(type(now)is int and now>=0,'owner_clock')
    if record is None:return False
    need(type(record)is dict and set(record)=={'until','revision'} and type(record['until'])is int and record['until']>=0
         and type(record['revision'])is int and record['revision']>0,'stop_record')
    return record['until']>now

def guarded_evaluate(service,raw,nonce,load_stop,resolve_principal,now,*,peer_verified=False):
    """The installed policy supplies the already reviewed frame/identity resolver."""
    try:
        need(peer_verified is True,'owner_peer')
        owner=resolve_principal(raw)
        need(type(owner)is str and re.fullmatch('[a-f0-9]{64}',owner)is not None,'owner_hash')
        if gate(load_stop(owner),now):return STOPPED
    except Exception:return UNAVAILABLE
    return service.evaluate(raw,nonce,peer_verified=True)

def statistics(connection,owners,now):
    need(type(owners)is list and len(owners)<=100 and type(now)is int and now>=3600,'owner_stats_bound')
    need(len(set(owners))==len(owners) and all(type(k)is str and re.fullmatch('[a-f0-9]{64}',k) for k in owners),'owner_stats_identity')
    connection.execute('PRAGMA query_only=ON')
    rows=[]
    connection.execute('BEGIN')
    try:
        for owner in owners:
            values=connection.execute('SELECT COALESCE(SUM(CASE WHEN admitted_at>? THEN messages ELSE 0 END),0),COALESCE(SUM(CASE WHEN admitted_at>? THEN recipients ELSE 0 END),0),COALESCE(SUM(messages),0),COALESCE(SUM(recipients),0) FROM admission_totals WHERE principal=? AND admitted_at>? AND admitted_at<=?',
                (now-60,now-60,owner,now-3600,now)).fetchone()
            need(values is not None and len(values)==4 and all(type(x)is int and x>=0 for x in values),'owner_stats_numbers')
            rows.append({'principal':owner,'minute_messages':values[0],'minute_recipients':values[1],'hour_messages':values[2],'hour_recipients':values[3]})
    finally:connection.rollback()
    return {'observed_at':now,'semantics':'DATA_admission_reservations_not_delivery_counts','rows':rows}

class Stops:
    """Local SQLite reference store, used by the broker's separate control journal."""
    def __init__(self,db):
        self.db=db;db.execute('PRAGMA synchronous=FULL')
        db.executescript('CREATE TABLE IF NOT EXISTS owner_stops(principal TEXT PRIMARY KEY,until_at INTEGER NOT NULL,revision INTEGER NOT NULL);'
                         'CREATE TABLE IF NOT EXISTS owner_stop_history(id INTEGER PRIMARY KEY,principal TEXT NOT NULL,actor INTEGER NOT NULL,before_until INTEGER NOT NULL,after_until INTEGER NOT NULL,revision INTEGER NOT NULL,reason TEXT NOT NULL);')
    def read(self,key):
        row=self.db.execute('SELECT until_at,revision FROM owner_stops WHERE principal=?',(key,)).fetchone()
        return {'until':row[0],'revision':row[1]} if row else None
    def save(self,kind,owner_id,actor,now,seconds,revision,reason):
        key=principal(kind,owner_id)
        need(type(actor)is int and actor>0 and type(now)is int and now>=0,'stop_actor_time')
        need(type(seconds)is int and (seconds==0 or 60<=seconds<=86400),'stop_duration')
        need(type(revision)is int and revision>=0 and reason in ('account_compromise','application_error','operator_review'),'stop_input')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            old=self.read(key);before=old['until'] if old else 0
            need((old['revision'] if old else 0)==revision,'stop_stale_revision')
            value=now+seconds if seconds else 0;next_revision=revision+1
            self.db.execute('INSERT INTO owner_stops VALUES(?,?,?) ON CONFLICT(principal) DO UPDATE SET until_at=excluded.until_at,revision=excluded.revision',(key,value,next_revision))
            self.db.execute('INSERT INTO owner_stop_history(principal,actor,before_until,after_until,revision,reason) VALUES(?,?,?,?,?,?)',(key,actor,before,value,next_revision,reason))
            self.db.commit();return {'principal':key,'until':value,'revision':next_revision}
        except Exception:self.db.rollback();raise
