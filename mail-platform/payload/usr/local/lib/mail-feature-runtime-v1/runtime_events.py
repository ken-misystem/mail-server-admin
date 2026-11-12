"""Bounded retained normalized failures. Read-only transactions, no mail/log originals."""
import json,sqlite3,stat
from forwarding import need

def failures(path,now_us):
    info=path.lstat();need(stat.S_ISREG(info.st_mode)and info.st_uid==0 and info.st_nlink==1 and not info.st_mode&0o077,'normalized_event_database')
    need(type(now_us)is int and now_us>=0,'normalized_event_clock');db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=.2)
    try:
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN');rows=db.execute("SELECT ts,data FROM events WHERE ts>=? AND ts<=? AND json_extract(data,'$.category')='smtp_out' AND json_extract(data,'$.outcome') IN ('deferred','failed') ORDER BY ts DESC,id DESC LIMIT 20001",(max(0,now_us-86400000000),now_us)).fetchall()
        # Truncation does not become a zero-failure success or clear an existing hold.
        need(len(rows)<=20000,'retained_failure_window_truncated');need(sum(len(raw)for _,raw in rows)<=32*1024*1024,'retained_failure_byte_bound');result=[]
        for stamp,raw in rows:
            try:row=json.loads(raw)
            except (ValueError,TypeError):raise ValueError('retained_failure_row_invalid')from None
            need(type(row)is dict and type(stamp)is int and row.get('ts')==stamp,'retained_failure_row_binding')
            if row.get('category')=='smtp_out'and row.get('outcome')in ('deferred','failed'):result.append({key:row.get(key)for key in ('ts','category','outcome','recipient','queue')})
        return result
    finally:
        try:db.rollback()
        finally:db.close()
