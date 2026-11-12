"""Bounded Postfix queue inventory and audited single-ID operations; no shell/body."""
import hashlib,json,re,time

ACTIONS={'hold':('/usr/sbin/postsuper','-h'),'release':('/usr/sbin/postsuper','-H'),'retry':('/usr/sbin/postqueue','-i')}
REASONS=('delivery_investigation','destination_fixed','operator_review')

def need(ok,reason):
    if not ok:raise ValueError(reason)

def identity(value):
    need(type(value)is str and re.fullmatch(r'[A-Za-z0-9]{5,52}',value)is not None and value!='ALL','queue_id')
    return value

def decode(raw):
    need(type(raw)is bytes and len(raw)<=8*1024*1024,'queue_output_bound')
    rows=[];seen=set()
    for line in raw.splitlines():
        need(len(rows)<20000 and len(line)<=131072,'queue_row_bound')
        item=json.loads(line)
        need(type(item)is dict,'queue_object')
        qid=identity(item.get('queue_id'));need(qid not in seen,'duplicate_queue_id');seen.add(qid)
        need(item.get('queue_name') in ('incoming','active','deferred','hold','maildrop'),'queue_state')
        need(type(item.get('arrival_time'))is int and item['arrival_time']>=0,'arrival_time')
        need(type(item.get('message_size'))is int and item['message_size']>=0,'message_size')
        need(type(item.get('sender'))is str and len(item['sender'])<=320 and not any(ord(c)<32 for c in item['sender']),'sender')
        recipients=item.get('recipients');need(type(recipients)is list and 1<=len(recipients)<=1000,'recipients')
        destinations=[]
        for target in recipients:
            address=target.get('address');reason=target.get('delay_reason','')
            need(type(address)is str and len(address)<=320 and not any(ord(c)<32 for c in address),'recipient')
            need(type(reason)is str and len(reason)<=8192,'delay_reason')
            # Envelope metadata only. Plain text is escaped by the frontend.
            destinations.append({'address':address,'reason':reason})
        row={'id':qid,'state':item['queue_name'],'arrival':item['arrival_time'],'bytes':item['message_size'],
             'sender':item['sender'],'recipients':destinations}
        row['token']=hashlib.sha256(json.dumps(row,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        rows.append(row)
    return rows

def browse(rows,*,query='',state='',page=1,size=25,now=None):
    need(type(query)is str and len(query)<=254 and not any(ord(c)<32 for c in query),'queue_search')
    need(state in ('','incoming','active','deferred','hold','maildrop'),'queue_filter')
    need(type(page)is int and 1<=page<=800 and type(size)is int and size in (25,50,100),'queue_page')
    now=int(time.time()) if now is None else now;term=query.casefold()
    selected=[r for r in rows if (not state or r['state']==state) and (not term or term in r['id'].casefold() or term in r['sender'].casefold() or any(term in x['address'].casefold() for x in r['recipients']))]
    selected.sort(key=lambda r:(r['arrival'],r['id']))
    return {'rows':[dict(r,age=max(0,now-r['arrival'])) for r in selected[(page-1)*size:page*size]],'total':len(selected),'page':page,'size':size,'observed_at':now}

class Audit:
    """Separate FULL SQLite journal; claim is durable before the external command."""
    def __init__(self,connection):
        self.db=connection
        need(self.db.execute('PRAGMA synchronous=FULL').fetchall()==[],'audit_sync')
        self.db.execute('CREATE TABLE IF NOT EXISTS queue_actions(request_id TEXT PRIMARY KEY,request TEXT NOT NULL,state TEXT NOT NULL,receipt TEXT)')
        self.db.commit()
    def claim(self,request):
        raw=json.dumps(request,sort_keys=True,separators=(',',':'));self.db.execute('BEGIN IMMEDIATE')
        try:
            row=self.db.execute('SELECT request,state,receipt FROM queue_actions WHERE request_id=?',(request['request_id'],)).fetchone()
            if row:
                need(row[0]==raw,'request_id_reused');self.db.rollback()
                return {'state':row[1],'receipt':json.loads(row[2]) if row[2] else None}
            self.db.execute('INSERT INTO queue_actions VALUES(?,?,?,NULL)',(request['request_id'],raw,'pending'));self.db.commit();return None
        except Exception:self.db.rollback();raise
    def finish(self,request_id,receipt):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            changed=self.db.execute('UPDATE queue_actions SET state=?,receipt=? WHERE request_id=? AND state=?',
                ('finished',json.dumps(receipt,sort_keys=True),request_id,'pending')).rowcount
            need(changed==1,'audit_transition');self.db.commit()
        except Exception:self.db.rollback();raise

class QueueAdmin:
    def __init__(self,runner,audit,clock=time.time):self.runner=runner;self.audit=audit;self.clock=clock
    def inventory(self):
        code,out,err=self.runner(('/usr/sbin/postqueue','-j'))
        need(code==0 and not err,'queue_inventory_unavailable');return decode(out)
    def apply(self,request):
        need(type(request)is dict and set(request)=={'action','id','confirm','token','reason','actor','request_id','issued_at'},'queue_request_fields')
        identity(request['id']);need(request['confirm']==request['id'],'queue_confirmation')
        need(request['action'] in ACTIONS and request['reason'] in REASONS,'queue_operation')
        need(type(request['actor'])is str and re.fullmatch('[1-9][0-9]{0,19}',request['actor'])is not None,'queue_actor')
        need(type(request['request_id'])is str and re.fullmatch('[a-f0-9]{32}',request['request_id'])is not None,'request_id')
        need(type(request['token'])is str and re.fullmatch('[a-f0-9]{64}',request['token'])is not None,'queue_token')
        need(type(request['issued_at'])is int and 0<=self.clock()-request['issued_at']<=120,'queue_request_expired')
        previous=self.audit.claim(request)
        if previous is not None:
            return previous['receipt'] if previous['state']=='finished' else {'state':'unknown','automatic_retry':False}
        receipt={'state':'unknown','action':request['action'],'id':request['id'],'automatic_retry':False}
        try:
            matches=[x for x in self.inventory() if x['id']==request['id']]
            if not matches:receipt['state']='already_absent'
            elif matches[0]['token']!=request['token']:receipt['state']='changed'
            else:
                state=matches[0]['state'];action=request['action']
                need((action=='release' and state=='hold') or (action=='hold' and state in ('deferred','active','incoming')) or (action=='retry' and state=='deferred'),'queue_action_state')
                code,out,err=self.runner((*ACTIONS[action],request['id']))
                # Native messages may contain envelope addresses; only the exit is returned.
                receipt['native_exit']=code
                if code==0:
                    after=[x for x in self.inventory() if x['id']==request['id']]
                    receipt['state']=('held' if after and after[0]['state']=='hold' else 'unknown') if action=='hold' else ('released' if not after or after[0]['state']!='hold' else 'unknown') if action=='release' else 'retry_requested'
                else:receipt['state']='native_failed'
        except Exception as error:
            receipt['failure_class']=type(error).__name__
        self.audit.finish(request['request_id'],receipt)
        return receipt
