"""Control-plane dispatcher. Fixed adapters, verified peer, durable operation receipts."""
import hashlib,json,re
from queue_admin import Audit,QueueAdmin,browse,need
from owner_control import Stops,principal,statistics

class FeatureBroker:
    def __init__(self,queue_runner,control_db,directory,publisher,ledger_read,clock):
        self.audit=Audit(control_db);self.stops=Stops(control_db);self.queue=QueueAdmin(queue_runner,self.audit,clock)
        self.db=control_db;self.directory=directory;self.publisher=publisher;self.ledger_read=ledger_read;self.clock=clock
        self.db.execute('CREATE TABLE IF NOT EXISTS control_revision(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL)')
        self.db.execute('INSERT OR IGNORE INTO control_revision VALUES(1,1)');self.db.commit()
    def snapshot(self):
        revision=self.db.execute('SELECT revision FROM control_revision WHERE id=1').fetchone()[0]
        rows=self.db.execute('SELECT principal,until_at,revision FROM owner_stops ORDER BY principal').fetchall();need(len(rows)<=10000,'stop_snapshot_bound')
        return {'version':1,'revision':revision,'owners':{row[0]:{'until':row[1],'revision':row[2]} for row in rows}}
    def start(self):
        # Reconcile committed state before accepting any administrator operation.
        self.publisher(self.snapshot())
    def system_actor(self,identity):
        need(type(identity)is str and re.fullmatch('[1-9][0-9]{0,19}',identity),'actor_id')
        row=self.directory.actor(identity);need(row=={'active':True,'system_admin':True},'system_admin_required')
    def owner_stop(self,r):
        need(type(r)is dict and set(r)=={'kind','owner_id','confirm','seconds','revision','reason','actor','request_id','issued_at'},'owner_request')
        self.system_actor(r['actor']);need(type(r['issued_at'])is int and 0<=int(self.clock())-r['issued_at']<=120,'owner_request_expired')
        need(type(r['request_id'])is str and re.fullmatch('[a-f0-9]{32}',r['request_id']),'owner_request_id')
        key=principal(r['kind'],r['owner_id']);owner=self.directory.owner(r['kind'],r['owner_id'])
        need(owner is not None and type(r['confirm'])is str and r['confirm']==owner['label'],'owner_confirmation')
        need(type(r['seconds'])is int and (r['seconds']==0 or 60<=r['seconds']<=86400) and type(r['revision'])is int and r['revision']>=0,'owner_input')
        need(r['reason'] in ('account_compromise','application_error','operator_review'),'owner_reason')
        previous=self.audit.claim(r)
        if previous:return previous['receipt'] if previous['state']=='finished' else {'state':'unknown','automatic_retry':False}
        receipt={'state':'unknown','automatic_retry':False}
        busy_published=False
        try:
            current=self.stops.read(key)
            need((current['revision'] if current else 0)==r['revision'],'stop_stale_revision')
            self.db.execute('UPDATE control_revision SET revision=revision+1 WHERE id=1');self.db.commit()
            rev=self.db.execute('SELECT revision FROM control_revision WHERE id=1').fetchone()[0]
            # Fail-closed sentinel: no old permissive snapshot survives a committed stop.
            self.publisher({'version':1,'revision':rev,'state':'updating'});busy_published=True
            changed=self.stops.save(r['kind'],r['owner_id'],int(r['actor']),int(self.clock()),r['seconds'],r['revision'],r['reason'])
            self.publisher(self.snapshot());busy_published=False
            receipt={'state':'applied','until':changed['until'],'revision':changed['revision'],'automatic_retry':False}
        except Exception as error:
            # If a commit/publish is uncertain, keep the sentinel until a supervised
            # restart reopens and checks the database. Never silently republish old data.
            receipt.update(failure_class=type(error).__name__,policy_unavailable_until_reconciled=busy_published)
        self.audit.finish(r['request_id'],receipt);return receipt
    def handle(self,request,*,peer='frontend'):
        need(peer in ('frontend','collector') and type(request)is dict and type(request.get('operation'))is str,'feature_peer_or_request')
        op=request['operation']
        if op=='queue.browse':
            need(set(request)=={'operation','filters'} and type(request['filters'])is dict,'queue_browse_fields')
            return browse(self.queue.inventory(),**request['filters'],now=int(self.clock()))
        if op=='queue.apply':
            need(peer=='frontend' and set(request)=={'operation','request'},'feature_mutation_peer')
            self.system_actor(request['request'].get('actor'));return self.queue.apply(request['request'])
        if op=='owner.browse':
            need(set(request)=={'operation','filters'},'owner_browse_fields');values=self.directory.browse(request['filters'])
            need(type(values)is dict and type(values.get('rows'))is list and len(values['rows'])<=100,'owner_rows')
            owners=[principal(r['kind'],r['id']) for r in values['rows']]
            with self.ledger_read() as connection:stats=statistics(connection,owners,int(self.clock()))
            mapping={r['principal']:r for r in stats['rows']}
            for row,key in zip(values['rows'],owners):row['usage']=mapping[key];row['stop']=self.stops.read(key) or {'until':0,'revision':0}
            return dict(values,observed_at=int(self.clock()),semantics=stats['semantics'])
        if op=='owner.stop':
            need(peer=='frontend' and set(request)=={'operation','request'},'feature_mutation_peer');return self.owner_stop(request['request'])
        raise ValueError('feature_operation_not_allowed')
