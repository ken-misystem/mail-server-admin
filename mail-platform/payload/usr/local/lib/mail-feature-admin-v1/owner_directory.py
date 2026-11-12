"""Only fixed read-only inventory/role queries. Never reads password columns."""
from contextlib import contextmanager
import re
from forwarding import domain,need

class Directory:
    def __init__(self,connect):self.connect=connect
    @contextmanager
    def cursor(self):
        db=self.connect();cursor=None
        try:
            cursor=db.cursor();cursor.execute('SET SESSION max_statement_time=3');cursor.execute('START TRANSACTION READ ONLY');yield cursor
        finally:
            try:db.rollback()
            finally:
                try:
                    if cursor is not None:cursor.close()
                finally:db.close()
    def actor(self,identity):
        need(type(identity)is str and re.fullmatch('[1-9][0-9]{0,19}',identity),'admin_identity')
        with self.cursor() as q:q.execute('SELECT active,is_system_admin FROM mail_management.mail_admin_users WHERE id=%s LIMIT 2',(identity,));rows=q.fetchall()
        need(len(rows)==1 and all(v in (0,1) for v in rows[0]),'admin_missing')
        return {'active':rows[0][0]==1,'system_admin':rows[0][1]==1}
    def owner(self,kind,identity):
        need(kind in ('mailbox','legacy') and type(identity)is int and 0<identity<2**64,'owner_identity')
        query='SELECT id,email,active FROM mailserver.virtual_users WHERE id=%s LIMIT 2' if kind=='mailbox' else 'SELECT id,login_id,enabled FROM mail_management.mail_legacy_smtp_credentials WHERE id=%s LIMIT 2'
        with self.cursor() as q:q.execute(query,(identity,));rows=q.fetchall()
        need(len(rows)<=1,'owner_ambiguous')
        return {'id':rows[0][0],'label':rows[0][1],'active':rows[0][2]==1,'kind':kind} if rows else None
    def browse(self,filters):
        need(type(filters)is dict and set(filters)=={'kind','q','domain','page','size'},'owner_filters')
        kind=filters['kind'];text=filters['q'];host=filters['domain'];page=filters['page'];size=filters['size']
        need(kind in ('mailbox','legacy') and type(text)is str and len(text)<=254 and all(ord(c)>=32 for c in text),'owner_search')
        need(type(host)is str and (host=='' or domain(host)==host),'owner_domain')
        need(type(page)is int and 1<=page<=40000 and type(size)is int and size in (25,50,100),'owner_page')
        if kind=='mailbox':
            source='mailserver.virtual_users c JOIN mailserver.virtual_domains d ON d.id=c.domain_id';label='c.email';active='c.active';domain_clause='d.name=%s'
        else:source='mail_management.mail_legacy_smtp_credentials c';label='c.login_id';active='c.enabled';domain_clause='SUBSTRING_INDEX(c.sender_address,\'@\',-1)=%s'
        where=[];values=[]
        if text:where.append(label+" LIKE %s ESCAPE '!'");values.append(text.replace('!','!!').replace('%','!%').replace('_','!_')+'%')
        if host:where.append(domain_clause);values.append(host)
        suffix=' WHERE '+' AND '.join(where) if where else ''
        with self.cursor() as q:
            q.execute('SELECT COUNT(*) FROM '+source+suffix,tuple(values));total=q.fetchone()[0];need(type(total)is int and total<=1000000,'owner_total_bound')
            q.execute('SELECT c.id,'+label+','+active+' FROM '+source+suffix+' ORDER BY c.id LIMIT %s OFFSET %s',tuple(values+[size,(page-1)*size]));rows=q.fetchall()
        return {'rows':[{'id':r[0],'kind':kind,'label':r[1],'active':r[2]==1} for r in rows],'total':total,'page':page,'size':size}
