"""Fixed readonly runtime inventory; never password columns or arbitrary SQL."""
from contextlib import contextmanager
from forwarding import need,address,domain

class RuntimeDirectory:
    def __init__(self,connect):self.connect=connect
    @contextmanager
    def cursor(self):
        db=self.connect();cursor=None
        try:
            cursor=db.cursor();cursor.execute('SET SESSION max_statement_time=3');cursor.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');cursor.execute('START TRANSACTION READ ONLY');yield cursor
        finally:
            try:db.rollback()
            finally:
                try:
                    if cursor is not None:cursor.close()
                finally:db.close()
    def inventory(self):
        with self.cursor()as q:
            q.execute('SELECT id,name,active FROM mailserver.virtual_domains ORDER BY id LIMIT 10001');domain_rows=q.fetchall();need(len(domain_rows)<=10000,'runtime_domain_bound')
            id_to_name={};domain_ids={};domain_active={}
            for identity,name,active in domain_rows:
                need(type(identity)is int and identity>0 and active in (0,1),'runtime_domain_shape');domain(name);need(identity not in id_to_name and name not in domain_ids,'runtime_domain_ambiguous')
                id_to_name[identity]=name;domain_ids[name]=identity;domain_active[identity]=active==1
            q.execute('SELECT alias_domain,target_domain_id FROM mailserver.virtual_domain_aliases ORDER BY id LIMIT 1001');alias_rows=q.fetchall();need(len(alias_rows)<=1000,'runtime_domain_alias_bound');domain_aliases={}
            for name,target in alias_rows:domain(name);need(name not in domain_aliases and name not in domain_ids and target in id_to_name,'runtime_domain_alias_shape');domain_aliases[name]=id_to_name[target]
            q.execute('SELECT id,domain_id,email,active FROM mailserver.virtual_users ORDER BY id LIMIT 10001');rows=q.fetchall();need(len(rows)<=10000,'runtime_user_bound');users=[];by_id={};active_users={}
            for identity,host,email,active in rows:
                address(email);need(type(identity)is int and identity>0 and identity not in by_id and host in id_to_name and email.split('@')[1]==id_to_name[host]and active in (0,1),'runtime_mailbox_binding')
                users.append(email);by_id[identity]=email;active_users[identity]=active==1 and domain_active[host]
            q.execute('SELECT source,destination FROM mailserver.virtual_aliases ORDER BY id LIMIT 10001');rows=q.fetchall();need(len(rows)<=10000,'runtime_alias_bound');aliases=[]
            for source,target in rows:
                address(source);need(type(target)is str and len(target)<=3200,'runtime_alias_target');targets=target.split(',');need(1<=len(targets)<=10,'runtime_alias_target_bound');aliases.append((source,[address(value)for value in targets]))
            q.execute('SELECT user_id,destinations,enabled,revision FROM mail_management.mail_feature_forwards ORDER BY user_id LIMIT 10001');rows=q.fetchall();need(len(rows)<=10000,'runtime_forward_bound');routes=[]
            import json
            configured=set()
            for identity,raw,enabled,revision in rows:
                need(identity in by_id and enabled in (0,1)and type(revision)is int and revision>0 and type(raw)is str and len(raw)<=8192,'runtime_forward_shape');targets=json.loads(raw)
                need(identity not in configured,'runtime_forward_duplicate');configured.add(identity)
                routes.append({'source':by_id[identity],'destinations':targets,'enabled':enabled==1 and active_users[identity],'revision':revision})
            # A per-user before-storage must have an inert script even for users
            # without a forwarding row. Never turn a missing generated file into
            # a delivery dependency for those users.
            routes.extend({'source':email,'destinations':[],'enabled':False,'revision':0}for identity,email in by_id.items()if identity not in configured)
            q.execute('SELECT kind,revision,payload FROM mail_management.mail_feature_settings ORDER BY kind LIMIT 3');rows=q.fetchall();need(len(rows)<=2,'runtime_settings_bound');settings={}
            for kind,revision,raw in rows:
                need(kind in ('access','spam')and kind not in settings and type(revision)is int and revision>0 and type(raw)is str and len(raw)<=2097152,'runtime_setting_shape');settings[kind]={'revision':revision,'payload':json.loads(raw)}
            return {'domains':set(domain_ids),'domain_ids':domain_ids,'domain_aliases':domain_aliases,'users':users,'aliases':aliases,'routes':routes,'settings':settings}
