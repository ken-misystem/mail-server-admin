"""Render least-privilege production DDL from the verified six-role plan.

    No SQL execution or credentials. Session access and a separate Passkey
    verifier role are added; FPM/orchestrator never gain credential-table write.
"""
from copy import deepcopy
from hashlib import sha256
import json
import re

ROLES={'view_definer':'mailcert_views_v1','identity_reader':'mailcert_identity_v1',
    'orchestrator':'mailcert_owner_v1','issuer_journal':'mailcert_issuer_v1','gateway_reader':'mailcert_gateway_v1',
    'lifecycle_provisioner':'mailcert_lifecycle_v1','session_reader':'mailcert_session_v1','webauthn_verifier':'mailcert_verify_v1'}


def need(value,code):
    if value is not True:raise ValueError(code)


def render(saved):
    need(type(saved)is dict and set(saved['roles'])==set(ROLES)-{'session_reader','webauthn_verifier'},'verified_base_roles')
    need(len(set(ROLES.values()))==8 and all(re.fullmatch('[a-z][a-z0-9_]{2,31}',v)for v in ROLES.values()),'principal_inventory')
    base=deepcopy(saved);schema=base['schema'];grants=base['grants']
    for role,old in saved['roles'].items():
        schema=[s.replace("'"+old+"'@'localhost'","'"+ROLES[role]+"'@'localhost'")for s in schema]
        grants=[s.replace("'"+old+"'@'localhost'","'"+ROLES[role]+"'@'localhost'")for s in grants]
    for i,sql in enumerate(schema):
        schema[i]=re.sub(r'^CREATE TABLE (mail_client_[a-z_]+)\b',r'CREATE TABLE mail_management.\1',sql)
    steps=[{'sql':(schema if row['kind']=='schema'else grants)[row['index']],'phase':row['phase']}for row in base['execution_order']]
    current="""CREATE ALGORITHM=MERGE DEFINER='mailcert_views_v1'@'localhost' SQL SECURITY DEFINER
VIEW mail_management.mail_client_bootstrap_current_owners AS
SELECT u.id AS owner_id,u.auth_epoch,0 AS identity_version,LOWER(u.email) AS canonical_mailbox,
 (u.active=1 AND d.active=1) AS active
FROM mailserver.virtual_users u JOIN mailserver.virtual_domains d ON d.id=u.domain_id;"""
    login=schema[2].replace('mail_client_login_owners','mail_client_bootstrap_login_owners').replace('mail_client_current_owners','mail_client_bootstrap_current_owners')
    need(login!=schema[2]and 'mail_client_owner_locks'not in login,'bootstrap_login_source')
    steps.extend([
        {'sql':current,'phase':'bootstrap_current_view'},
        {'sql':"GRANT SELECT (owner_id,auth_epoch,identity_version,canonical_mailbox,active) ON mail_management.mail_client_bootstrap_current_owners TO 'mailcert_views_v1'@'localhost';",'phase':'bootstrap_definer_current_grant'},
        {'sql':login,'phase':'bootstrap_login_view'}])
    def grant(role,privilege,table,columns):
        clause=' ('+','.join(columns)+')'if columns else''
        steps.append({'sql':f"GRANT {privilege}{clause} ON {table} TO '{ROLES[role]}'@'localhost';",'phase':'additional_minimal_grants'})
    for role in ('identity_reader','lifecycle_provisioner'):
        grant(role,'SELECT','mail_management.mail_client_bootstrap_login_owners',None)
        grant(role,'SELECT','mail_management.mail_client_bootstrap_current_owners',('owner_id','auth_epoch','canonical_mailbox','active'))
    grant('lifecycle_provisioner','SELECT','roundcube.users',('user_id','username','mail_host'))
    grant('lifecycle_provisioner','SELECT','mail_management.mail_client_current_owners',('owner_id','identity_version','active'))
    grant('session_reader','SELECT','roundcube.session',('sess_id','vars','changed'))
    grant('webauthn_verifier','SELECT','roundcube.auth_webauthn_users',('user_id','user_handle'))
    grant('webauthn_verifier','SELECT','roundcube.auth_webauthn_credentials',('id','user_id','credential_id','user_handle','credential_record_json','transports_json','enabled','sign_count'))
    grant('webauthn_verifier','UPDATE','roundcube.auth_webauthn_credentials',('credential_record_json','sign_count','last_used_at'))
    # ON DELETE RESTRICT prevents deletion; it is not a DELETE statement.
    need(all(not re.search(r'^\s*(?:DROP|TRUNCATE|DELETE|REVOKE)\b|\bALL PRIVILEGES\b|\bGRANT OPTION\b|\bON DELETE (?:CASCADE|SET NULL)\b',row['sql'],re.I)
        and not(row['sql'].lstrip().upper().startswith('GRANT ')and re.search(r'\bDELETE\b',row['sql'],re.I))for row in steps),'no_destructive_or_broad_sql')
    return {'roles':dict(ROLES),'steps':steps,'new_accounts':[
        {'role':role,'principal':name,'password_in_private_parameter':True,'locked':role=='view_definer'}for role,name in ROLES.items()],
        'production_schema':True,'executed':False,'seeds_existing_owners':False,'source_plan_sha256':sha256(json.dumps(saved,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        'bootstrap_identity_version_zero_never_an_issuance_identity':True,
        'existing_passkey_counter_updates_only_after_real_user_uv':True,
        'credential_update_role_is_not_fpm_or_orchestrator':True}
