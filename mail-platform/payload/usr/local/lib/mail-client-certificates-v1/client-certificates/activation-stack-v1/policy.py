"""Inert deployment decisions. No implicit activation/key generation/DB writes."""
from pathlib import PureWindowsPath
import re

ROLES={
 'identity_reader':'mailcert_identity_v1','orchestrator':'mailcert_owner_v1',
 'issuer_journal':'mailcert_issuer_v1','gateway_reader':'mailcert_gateway_v1',
 'view_definer':'mailcert_views_v1','lifecycle_provisioner':'mailcert_lifecycle_v1',
 'session_reader':'mailcert_session_v1'}
ROOTS={'release':'/usr/local/lib/mail-client-certificates-v1',
       'private':'/etc/mail-client-certificates-v1',
       'state':'/var/lib/mail-client-certificates-v1',
       'runtime':'/run/mail-client-certificates-v1'}
# NEW proposed custody path chosen after the user delegated the location choice.
# This module creates no outside-repository files and does not claim offline custody.
CA_BACKUP=r'C:\Users\ken\Mail-Client-CA-Offline'
CA_PROFILE={'root_rsa_bits':4096,'root_days':3650,'root_path_length':1,
    'issuer_rsa_bits':4096,'issuer_days':730,'issuer_path_length':0,
    'leaf_rsa_bits':3072,'leaf_days':90,'issuer_crl_days':7,'root_crl_days':365,
    'leaf_eku':['clientAuth'],'issuer_eku':['clientAuth'],
    'production_root_key_on_mail_server':False,'server_issues_only_from_intermediate':True,
    'backup_cipher':'AES-256','backup_new_exclusive_only':True,
    'backup_password_in_argv_env_repository_or_chat':False,
    'physical_offline_custody_verified':False}


def need(ok,reason):
    if ok is not True:raise ValueError(reason)


def selected_plan():
    need(len(ROLES)==7 and len(set(ROLES.values()))==7
         and all(re.fullmatch('[a-z][a-z0-9_]{2,31}',v) for v in ROLES.values()),'seven_distinct_roles')
    need(len(set(ROOTS.values()))==4 and all(v.startswith('/') and '..' not in v.split('/')
         and v!='/' for v in ROOTS.values()),'isolated_roots')
    need(PureWindowsPath(CA_BACKUP).is_absolute() and 'mail-server-admin' not in CA_BACKUP.lower(),
         'ca_backup_outside_repository')
    return {'kind':'new_proposed_placement_not_installed','activation_ready':False,
        'roles':dict(ROLES),'roots':dict(ROOTS),'ca':dict(CA_PROFILE),
        'ca_backup_proposed_path':CA_BACKUP,'ca_backup_created':False,
        'must_preserve':['roundcube_https_and_private_mail_routes','mta_25',
            'normal_pop_and_junk_timers','mail_and_uidl','existing_auth_policies'],
        'pending':['exact_live_session_table_binding','full_runtime_and_webauthn_wiring',
            'dedicated_native_backend_proof','new_ca_custody','rollback_and_exact_apply_review']}


def session_grant():
    return "GRANT SELECT (sess_id,vars,changed) ON roundcube.session TO '"+ROLES['session_reader']+"'@'localhost';"
