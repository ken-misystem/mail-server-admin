"""User-selected encrypted ken10 storage. Never assert physical offline custody."""
from hashlib import sha256
import json
import re
import time
import uuid

def need(value,code):
    if value is not True:raise ValueError(code)

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()

def receipt_binding(restoration):
    need(type(restoration)is dict and set(restoration)=={'version','issuer_id','root_certificate_sha256','issuer_certificate_sha256','encrypted_backup_sha256','restore_verified'}
        and type(restoration['version'])is int and restoration['version']==1 and restoration['restore_verified']is True,'pc_custody_restore_required')
    need(str(uuid.UUID(restoration['issuer_id']))==restoration['issuer_id']and all(type(restoration[k])is str and re.fullmatch('[a-f0-9]{64}',restoration[k])is not None
        for k in ('root_certificate_sha256','issuer_certificate_sha256','encrypted_backup_sha256')),'pc_custody_restore_binding')
    return sha256(canonical(restoration)).hexdigest()

def acknowledge(restoration,statement,initial=True):
    binding=receipt_binding(restoration)
    required={'version','kind','host','restore_receipt_sha256','capsule_sha256','dpapi_recovery_sha256','capsule_readback_verified','recovery_readback_verified',
        'separate_directories','current_user_only_acl_verified','root_plaintext_never_persisted','recovery_key_server_persisted','physical_offline_custody_confirmed','operator_policy_accepted_at'}
    need(type(statement)is dict and set(statement)==required,'pc_custody_statement_fields')
    need(type(statement['version'])is int and statement['version']==1 and statement['kind']=='encrypted_pc'and statement['host']=='ken10'
        and statement['restore_receipt_sha256']==binding and statement['capsule_sha256']==restoration['encrypted_backup_sha256']
        and re.fullmatch('[a-f0-9]{64}',statement['dpapi_recovery_sha256'])is not None,'pc_custody_file_binding')
    need(all(statement[k]is True for k in ('capsule_readback_verified','recovery_readback_verified','separate_directories','current_user_only_acl_verified','root_plaintext_never_persisted'))
        and statement['recovery_key_server_persisted']is False and statement['physical_offline_custody_confirmed']is False,'pc_custody_protection_required')
    now=time.time();need(type(statement['operator_policy_accepted_at'])is int and 0<statement['operator_policy_accepted_at']<=now
        and(not initial or now-statement['operator_policy_accepted_at']<=86400),'pc_custody_acceptance_time')
    return {'issuer_id':restoration['issuer_id'],'issuer_certificate_sha256':restoration['issuer_certificate_sha256'],
        'root_certificate_sha256':restoration['root_certificate_sha256'],'encrypted_backup_sha256':restoration['encrypted_backup_sha256'],
        'restore_evidence_sha256':binding,'custody_policy_accepted':True}

def validate(custody,restoration,statement):
    expected=acknowledge(restoration,statement,False);need(custody==expected,'pc_custody_saved_evidence_mismatch');return expected
