"""Root-controlled CA adoption with overlapping trust and CAS recovery."""
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid

from certificate_state import STATE, trusted, private_directory, new_file, require, certificate_lock, failure,evidence_path,require_settled
from host_transaction import Commands, Files, Transaction, durable_json
import time

PUBLIC = ('root','issuer','root_crl','custody','restoration','custody_statement')
PRIVATE = ('issuer_key','issuer_password')
ACTORS = ('owner','lifecycle','verifier','issuer','gate')
CONFIG_ROOT = Path('/etc/mail-client-certificates-v1')
DROPIN = '/etc/systemd/system/mail-client-cert-issuer.service.d/70-ca-generations.conf'
RUNTIME = Path('/usr/local/lib/mail-client-certificates-v1/client-certificates')
PENDING=STATE/'ca-pending.json'


def prepare(directory):
    require(os.geteuid()==0,'CA_root_required')
    with certificate_lock():
        require_settled()
        return import_generation(directory)


def import_generation(directory):
    """Import an offline ceremony result. The root private key is never an input."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from datetime import datetime, timezone
    require(os.geteuid() == 0, 'CA_root_required')
    directory = Path(directory)
    require({p.name for p in directory.iterdir()} == set(PUBLIC+PRIVATE), 'CA_import_exact_inventory')
    inputs = {name:trusted(directory/name, private=name in PRIVATE)[0] for name in PUBLIC+PRIVATE}
    custody = json.loads(inputs['custody'])
    sys.path.insert(0,str(RUNTIME/'runtime-completion-v1'))
    sys.path.insert(0,str(RUNTIME/'production-runtime-v1'))
    from pc_custody import validate
    validate(custody,json.loads(inputs['restoration']),json.loads(inputs['custody_statement']))
    from ca_startup import PublicChain
    import time
    PublicChain(inputs['root'],time.time)(inputs['issuer'],custody['root_certificate_sha256'])
    identity = custody['issuer_id']
    require(str(uuid.UUID(identity)) == identity, 'CA_import_identity')
    root, issuer = (x509.load_pem_x509_certificate(inputs[name]) for name in ('root','issuer'))
    root.verify_directly_issued_by(root)
    issuer.verify_directly_issued_by(root)
    now = datetime.now(timezone.utc)
    for name, cert, pin in (('root',root,'root_certificate_sha256'),('issuer',issuer,'issuer_certificate_sha256')):
        require(hashlib.sha256(inputs[name]).hexdigest() == custody[pin], 'CA_custody_certificate_pin')
        require(cert.not_valid_before_utc <= now < cert.not_valid_after_utc, 'CA_import_validity')
        require(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca, 'CA_import_constraints')
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        require(usage.key_cert_sign and usage.crl_sign, 'CA_import_key_usage')
    crl = x509.load_pem_x509_crl(inputs['root_crl'])
    require(crl.issuer == root.subject and crl.is_signature_valid(root.public_key())
            and crl.last_update_utc <= now < crl.next_update_utc, 'CA_import_root_CRL')
    require(crl.get_revoked_certificate_by_serial_number(issuer.serial_number) is None, 'CA_import_revoked_issuer')
    require(inputs['issuer_key'].startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----'), 'CA_import_encrypted_issuer_required')
    password = inputs['issuer_password'].removesuffix(b'\n')
    require(password and b'\n' not in password and b'\x00' not in password, 'CA_import_password_shape')
    key = serialization.load_pem_private_key(inputs['issuer_key'],password=password)
    require(key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
            == issuer.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo), 'CA_import_key_pair')
    known=[]
    actor_path=CONFIG_ROOT/'issuer.json'
    if actor_path.exists():
        actor=json.loads(trusted(actor_path)[0])
        known.append({'ca':actor['ca']})
        known.extend(actor.get('previous_ca',[]))
    for path in (STATE/'ca').glob('*/generation.json'):
        known.append(json.loads(trusted(path,private=True)[0]))
    public_key=issuer.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    for item in known:
        existing=x509.load_pem_x509_certificate(trusted(item['ca']['issuer']['path'])[0])
        existing_key=existing.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        require(existing.subject!=issuer.subject or existing_key!=public_key,'CA_issuer_CRL_identity_reuse')
    private_directory(STATE)
    target = private_directory(STATE/'ca'/identity)
    require(not list(target.iterdir()), 'CA_generation_already_imported')
    for name,raw in inputs.items():
        new_file(target/name,raw,0o600 if name in PRIVATE else 0o644)
    value = {'issuer_id':identity,'directory':str(target),
             'ca':{name:{'path':str(target/name),'sha256':hashlib.sha256(inputs[name]).hexdigest()} for name in PUBLIC}}
    # Public CA paths must remain traversable by the isolated issuer and gate.
    # Place a separate public-only copy outside the root-private state tree.
    public = Path('/var/lib/mail-platform-pki/generations')/identity
    for path in (public.parent,public):
        if not path.exists():
            path.mkdir(mode=0o755)
            os.chmod(path,0o755)
        require(not path.is_symlink() and path.stat().st_uid==0 and path.stat().st_mode & 0o777 == 0o755,'CA_public_directory_permissions')
    for name in PUBLIC:
        new_file(public/name,inputs[name],0o644)
        value['ca'][name]['path'] = str(public/name)
    durable_json(target/'generation.json',value)
    return value


def public_config(actor):
    path = CONFIG_ROOT/(actor+'.json')
    raw, attributes = trusted(path)
    return path,json.loads(raw),attributes


def adopted(config):
    ca = config['ca']
    current = STATE/'ca-current.json'
    if current.exists():
        value = json.loads(trusted(current,private=True)[0])['active']
        require(value['ca'] == ca, 'CA_active_state_binding')
        return value
    custody = json.loads(trusted(ca['custody']['path'])[0])
    identity = custody['issuer_id']
    uuid.UUID(identity)
    return {'issuer_id':identity,'ca':ca,
            'private':{kind:'/var/lib/mail-client-certificates-v1/credentials/issuer/issuer_'+kind
                       for kind in ('certificate','key','password')}}


def count_live(commands, identity):
    identity = uuid.UUID(identity)
    sql = ("SET SESSION time_zone='+00:00'; SET SESSION max_statement_time=3; START TRANSACTION READ ONLY; "
           "SELECT COUNT(*) FROM mail_management.mail_client_issuer_journal j JOIN mail_management.mail_client_devices d ON d.id=j.device_id "
           "WHERE j.issuer_id=UNHEX('"+identity.hex+"') AND GREATEST(COALESCE(j.expires_at,DATE_ADD(d.created_at,INTERVAL 90 DAY)),COALESCE(d.expires_at,DATE_ADD(d.created_at,INTERVAL 90 DAY)))>UTC_TIMESTAMP(); ROLLBACK;")
    raw = commands.run('CA_live_certificates', ['/usr/bin/mariadb','--batch','--skip-column-names','-e',sql])
    require(raw.strip().isdigit(), 'CA_live_certificate_count')
    return int(raw.strip())


def restart(commands, *, owner=True):
    commands.run('CA_daemon_reload',['/usr/bin/systemctl','daemon-reload'])
    units = ['mail-client-cert-issuer.service','mail-client-cert-gate.socket','mail-client-cert-gate.service']
    if owner:
        units.append('mail-client-cert-owner.service')
    for unit in units:
        commands.run('CA_start_'+unit.replace('.','_').replace('-','_'),['/usr/bin/systemctl','start',unit])
        commands.run('CA_active_'+unit.replace('.','_').replace('-','_'),['/usr/bin/systemctl','is-active',unit])


def observe_gate(commands):
    from host_transaction import regular
    health=json.loads(trusted(CONFIG_ROOT/'health.json')[0])
    started=time.time()
    deadline=time.monotonic()+25
    observations=[]
    while True:
        try:
            raw,attributes=regular('/run/mail-client-certificates-v1/gate/health.json',8192)
            value=json.loads(raw)
            valid=(attributes['uid']==health['gate_uid'] and not attributes['mode'] & 0o022
                   and value['observed_at']>=int(started)-1 and value['threads_healthy'] is True
                   and value['crl_expires']>time.time()+3600)
        except (OSError,ValueError) as error:
            value={'class':type(error).__name__}
            valid=False
        observations.append(value)
        durable_json(commands.directory/'CA-gate-observations.json',observations)
        if valid:
            return
        require(time.monotonic()<deadline,'CA_gate_health_not_ready')
        time.sleep(.2)


def verify_runtime(commands):
    release=RUNTIME.parent
    raw,_=trusted(release/'runtime-manifest.json')
    manifest=json.loads(raw)
    helper='client-certificates/runtime-completion-v1/ca_generations.py'
    require(helper in manifest['pins'] and hashlib.sha256(trusted(release/helper)[0]).hexdigest()==manifest['pins'][helper],
            'CA_runtime_migration_required')
    binds=commands.run('CA_effective_gate_bindings',['/usr/bin/systemctl','show','mail-client-cert-gate.service','-p','BindReadOnlyPaths','--value']).decode()
    require(release.as_posix() not in binds and (CONFIG_ROOT/'gate.json').as_posix() not in binds,'CA_enrolled_runtime_migration_required')


def switch(identity, evidence, *, retire=False, rollback=False):
    require(os.geteuid() == 0, 'CA_root_required')
    require(json.loads(trusted('/var/lib/mail-platform-setup/state.json',private=True)[0])['phase']=='published','CA_publication_required')
    identity = str(uuid.UUID(identity))
    transaction = Transaction(evidence_path(evidence))
    commands, files = Commands(evidence), Files('/',evidence)
    stopped = False
    owner_released = False
    with certificate_lock():
        try:
            require_settled()
            verify_runtime(commands)
            records = {actor:public_config(actor) for actor in ACTORS}
            original = adopted(records['issuer'][1])
            prior = records['issuer'][1].get('previous_ca',[])
            current_path=STATE/'ca-current.json'
            retired=json.loads(trusted(current_path,private=True)[0]).get('retired',[]) if current_path.exists() else []
            require(all(item[1]['ca'] == original['ca'] and item[1].get('previous_ca',[]) == prior
                        for item in records.values()), 'CA_actor_configuration_consistency')
            if retire:
                require(identity in [item['issuer_id'] for item in prior], 'CA_retirement_generation')
                count = count_live(commands,identity)
                durable_json(Path(evidence)/'retirement-count.json',{'issuer_id':identity,'unexpired':count})
                require(count == 0, 'CA_unexpired_certificates_prevent_retirement')
                active = original
                previous = [item for item in prior if item['issuer_id'] != identity]
                retired=[next(item for item in prior if item['issuer_id']==identity),*retired]
            elif rollback:
                require(identity in [item['issuer_id'] for item in [*prior,*retired]], 'CA_rollback_retained_generation')
                active = next(item for item in [*prior,*retired] if item['issuer_id'] == identity)
                previous = [original,*(item for item in prior if item['issuer_id'] != identity)]
                require(len(previous)<=2,'CA_rollback_trust_bound')
                retired=[item for item in retired if item['issuer_id']!=identity]
            else:
                active = json.loads(trusted(STATE/'ca'/identity/'generation.json',private=True)[0])
                active['private'] = {'certificate':active['ca']['issuer']['path'],
                                     'key':active['directory']+'/issuer_key','password':active['directory']+'/issuer_password'}
                require(identity != original['issuer_id'] and len(prior) < 2, 'CA_rotation_bound_or_same_generation')
                require(identity not in [item['issuer_id'] for item in prior], 'CA_generation_already_retained')
                previous = [original,*prior]
            # Freeze issuer requests before changing either credentials or trust.
            pending={'format':1,'phase':'changing','evidence':str(evidence),'owner_release_requested':False}
            durable_json(PENDING,pending)
            transaction.value['phase']='stopping_issuance_and_gate';transaction.save()
            for unit in ('mail-client-cert-owner.service','mail-client-cert-gate.socket','mail-client-cert-gate.service','mail-client-cert-issuer.service'):
                stopped = True
                commands.run('CA_stop_'+unit.replace('.','_').replace('-','_'),['/usr/bin/systemctl','stop','--quiet',unit])
            pending_downloads = commands.run('CA_pending_downloads',['/usr/bin/mariadb','--batch','--skip-column-names','-e',
                "SET SESSION time_zone='+00:00'; START TRANSACTION READ ONLY; SELECT COUNT(*) FROM mail_management.mail_client_downloads WHERE state IN ('ready','consumed','unknown') AND expires_at>UTC_TIMESTAMP(); ROLLBACK;"])
            require(pending_downloads.strip() == b'0', 'CA_unclaimed_downloads_prevent_rotation')
            transaction.value['phase']='CA_configuration_publication';transaction.save()
            for actor,(path,config,attributes) in records.items():
                require(trusted(path)[1] == attributes, 'CA_configuration_CAS')
                config = dict(config,ca=active['ca'],previous_ca=previous)
                files.write(str(path),(json.dumps(config,indent=2)+'\n').encode(),attributes['mode'],attributes['uid'],attributes['gid'])
            lines = ['[Service]','LoadCredential=',
                     'LoadCredential=issuer_journal:/var/lib/mail-client-certificates-v1/credentials/issuer/issuer_journal']
            for kind,path in active['private'].items():
                lines.append('LoadCredential=issuer_'+kind+':'+path)
            for item in previous:
                for kind,path in item['private'].items():
                    lines.append('LoadCredential=ca_'+uuid.UUID(item['issuer_id']).hex+'_'+kind+':'+path)
            files.write(DROPIN, ('\n'.join(lines)+'\n').encode())
            health_path = CONFIG_ROOT/'health.json'
            health_raw,attributes = trusted(health_path)
            health = json.loads(health_raw)
            health.update(root_certificate=active['ca']['root']['path'],issuer_certificate=active['ca']['issuer']['path'])
            files.write(str(health_path),(json.dumps(health,indent=2)+'\n').encode(),attributes['mode'],attributes['uid'],attributes['gid'])
            restart(commands,owner=False)
            observe_gate(commands)
            files.write(str(STATE/'ca-current.json'),(json.dumps({'active':active,'previous':previous,'retired':retired,'evidence':str(evidence)},indent=2)+'\n').encode(),0o600)
            owner_released = True
            pending['owner_release_requested']=True;durable_json(PENDING,pending)
            commands.run('CA_release_owner',['/usr/bin/systemctl','start','mail-client-cert-owner.service'])
            commands.run('CA_owner_active',['/usr/bin/systemctl','is-active','mail-client-cert-owner.service'])
            transaction.value.update(phase='issuance_resumed_health_pending',active=active['issuer_id'],
                                     previous=[item['issuer_id'] for item in previous]);transaction.save()
        except Exception as error:
            recovery = {'status':'unchanged'}
            if owner_released:
                recovery = {'status':'held_after_issuance_resumed','all_CA_material_retained':True}
            elif stopped:
                try:
                    # Stop the new actors before restoring their file/credential view.
                    for unit in ('mail-client-cert-owner.service','mail-client-cert-gate.socket','mail-client-cert-gate.service','mail-client-cert-issuer.service'):
                        commands.run('CA_restore_stop_'+unit.replace('.','_').replace('-','_'),['/usr/bin/systemctl','stop','--quiet',unit])
                    recovery = files.restore()
                    require(recovery['status'] == 'restored','CA_recovery_CAS_held')
                    restart(commands)
                except Exception as restore_error:
                    recovery = {'status':'held','class':type(restore_error).__name__}
            if 'pending' in locals():
                pending['phase']='restored' if recovery['status'] in ('unchanged','restored') else 'held'
                durable_json(PENDING,pending)
            failure(evidence,error,transaction.value['phase'],recovery)
            transaction.finish('failed',recovery=recovery)
            raise
    # The collector takes the same certificate lock. Invoke it after releasing
    # the transaction lock, with issuance already resumed and both trusts retained.
    try:
        commands.run('CA_health',['/usr/bin/systemctl','start','mail-client-cert-health.service'])
        pending['phase']='complete';durable_json(PENDING,pending)
        transaction.finish('complete')
    except Exception as error:
        recovery={'status':'held_after_issuance_resumed','all_CA_material_retained':True}
        failure(evidence,error,'post_publication_health',recovery)
        pending['phase']='held';durable_json(PENDING,pending)
        transaction.finish('failed',recovery=recovery)
        raise
    return transaction.value


def recover(evidence, *, rollback=False):
    """Recover an interrupted CA journal while retaining all key and DB state."""
    require(os.geteuid()==0,'CA_root_required')
    transaction=Transaction(evidence_path(evidence))
    commands=Commands(evidence)
    with certificate_lock():
        pending=json.loads(trusted(PENDING,private=True)[0])
        require(pending['phase'] not in ('complete','restored'),'CA_no_pending_recovery')
        source=Path(pending['evidence'])
        try:
            if rollback:
                require(pending['owner_release_requested'] is False,'CA_rollback_unsafe_after_issuance_request')
            for unit in ('mail-client-cert-owner.service','mail-client-cert-gate.socket','mail-client-cert-gate.service','mail-client-cert-issuer.service'):
                commands.run('CA_recovery_stop_'+unit.replace('-','_').replace('.','_'),['/usr/bin/systemctl','stop','--quiet',unit])
            if rollback:
                files=Files('/',evidence)
                allowed={str(CONFIG_ROOT/(actor+'.json')) for actor in ACTORS}|{str(CONFIG_ROOT/'health.json'),DROPIN,str(STATE/'ca-current.json')}
                entries=[json.loads(trusted(path,private=True)[0]) for path in sorted(source.glob('file-entry-*.json'))]
                require(len(entries)<=8 and all(entry['path'] in allowed for entry in entries),'CA_recovery_file_inventory')
                for entry in entries:
                    if entry['backup'] is not None:
                        name=entry['backup']
                        require(Path(name).name==name,'CA_recovery_backup_name')
                        raw=trusted(source/name,private=True)[0]
                        require(hashlib.sha256(raw).hexdigest()==entry['before']['sha256'],'CA_recovery_backup_hash')
                        new_file(Path(evidence)/name,raw)
                files.entries=entries
                restored=files.restore()
                require(restored['status']=='restored','CA_recovery_CAS_held')
            else:
                value=json.loads(trusted(STATE/'ca-current.json',private=True)[0])
                for actor in ACTORS:
                    _,config,_=public_config(actor)
                    require(config['ca']==value['active']['ca'] and config.get('previous_ca',[])==value['previous'],'CA_recovery_configuration_incomplete_use_rollback')
            restart(commands,owner=False)
            observe_gate(commands)
            pending['owner_release_requested']=True;durable_json(PENDING,pending)
            commands.run('CA_recovery_release_owner',['/usr/bin/systemctl','start','mail-client-cert-owner.service'])
        except Exception as error:
            failure(evidence,error,'CA_explicit_recovery',{'status':'held','all_CA_material_retained':True})
            transaction.finish('failed',recovery={'status':'held'})
            raise
    try:
        commands.run('CA_recovery_health',['/usr/bin/systemctl','start','mail-client-cert-health.service'])
        pending['phase']='restored' if rollback else 'complete';durable_json(PENDING,pending)
        transaction.finish('complete',direction=pending['phase'])
    except Exception as error:
        failure(evidence,error,'CA_recovery_post_publication',{'status':'held'})
        transaction.finish('failed',recovery={'status':'held'})
        raise
    return transaction.value
