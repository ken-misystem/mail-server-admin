"""Journalled certificate-pair publication and verification of every TLS entrance."""
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import time
import uuid

from certificate_state import configuration, certificate_lock, private_directory, new_file, trusted, require, failure, evidence_path, require_settled,STATE
from host_transaction import Commands, Transaction, durable_json, regular

SERVICES = ('nginx.service', 'postfix.service', 'dovecot.service')
PENDING = STATE/'tls-pending.json'


def fingerprint(raw):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    return x509.load_pem_x509_certificate(raw).fingerprint(hashes.SHA256()).hex()


def validate_pair(certificate, key, config, commands):
    from cryptography import x509
    from datetime import datetime, timezone
    parsed = x509.load_pem_x509_certificate(certificate)
    now = datetime.now(timezone.utc)
    require(parsed.not_valid_before_utc <= now < parsed.not_valid_after_utc, 'TLS_certificate_validity')
    directory = commands.directory
    chain_path, key_path = directory/'candidate-chain.pem', directory/'candidate-key.pem'
    new_file(chain_path, certificate)
    new_file(key_path, key)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(chain_path), str(key_path))
    commands.run('TLS_chain_and_hostname', ['/usr/bin/openssl', 'verify', '-purpose', 'sslserver',
                 '-verify_hostname', config['host'], '-CAfile', config['trust_store'],
                 '-untrusted', str(chain_path), str(chain_path)])
    return fingerprint(certificate)


def current_live(host):
    live = Path('/etc/letsencrypt/live')/host
    if live.is_symlink():
        target = os.readlink(live)
        resolved = live.resolve(strict=True)
        require(resolved.parent == Path('/etc/letsencrypt/archive')/host, 'TLS_live_generation_root')
        info=resolved.lstat()
        require(info.st_uid==0 and info.st_mode & 0o077==0,'TLS_live_generation_permissions')
        certificate,chain_attributes=trusted(resolved/'fullchain.pem',private=True)
        _,key_attributes=trusted(resolved/'privkey.pem',private=True)
        return {'kind': 'symlink', 'target': target, 'fingerprint': fingerprint(certificate),'certificate_sha256':chain_attributes['sha256'],
                'entries':{'fullchain.pem':chain_attributes,'privkey.pem':key_attributes}}
    require(live.is_dir() and live.stat().st_uid == 0 and not live.stat().st_mode & 0o077, 'TLS_original_live_directory')
    names = sorted(path.name for path in live.iterdir())
    require(set(names) <= {'fullchain.pem', 'privkey.pem', 'chain.pem', 'cert.pem', 'README'}
            and {'fullchain.pem', 'privkey.pem'} <= set(names), 'TLS_original_live_inventory')
    entries = {}
    for name in ('fullchain.pem', 'privkey.pem'):
        path = live/name
        require(path.is_symlink(), 'TLS_original_live_link')
        target = path.resolve(strict=True)
        require(target.parent == Path('/etc/letsencrypt/archive')/host, 'TLS_original_archive_root')
        _, metadata = trusted(target, private=True)
        entries[name] = {'target': os.readlink(path), 'metadata': metadata}
    return {'kind': 'directory', 'entries': entries, 'fingerprint': fingerprint((live/'fullchain.pem').read_bytes()),
            'certificate_sha256':entries['fullchain.pem']['metadata']['sha256']}


def publish_link(live, target):
    temporary = live.with_name('.'+live.name+'-'+uuid.uuid4().hex)
    os.symlink(target, temporary)
    os.replace(temporary, live)
    parent = os.open(live.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def smtp_response(stream, code):
    lines = []
    for unused in range(40):
        line = stream.readline(4096)
        lines.append(line.decode('ascii',errors='replace'))
        if len(line) >= 4096 or not line.startswith((code+b' ',code+b'-')):
            error = ValueError('TLS_SMTP_response_'+code.decode())
            error.diagnostic = {'lines':lines}
            raise error
        if line.startswith(code+b' '):
            return
    error = ValueError('TLS_SMTP_response_bound')
    error.diagnostic = {'lines':lines}
    raise error


def probe(config, expected):
    """TLS handshakes only. No AUTH, SMTP MAIL or message body."""
    host, address = config['host'], config['probe_address']
    observed = {}
    for port, protocol in ((25, 'smtp'), (443, 'tls'), (465, 'tls'), (587, 'smtp'), (993, 'tls'), (995, 'tls')):
        context = ssl.create_default_context(cafile=config['trust_store'])
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        with socket.create_connection((address, port), timeout=8) as channel:
            channel.settimeout(8)
            if protocol == 'smtp':
                stream = channel.makefile('rwb', buffering=0)
                smtp_response(stream,b'220')
                stream.write(b'EHLO tls-check.invalid\r\n')
                smtp_response(stream,b'250')
                stream.write(b'STARTTLS\r\n')
                smtp_response(stream,b'220')
                stream.close()
            with context.wrap_socket(channel, server_hostname=host) as secure:
                pin = hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()
                observed[str(port)] = pin
                if pin != expected:
                    error = ValueError('TLS_presented_certificate_mismatch_'+str(port))
                    error.observed = observed
                    raise error
    return observed


def reload_consumers(commands):
    # Only the certificate pair changed. The native nginx reload parses its
    # configuration in the existing service authority. A separate nginx -t
    # would open the running service's PID/log files for writing in this unit.
    commands.run('Postfix_configuration', ['/usr/sbin/postconf', '-n'])
    commands.run('Postfix_services', ['/usr/sbin/postconf', '-M'])
    commands.run('Dovecot_syntax', ['/usr/bin/doveconf', '-n'])
    for unit in SERVICES:
        commands.run('reload_'+unit.replace('.', '_'), ['/usr/bin/systemctl', 'reload', unit])
    commands.run('refresh_certificate_gate', ['/usr/bin/systemctl', 'try-restart', 'mail-client-cert-gate.service'])


def apply_and_probe(config, commands, expected):
    setup = json.loads(trusted('/var/lib/mail-platform-setup/state.json', private=True)[0])
    if setup['phase'] == 'published':
        reload_consumers(commands)
        deadline = time.monotonic()+20
        observations = []
        while True:
            try:
                observed = probe(config, expected)
                durable_json(commands.directory/'TLS-observations.json',observations+[{'complete':observed}])
                return observed
            except (ValueError, OSError) as error:
                observations.append({'at':time.time(),'presented':getattr(error,'observed',{}),'expected':expected,
                                     'class':type(error).__name__,'reason':str(error),
                                     'diagnostic':getattr(error,'diagnostic',None)})
                durable_json(commands.directory/'TLS-observations.json',observations)
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.2)
    require(setup['phase'] == 'setup', 'TLS_setup_phase')
    commands.run('setup_nginx_reload', ['/usr/bin/systemctl', 'reload', 'nginx.service'])
    context = ssl.create_default_context(cafile=config['trust_store'])
    deadline=time.monotonic()+20
    observations=[]
    while True:
        try:
            with socket.create_connection(('127.0.0.1', 443), timeout=8) as channel:
                with context.wrap_socket(channel, server_hostname=config['host']) as secure:
                    actual=hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()
            observations.append({'actual':actual,'expected':expected})
            if actual==expected:
                durable_json(commands.directory/'setup-TLS-observations.json',observations)
                return {'phase':'isolated_setup','fingerprint':actual}
        except OSError as error:
            observations.append({'class':type(error).__name__,'reason':str(error)})
        durable_json(commands.directory/'setup-TLS-observations.json',observations)
        require(time.monotonic()<deadline,'TLS_initial_UI_certificate_mismatch')
        time.sleep(.2)


def deploy(certificate_path, key_path, evidence):
    require(os.geteuid() == 0, 'certificate_root_required')
    config = configuration()
    certificate = trusted(certificate_path)[0]
    key = trusted(key_path, private=True)[0]
    transaction = Transaction(evidence_path(evidence))
    commands = Commands(evidence)
    phase, changed, moved, bundle_changed = 'validation', False, False, False
    old = bundle = None
    live = Path('/etc/letsencrypt/live')/config['host']
    backup = live.with_name('.'+live.name+'-before-'+uuid.uuid4().hex)
    with certificate_lock():
        try:
            require_settled()
            expected = validate_pair(certificate, key, config, commands)
            old = current_live(config['host'])
            durable_json(Path(evidence)/'live-before.json', old)
            require(expected != old['fingerprint'] or hashlib.sha256(certificate).hexdigest()!=old['certificate_sha256'], 'TLS_certificate_already_current')
            receipt=STATE/'tls.json'
            if receipt.exists():
                previous=json.loads(trusted(receipt,private=True)[0])
                require(previous['fingerprint']==old['fingerprint'] and previous['generation']==str(live.resolve()),'TLS_unrecorded_live_change')
                require(previous.get('certificate_sha256',old['certificate_sha256'])==old['certificate_sha256'],'TLS_unrecorded_chain_change')
            directory = private_directory(Path('/etc/letsencrypt/archive')/config['host']/('generation-'+uuid.uuid4().hex))
            new_file(directory/'fullchain.pem', certificate)
            new_file(directory/'privkey.pem', key)
            new_file(directory/'certificate.pem', certificate)
            new_file(directory/'key.pem', key)
            bundle = Path('/var/lib/mail-client-cert-public-v1/tls/current')
            old_bundle = os.readlink(bundle)
            from cryptography import x509
            expiry = x509.load_pem_x509_certificate(certificate).not_valid_after_utc.timestamp()
            new_file(directory/'public.json', (json.dumps({'version':1,'certificate_sha256':hashlib.sha256(certificate).hexdigest(),'expires':expiry})+'\n').encode())
            phase = 'publication'
            transaction.value.update(phase=phase, live=str(live), backup=str(backup), generation=str(directory), old_bundle=old_bundle)
            transaction.save()
            pending={'format':1,'phase':'publication','live':str(live),'backup':str(backup),
                     'generation':str(directory),'old_bundle':old_bundle,'before':old,'expected':expected,'evidence':str(evidence)}
            durable_json(PENDING,pending)
            require(current_live(config['host']) == old, 'TLS_live_CAS_conflict')
            if old['kind'] == 'directory':
                os.replace(live, backup)
                moved = True
            publish_link(live, '../archive/'+config['host']+'/'+directory.name)
            changed = True
            publish_link(bundle, str(directory))
            bundle_changed = True
            pending['phase']='published_verification_pending';durable_json(PENDING,pending)
            phase = 'consumer_reload_and_verification'
            observed = apply_and_probe(config, commands, expected)
            durable_json(Path(evidence)/'presented.json', observed)
            durable_json(STATE/'tls.json', {'format':1,'generation':str(directory),'fingerprint':expected,
                                          'certificate_sha256':hashlib.sha256(certificate).hexdigest(),'phase':'complete'})
            pending['phase']='complete';durable_json(PENDING,pending)
            transaction.finish('complete', certificate_fingerprint=expected)
            return {'status':'complete','fingerprint':expected,'evidence':str(evidence)}
        except Exception as error:
            recovery = {'status':'unchanged'}
            if moved or changed:
                try:
                    if changed:
                        require(live.is_symlink() and live.resolve() == directory, 'TLS_recovery_live_CAS')
                    else:
                        require(not os.path.lexists(live) and backup.is_dir(), 'TLS_adoption_recovery_CAS')
                    require(bundle.is_symlink() and os.readlink(bundle) == (str(directory) if bundle_changed else old_bundle), 'TLS_recovery_bundle_CAS')
                    if old['kind'] == 'directory':
                        if changed:
                            live.unlink()
                        os.replace(backup, live)
                    else:
                        publish_link(live, old['target'])
                    if bundle_changed:
                        publish_link(bundle, old_bundle)
                    if changed:
                        apply_and_probe(config, commands, old['fingerprint'])
                    durable_json(STATE/'tls.json',{'format':1,'generation':str(live.resolve()),'fingerprint':old['fingerprint'],
                                                 'certificate_sha256':old['certificate_sha256'],'phase':'complete'})
                    recovery = {'status':'restored','old_fingerprint':old['fingerprint']}
                except Exception as restore_error:
                    import traceback
                    recovery = {'status':'held','class':type(restore_error).__name__,
                                'reason':str(restore_error) if type(restore_error) is ValueError else 'operation_failed',
                                'command':getattr(restore_error,'record',None),
                                'frames':[{'file':Path(item.filename).name,'line':item.lineno,'function':item.name}
                                          for item in traceback.extract_tb(restore_error.__traceback__)]}
            failure(evidence, error, phase, recovery)
            if 'pending' in locals():
                pending['phase']='restored' if recovery['status'] in ('restored','restored_before_pointer_publication','unchanged') else 'held'
                durable_json(PENDING,pending)
            transaction.finish('failed', phase_failed=phase, recovery=recovery)
            raise


def recover(evidence, *, rollback=False):
    """Explicit recovery of a durable interrupted transaction, with exact CAS."""
    require(os.geteuid()==0,'certificate_root_required')
    config=configuration()
    transaction=Transaction(evidence_path(evidence))
    commands=Commands(evidence)
    with certificate_lock():
        pending=json.loads(trusted(PENDING,private=True)[0])
        require(pending['phase'] not in ('complete','restored'),'TLS_no_pending_recovery')
        live=Path('/etc/letsencrypt/live')/config['host']
        generation=Path(pending['generation'])
        backup=Path(pending['backup'])
        require(pending['live']==str(live) and generation.parent==Path('/etc/letsencrypt/archive')/config['host']
                and backup.parent==live.parent and backup.name.startswith('.'+config['host']+'-before-'),'TLS_recovery_paths')
        bundle=Path('/var/lib/mail-client-cert-public-v1/tls/current')
        old=pending['before']
        try:
            if rollback:
                bundle_target=os.readlink(bundle)
                require(bundle_target in (str(generation),pending['old_bundle']),'TLS_recovery_bundle_unknown')
                new_live=live.is_symlink() and live.resolve()==generation
                if not new_live and os.path.lexists(live):
                    require(current_live(config['host'])==old,'TLS_recovery_old_CAS')
                if old['kind']=='directory' and (new_live or not os.path.lexists(live)):
                    require(backup.is_dir() and not backup.is_symlink(),'TLS_recovery_backup_missing')
                    for name,entry in old['entries'].items():
                        require(os.readlink(backup/name)==entry['target'] and trusted((backup/name).resolve(),private=True)[1]==entry['metadata'],'TLS_recovery_backup_CAS')
                    if new_live:live.unlink()
                    os.replace(backup,live)
                elif new_live:
                    publish_link(live,old['target'])
                if bundle_target!=pending['old_bundle']:publish_link(bundle,pending['old_bundle'])
                expected=old['fingerprint']
                phase='restored'
            else:
                require(live.is_symlink() and live.resolve()==generation and bundle.resolve()==generation,'TLS_recovery_generation_CAS')
                certificate=trusted(generation/'fullchain.pem',private=True)[0]
                key=trusted(generation/'privkey.pem',private=True)[0]
                expected=validate_pair(certificate,key,config,commands)
                require(expected==pending['expected'],'TLS_recovery_certificate_pin')
                phase='complete'
            observed=apply_and_probe(config,commands,expected)
            durable_json(Path(evidence)/'presented.json',observed)
            pending['phase']=phase;pending['recovery_evidence']=str(evidence)
            durable_json(PENDING,pending)
            durable_json(STATE/'tls.json',{'format':1,'generation':str(live.resolve()),'fingerprint':expected,
                                          'certificate_sha256':hashlib.sha256(trusted((live/'fullchain.pem').resolve(),private=True)[0]).hexdigest(),'phase':'complete'})
            transaction.finish('complete',direction=phase,fingerprint=expected)
            return transaction.value
        except Exception as error:
            failure(evidence,error,'TLS_explicit_recovery',{'status':'held'})
            transaction.finish('failed',recovery={'status':'held'})
            raise
