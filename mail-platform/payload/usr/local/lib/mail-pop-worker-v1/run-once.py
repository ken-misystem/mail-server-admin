#!/usr/bin/python3
"""Pilot account1 only; normal fetchmail, preserved baseline, no scheduler or retries."""
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import time

BASE = Path('/usr/local/lib/mail-pop-worker-v1')
STATE = Path('/var/lib/mail-pop')
ACCOUNT = STATE / 'accounts/1'
PHP = ['/usr/bin/php', '-d', 'display_errors=0', '-d', 'log_errors=0', '-d', 'auto_prepend_file=', '-d', 'auto_append_file=', '-d', 'opcache.enable_cli=0']
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'}
FETCH = ['/usr/bin/fetchmail','--nodetach','--daemon','0','--nosyslog','--silent','-f','-',
         '--idfile',(ACCOUNT / 'fetchids').as_posix(),'--pidfile',(ACCOUNT / 'fetchmail.pid').as_posix()]

def need(value, reason):
    if not value:raise ValueError(reason)

def source_allowed(row):
    need(isinstance(row,dict) and set(row)=={'id','user_id','remote_host','remote_port','remote_username','enabled','email','cap','seconds','active_count'},'source_shape')
    need(row['id']=='1' and row['email']==row['remote_username']=='ken@mi-sys.jp'
         and row['remote_host']=='mail.mi-sys.jp' and row['remote_port']==995,'source_identity')
    need(isinstance(row['user_id'],str) and re.fullmatch(r'[1-9][0-9]{0,19}',row['user_id'])
         and int(row['user_id'])<=18446744073709551615,'owner_id')
    need(all(type(row[k]) is int for k in ('remote_port','enabled','cap','seconds','active_count')),'source_types')
    need(row['enabled']==1 and 1<=row['active_count']<=row['cap']<=100 and 60<=row['seconds']<=86400,'source_not_allowed')

def read_file(path, uid, gid, mode, maximum):
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as handle:
        info=os.fstat(handle.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid==uid and info.st_gid==gid and info.st_nlink==1
             and stat.S_IMODE(info.st_mode)==mode and 0<info.st_size<=maximum,'file_boundary')
        raw=handle.read(maximum+1);after=os.fstat(handle.fileno())
    need(len(raw)==info.st_size and (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)
         ==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns),'file_changed')
    return raw

def bridge(mode, value=None):
    need(mode in ('--metadata','--config','--result','--history-start','--history-finish'),'bridge_mode')
    data=None if value is None else json.dumps(value,separators=(',',':')).encode()
    r=subprocess.run(PHP+[str(BASE/'bridge.php'),mode],input=data,stdout=subprocess.PIPE,
                     stderr=subprocess.DEVNULL,timeout=15,env=ENV,cwd='/')
    need(0<len(r.stdout)<=16384,'bridge_unverified')
    if r.returncode!=0:retry_bridge_error(r.stdout)
    result=json.loads(r.stdout);need(isinstance(result,dict) and result.get('status')=='ok','bridge_unverified')
    return result

def endpoint(saved, row, history):
    code='import json,socket,sys;h=json.loads(sys.stdin.read());print(json.dumps(sorted({r[4][0] for r in socket.getaddrinfo(h,995,type=socket.SOCK_STREAM)})))'
    r=subprocess.run(['/usr/bin/python3','-I','-B','-c',code],input=json.dumps(row['remote_host']).encode(),
                     stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15,env=ENV,cwd='/')
    need(r.returncode==0 and len(r.stdout)<=16384,'dns_unverified')
    ips=json.loads(r.stdout);need(isinstance(ips,list) and 0<len(ips)<=32,'dns_shape')
    addresses={history.public_ip(str(ipaddress.ip_address(ip))) for ip in ips}
    r=subprocess.run(['/usr/sbin/ip','-j','address','show'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                     stderr=subprocess.DEVNULL,timeout=10,env=ENV,cwd='/')
    need(r.returncode==0 and len(r.stdout)<=131072,'local_addresses')
    interfaces=json.loads(r.stdout)
    local={str(ipaddress.ip_address(x['local'])) for interface in interfaces for x in interface['addr_info']}
    need(local and not addresses & local and saved['queryname'] in addresses,'source_changed_or_self')
    history.require_binding(saved,'1',row['remote_host'],row['remote_port'],row['remote_username'],saved['queryname'])
    return saved['queryname']

def record(value):
    # Only account1 attempt metadata; never history/binding/initialization or plaintext credentials.
    target=ACCOUNT/'attempt.json';temporary=ACCOUNT/'.attempt.tmp'
    need(not os.path.lexists(temporary),'attempt_temporary_exists')
    with os.fdopen(os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600),'wb') as handle:
        handle.write((json.dumps(value,sort_keys=True)+'\n').encode());handle.flush();os.fsync(handle.fileno())
    os.replace(temporary,target)
    fd=os.open(ACCOUNT,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

"""Injected into the pinned worker: bounded stderr flags only, no raw output/file."""








"""Finite run-history metadata; injected into the currently deployed pilot worker."""


def history_ids(raw, saved):
    # IDs remain private memory and are never put in the run-history table.
    need(isinstance(raw, bytes) and 0 < len(raw) <= 128*1024*1024, 'history_count')
    prefix=(saved['username']+'@'+saved['queryname']+' ').encode('ascii')
    need(raw.endswith(b'\n'), 'history_count')
    seen=set()
    for line in raw.split(b'\n')[:-1]:
        need(line.startswith(prefix) and len(line)<512, 'history_count')
        value=line[len(prefix):]
        need(1<=len(value)<=70 and all(33<=c<=126 for c in value) and value not in seen, 'history_count')
        seen.add(value)
    need(0<len(seen)<=2000000, 'history_count')
    return seen


def history_delta(before, after):
    need(isinstance(before,set) and isinstance(after,set) and before<=after, 'history_count')
    count=len(after-before)
    need(count<=50, 'history_count')
    return count




def finish_run_history(run_id, result, history_before, saved, user):
    count=0 if not result.get('retrieval_attempted') else None
    if result.get('retrieval_attempted') and history_before is not None:
        try:
            after=read_file(ACCOUNT/'fetchids',user.pw_uid,user.pw_gid,0o600,128*1024*1024)
            count=history_delta(history_before,history_ids(after,saved))
        except Exception:count=None
    value={'run_id':run_id,**history_summary(result,count)}
    bridge('--history-finish',value)

def _mail_pop_compat_load():
    import hashlib,os,stat,pwd
    path='/usr/local/lib/mail-pop-compat-v1/compat.py'
    group=pwd.getpwnam('mailpop').pw_gid
    for parent in ('/usr','/usr/local','/usr/local/lib','/usr/local/lib/mail-pop-compat-v1'):
        info=os.lstat(parent)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('compat_code')
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as handle:
        info=os.fstat(handle.fileno());raw=handle.read(65537);after=os.fstat(handle.fileno())
    signature=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
    if not stat.S_ISREG(info.st_mode) or (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode),info.st_nlink)!=(0,group,0o640,1) or signature(info)!=signature(after) or signature(info)!=signature(os.lstat(path)):raise ValueError('compat_code')
    if len(raw)!=15388 or hashlib.sha256(raw).hexdigest()!='2121a0f745d1f512a22b61681e4c0d4573d669355a43e3acd96f7aa6b1b7f291':raise ValueError('compat_code')
    scope={'__name__':'pinned_pop_compat'}
    exec(compile(raw,'pinned_pop_compat','exec'),scope)
    return scope


RETRY_DETAILS = ('retry_wait', 'retry_state_changed', 'retry_reserved', 'retry_blocked', 'socket_unclassified', 'socket_connect_timeout', 'socket_server_timeout', 'socket_refused', 'socket_reset', 'socket_eof', 'network_unreachable', 'host_unreachable', 'dns_temporary', 'uidl_write_failed', 'smtp_timeout')
RETRY_REASONS = RETRY_DETAILS + ('source_not_allowed', 'source_identity', 'owner_id', 'source_types', 'source_shape', 'file_boundary', 'file_changed', 'compat_code', 'migration_compat_unverified', 'previous_attempt_unverified', 'poll_not_due', 'history_binding_changed', 'initialization_binding', 'first_history_changed', 'history_count', 'dns_unverified', 'dns_shape', 'local_addresses', 'source_changed_or_self', 'fetchmail_argv', 'native_exit_unverified', 'bridge_unverified', 'bridge_mode', 'result_shape', 'attempt_temporary_exists', 'runtime_directory', 'state_directory', 'lock_metadata', 'mailpop_caller', 'run_id', 'history_code_pin', 'diagnostic_shape', 'config_bound')

def retry_digest(raw):
    return hashlib.sha256(raw).hexdigest()

def retry_hashes(value):
    need(type(value) is dict and set(value) == {'fetchids', 'binding.json', 'initialization.json'}, 'retry_state_changed')
    need(all((type(x) is str and re.fullmatch('[0-9a-f]{64}', x) for x in value.values())), 'retry_state_changed')
    return value

def retry_snapshot(user):
    return {n: retry_digest(read_file(ACCOUNT / n, user.pw_uid if n == 'fetchids' else 0, user.pw_gid, 384 if n == 'fetchids' else 416, 128 * 1024 * 1024 if n == 'fetchids' else 65536)) for n in ('fetchids', 'binding.json', 'initialization.json')}

def retry_delay(streak, interval):
    need(type(streak) is int and 1 <= streak <= 65535 and (type(interval) is int) and (60 <= interval <= 86400), 'retry_blocked')
    return max(interval, min(3600, 300 * 2 ** min(streak - 1, 4)))


def retry_decision(previous, attempt_hash, snapshot, approval, now, interval):
    need(type(previous) is dict and previous.get('account_id') == '1' and (previous.get('phase') == 'complete') and (type(previous.get('native_exit')) is int) and (previous.get('database_result_verified') is True) and (type(previous.get('started_at')) is int) and (0 < previous['started_at'] <= now), 'retry_reserved')
    code = previous['native_exit']
    if code in (0, 1, 13):
        return dict(wait=False, streak=0, delay_seconds=0, next_utc_epoch=0)
    need(code == 2 and retry_diagnostic_allowed(previous.get('diagnostic')), 'retry_blocked')
    retry_hashes(snapshot)
    context = previous.get('retry_context')
    if context is None:
        need(type(approval) is dict and set(approval) == {'version', 'account_id', 'attempt_sha256', 'completed_at', 'state'} and (type(approval['version']) is int) and (approval['version'] == 1) and (approval['account_id'] == '1') and (approval['attempt_sha256'] == attempt_hash) and (retry_hashes(approval['state']) == snapshot), 'retry_state_changed')
        streak = 1
        completed = approval['completed_at']
        delay = retry_delay(streak, interval)
        need(type(completed) is int and previous['started_at'] <= completed <= now, 'retry_state_changed')
    else:
        need(type(context) is dict and set(context) == {'version', 'streak', 'completed_at', 'delay_seconds', 'state'} and (type(context['version']) is int) and (context['version'] == 1) and (retry_hashes(context['state']) == snapshot), 'retry_state_changed')
        streak = context['streak']
        completed = context['completed_at']
        old_delay = context['delay_seconds']
        need(type(completed) is int and previous['started_at'] <= completed <= now and (type(old_delay) is int) and (300 <= old_delay <= 86400) and (old_delay >= retry_delay(streak, 60)), 'retry_state_changed')
        delay = max(old_delay, interval)
    due = completed + delay
    return dict(wait=now < due, streak=streak, delay_seconds=delay, next_utc_epoch=due)

def retry_previous(previous, raw, user, row):
    need(not any((os.path.lexists(ACCOUNT / n) for n in ('.attempt.tmp', 'fetchids_', 'fetchmail.pid'))), 'retry_reserved')
    code = previous.get('native_exit')
    approval = None
    snapshot = None
    if type(code) is int and code == 2:
        snapshot = retry_snapshot(user)
        if previous.get('retry_context') is None:
            approval = json.loads(read_file(Path('/etc/mail-pop/retry-bootstrap-v1.json'), 0, user.pw_gid, 416, 4096))
    return retry_decision(previous, retry_digest(raw), snapshot, approval, int(time.time()), row['seconds'])

def retry_complete(attempt, result, user, history_before, saved, row, streak, bindings):
    need(result.get('diagnostic', {}).get('detail_code') != 'uidl_write_failed', 'history_count')
    if result['native_exit'] != 2:
        return
    if not retry_diagnostic_allowed(result.get('diagnostic')):
        result['scheduled_retry_allowed'] = False
        return
    need(not any((os.path.lexists(ACCOUNT / n) for n in ('.attempt.tmp', 'fetchids_', 'fetchmail.pid'))), 'retry_reserved')
    after = read_file(ACCOUNT / 'fetchids', user.pw_uid, user.pw_gid, 384, 128 * 1024 * 1024)
    count = history_delta(history_before, history_ids(after, saved))
    state = retry_snapshot(user)
    need(state['fetchids'] == retry_digest(after), 'retry_state_changed')
    need(state['binding.json'] == bindings['binding.json'] and state['initialization.json'] == bindings['initialization.json'], 'retry_state_changed')
    streak = min(streak + 1, 65535)
    delay = retry_delay(streak, row['seconds'])
    completed = int(time.time())
    attempt['retry_context'] = dict(version=1, streak=streak, completed_at=completed, delay_seconds=delay, state=state)
    result.update(scheduled_retry_allowed=True, retry=dict(streak=streak, delay_seconds=delay, next_utc_epoch=completed + delay), history_preserved=True, seen_delta=count)

def retry_error(error, stage):
    name = type(error).__name__
    allowed = ('ValueError', 'OSError', 'PermissionError', 'FileNotFoundError', 'BlockingIOError', 'NameError', 'KeyError', 'TypeError', 'TimeoutExpired', 'InterruptedError', 'KeyboardInterrupt', 'SystemExit')
    reason = error.args[0] if type(error) is ValueError and len(error.args) == 1 and (error.args[0] in RETRY_REASONS) else 'unclassified'
    number = getattr(error, 'errno', None)
    line = 0
    t = error.__traceback__
    while t:
        if t.tb_frame.f_code.co_filename == __file__:
            line = t.tb_lineno
        t = t.tb_next
    answer = dict(version=1, phase=stage, error_class=name if name in allowed else 'other', reason=reason, errno=number if type(number) is int and 0 <= number <= 4095 else None, worker_source_line=line)
    d = getattr(error, 'bridge_diagnostic', None)
    if d is not None:
        try:
            answer['bridge'] = retry_bridge_diagnostic(d)
        except ValueError:
            pass
    return answer

def retry_bridge_error(raw):
    v = json.loads(raw)
    need(type(v) is dict and set(v) == {'status', 'raw_error_output', 'diagnostic'} and (v['status'] == 'fail') and (v['raw_error_output'] is False), 'bridge_unverified')
    d = retry_bridge_diagnostic(v['diagnostic'])
    e = ValueError('bridge_unverified')
    e.bridge_diagnostic = d
    raise e

def retry_bridge_diagnostic(d):
    need(type(d) is dict and set(d) == {'error_class', 'source_line', 'sqlstate', 'native_code', 'missing_driver'}, 'bridge_unverified')
    need(d['error_class'] in ('PDOException', 'RuntimeException', 'JsonException', 'TypeError', 'Error', 'other') and type(d['source_line']) is int and (0 < d['source_line'] <= 1000) and (type(d['missing_driver']) is bool), 'bridge_unverified')
    need(d['sqlstate'] is None or (type(d['sqlstate']) is str and re.fullmatch('[A-Z0-9]{5}', d['sqlstate'])), 'bridge_unverified')
    need(d['native_code'] is None or (type(d['native_code']) is int and 0 <= d['native_code'] <= 65535), 'bridge_unverified')
    return d



def diagnostic_fetch(config, diagnostic):
    import selectors
    import types
    need(isinstance(config, bytes) and 0 < len(config) <= 8192, 'config_bound')
    need(diagnostic == new_fetch_diagnostic(), 'diagnostic_shape')
    process = None
    selected = None
    buffers = {k: bytearray() for k in ('stdout', 'stderr')}
    sent = 0
    deadline = time.monotonic() + 900
    try:
        process = subprocess.Popen(FETCH, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, cwd=str(ACCOUNT))
        selected = selectors.DefaultSelector()
        for stream, event in ((process.stdin, selectors.EVENT_WRITE), (process.stdout, selectors.EVENT_READ), (process.stderr, selectors.EVENT_READ)):
            os.set_blocking(stream.fileno(), False)
            selected.register(stream, event)
        while selected.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                diagnostic['process_timed_out'] = True
                raise subprocess.TimeoutExpired(FETCH, 900)
            for key, event in selected.select(min(remaining, 1)):
                if key.fileobj is process.stdin:
                    try:
                        sent += os.write(key.fd, config[sent:sent + 4096])
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        diagnostic['stdin_write_error'] = True
                        sent = len(config)
                    if sent == len(config):
                        selected.unregister(process.stdin)
                        process.stdin.close()
                else:
                    try:
                        chunk = os.read(key.fd, 4096)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selected.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    label = 'stdout' if key.fileobj is process.stdout else 'stderr'
                    buf = buffers[label]
                    room = 32768 - len(buf)
                    buf.extend(chunk[:room])
                    diagnostic[label + '_truncated'] |= len(chunk) > room
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            diagnostic['process_timed_out'] = True
            raise subprocess.TimeoutExpired(FETCH, 900)
        try:
            code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            diagnostic['process_timed_out'] = True
            raise
        diagnostic['native_exit_class'] = {0: 'completed', 1: 'no_mail', 2: 'socket_error', 3: 'authentication_failure', 4: 'protocol_error', 5: 'syntax_or_command_error', 6: 'rcfile_permissions', 7: 'server_error_or_timeout', 8: 'client_exclusion', 9: 'authentication_lock_busy', 10: 'smtp_error', 11: 'dns_error', 12: 'bsmtp_error', 13: 'fetch_limit', 14: 'server_busy', 15: 'internal_error'}.get(code, 'other')
        return types.SimpleNamespace(returncode=code)
    finally:
        try:
            for k in ('stderr', 'stdout'):
                classify_fetch_stderr(buffers[k], diagnostic, k)
        finally:
            for raw in buffers.values():
                raw[:] = b'\x00' * len(raw)
                raw.clear()
            if selected is not None:
                selected.close()
            if process is not None:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()

def _smtp_v2_new_fetch_diagnostic():
    return dict(version=2, raw_output_saved=False, stderr_inspected_bytes=0, stderr_truncated=False, stdout_inspected_bytes=0, stdout_truncated=False, process_timed_out=False, stdin_write_error=False, native_exit_class='unknown', detail_code='none', transport_phase='unknown', timeout_seconds=None, reported_errno_symbol='none', unclassified_records=0, markers={k: False for k in ('connection_refused', 'connection_reset', 'connection_closed', 'timeout', 'tls', 'certificate', 'authentication', 'smtp', 'protocol', 'syntax')})

def _smtp_v2_retry_allowed(d):
    if type(d) is not dict:
        return False
    old = {'version', 'raw_output_saved', 'stderr_inspected_bytes', 'stderr_truncated', 'process_timed_out', 'stdin_write_error', 'native_exit_class', 'markers'}
    if type(d.get('version')) is not int or d['version'] not in (1, 2):
        return False
    if set(d) != (old if d['version'] == 1 else set(_smtp_v2_new_fetch_diagnostic())):
        return False
    for k in ('stderr_inspected_bytes',) if d['version'] == 1 else ('stderr_inspected_bytes', 'stdout_inspected_bytes'):
        if type(d[k]) is not int or not 0 <= d[k] <= 32768:
            return False
    flags = d.get('markers')
    return type(d.get('version')) is int and d['version'] in (1, 2) and (d.get('native_exit_class') == 'socket_error') and (d.get('raw_output_saved') is False) and (d.get('process_timed_out') is False) and (d.get('stdin_write_error') is False) and (d.get('stderr_truncated') is False) and (d.get('stdout_truncated', False) is False) and (type(flags) is dict) and (set(flags) == {'connection_refused', 'connection_reset', 'connection_closed', 'timeout', 'tls', 'certificate', 'authentication', 'smtp', 'protocol', 'syntax'}) and all((type(x) is bool for x in flags.values())) and (not any((flags[k] for k in ('certificate', 'tls', 'authentication', 'smtp', 'protocol', 'syntax')))) and (d.get('detail_code') != 'uidl_write_failed') and (d.get('transport_phase') != 'smtp')

def _smtp_prior_history_summary(result, count):
    phase=result.get('stage','preconditions')
    need(phase in ('preconditions','policy','binding','private_config','native_fetch','result_update','complete'), 'history_phase')
    code=result.get('native_exit')
    if type(code) is not int or not 0<=code<=255:code=None
    diagnostic=result.get('diagnostic',{})
    flags=diagnostic.get('markers',{})
    outcome='failed';detail='preflight_failed'
    if diagnostic.get('process_timed_out'):detail='timeout'
    elif result.get('error_class') in ('KeyboardInterrupt','SystemExit','InterruptedError'):detail='interrupted'
    elif code is not None and code not in (0,1,13):
        detail={2:'connection_failed',3:'auth_failed',4:'protocol_failed',7:'timeout',10:'smtp_observed',11:'connection_failed'}.get(code,'native_failed')
        # Exit7 conflates server error and timeout. Do not claim timeout without a marker.
        if code==7 and not flags.get('timeout'):detail='native_failed'
        if flags.get('certificate') or flags.get('tls'):detail='tls_failed'
    elif result.get('status')=='ok' and result.get('database_result_verified') is True and code in (0,1,13):
        outcome={0:'success',1:'no_mail',13:'limit_reached'}[code];detail='none'
        if flags.get('smtp'):outcome='warning';detail='smtp_observed'
        if count is None:outcome='warning';detail='history_unverified'
    elif result.get('result')=='retry_wait':outcome='warning';detail='retry_wait'
    elif phase=='result_update':detail='result_unverified'
    elif result.get('retrieval_attempted'):detail='native_failed'
    elif result.get('history_reason')=='source_not_allowed':detail='source_not_allowed'
    if code==2 and diagnostic.get('detail_code') in RETRY_DETAILS:detail=diagnostic['detail_code']
    if result.get('history_reason') in RETRY_DETAILS:detail=result['history_reason']
    return dict(outcome=outcome,phase=phase,detail_code=detail,fetched_count=count,native_exit=code)

"""Pure SMTP evidence for fetchmail6.4.39. No I/O, raw replies or message identifiers."""
SMTP_DETAILS=('smtp_reject_temporary','smtp_reject_permanent','smtp_reject_mixed',
    'smtp_connect_failed','smtp_failure_unclassified','smtp_legacy_unverified','diagnostic_incomplete')


def _smtp_blank():
    return dict(version=1,response_groups=[],reject_records=0,normal_response_records=0,
        connection_failure_records=0,timeout_records=0,transaction_failure_records=0,
        unclassified_failure_records=0,malformed_enhanced_records=0,groups_truncated=False)


def _smtp_valid(d):
    need(type(d) is dict and set(d)==set(_smtp_blank()) and type(d['version']) is int and d['version']==1,'diagnostic_shape')
    for k in ('reject_records','normal_response_records','connection_failure_records','timeout_records',
              'transaction_failure_records','unclassified_failure_records','malformed_enhanced_records'):
        need(type(d[k]) is int and 0<=d[k]<=1000,'diagnostic_shape')
    need(type(d['groups_truncated']) is bool and type(d['response_groups']) is list and len(d['response_groups'])<=8,'diagnostic_shape')
    seen=set();total=0
    for g in d['response_groups']:
        need(type(g) is dict and set(g)=={'code','enhanced','records'} and type(g['code']) is int and 400<=g['code']<=599
             and type(g['records']) is int and 1<=g['records']<=1000,'diagnostic_shape')
        e=g['enhanced'];need(e is None or type(e) is str and re.fullmatch(str(g['code']//100)+r'\.[0-9]{1,3}\.[0-9]{1,3}',e),'diagnostic_shape')
        pair=(g['code'],e);need(pair not in seen,'diagnostic_shape');seen.add(pair);total+=g['records']
    need(min(1000,total)<=d['reject_records'] and (d['groups_truncated'] or min(1000,total)==d['reject_records']),'diagnostic_shape')
    return d


def _smtp_add(d,key):d[key]=min(1000,d[key]+1)


def _smtp_line(text,d):
    """Anchored application diagnostics only. Never infer SMTP from bare reply/body text."""
    if not isinstance(text,str) or len(text)>32768:return False
    s=d['smtp'];line=text[11:] if text.startswith('fetchmail: ') else text
    # Upstream sink.c formats: SMTP error: <reply>, SMTP connect to <host> failed.
    m=re.fullmatch(r'SMTP error: ([45][0-9]{2})(?:[ -]([^\r\n]*))?',line)
    if m:
        code=int(m[1]);tail=m[2] or '';e=None;candidate=re.match(r'([245]\.[0-9]{1,3}\.[0-9]{1,3})(?:[ \t]|$)',tail)
        if candidate:
            if candidate[1][0]==str(code//100):e=candidate[1]
            else:_smtp_add(s,'malformed_enhanced_records')
        _smtp_add(s,'reject_records')
        for g in s['response_groups']:
            if (g['code'],g['enhanced'])==(code,e):g['records']=min(1000,g['records']+1);break
        else:
            if len(s['response_groups'])<8:s['response_groups'].append(dict(code=code,enhanced=e,records=1))
            else:s['groups_truncated']=True
        return True
    if re.fullmatch(r'SMTP(?:<| response:)[ \t]+[23][0-9]{2}(?:[ -][^\r\n]*)?',line):
        _smtp_add(s,'normal_response_records');return True
    if re.fullmatch(r'SMTP connect to [^\r\n]{1,1024} failed',line):
        _smtp_add(s,'connection_failure_records');return True
    if re.fullmatch(r'timeout after [0-9]{1,4} seconds waiting for (?:SMTP|listener to respond)\.',line):
        _smtp_add(s,'timeout_records');return True
    if re.fullmatch(r'socket error while fetching from [^\r\n]{1,1024} and delivering to SMTP host [^\r\n]{1,512}',line):
        _smtp_add(s,'connection_failure_records');return True
    if line=='SMTP listener refused delivery' or re.fullmatch(r'SMTP transaction error while fetching from [^\r\n]{1,1536}',line):
        _smtp_add(s,'transaction_failure_records');return True
    if line.startswith('SMTP error:') or re.fullmatch(r'SMTP listener (?:doesn.t (?:really )?like|rejected) [^\r\n]{1,1024}',line):
        _smtp_add(s,'unclassified_failure_records');return True
    return False


def _smtp_kind(d):
    s=_smtp_valid(d['smtp']);classes={g['code']//100 for g in s['response_groups']}
    if s['reject_records']:
        if s['groups_truncated']:return 'smtp_failure_unclassified'
        return 'smtp_reject_mixed' if len(classes)>1 else 'smtp_reject_temporary' if classes=={4} else 'smtp_reject_permanent'
    if s['timeout_records']:return 'smtp_timeout'
    if s['connection_failure_records']:return 'smtp_connect_failed'
    if s['transaction_failure_records'] or s['unclassified_failure_records'] or d.get('native_exit_class')=='smtp_error':return 'smtp_failure_unclassified'
    return 'none'


def _smtp_refresh(d):d['markers']['smtp']=_smtp_kind(d)!='none'


def new_fetch_diagnostic():
    d=_smtp_v2_new_fetch_diagnostic();d.update(version=3,smtp=_smtp_blank());return d


def retry_diagnostic_allowed(d):
    if type(d) is not dict:return False
    if d.get('version')!=3:return _smtp_v2_retry_allowed(d)
    try:
        need(set(d)==set(new_fetch_diagnostic()),'diagnostic_shape');_smtp_valid(d['smtp'])
        if _smtp_kind(d)!='none':return False
        legacy={k:v for k,v in d.items() if k!='smtp'};legacy['version']=2
        return _smtp_v2_retry_allowed(legacy)
    except (ValueError,KeyError,TypeError):return False


def history_summary(result,count):
    # The old summary remains authoritative for auth/TLS/POP/history/interrupt failures.
    copied=dict(result);d=result.get('diagnostic',{});neutral=dict(d);flags=dict(d.get('markers',{}));flags['smtp']=False
    neutral['markers']=flags;copied['diagnostic']=neutral
    answer=_smtp_prior_history_summary(copied,count);code=result.get('native_exit')
    if answer['detail_code'] in ('history_unverified','result_unverified','interrupted','tls_failed','auth_failed'):return answer
    if d.get('version')==3:
        need(set(d)==set(new_fetch_diagnostic()),'diagnostic_shape');reason=_smtp_kind(d)
        if reason!='none' and type(code) is int and code in (0,1,2,10,13):
            answer['detail_code']=reason
            if code in (0,1,13) and result.get('status')=='ok' and result.get('database_result_verified') is True:answer['outcome']='warning'
        elif reason=='none' and answer['outcome'] in ('success','no_mail','limit_reached') and (d.get('stdout_truncated') or d.get('stderr_truncated')):
            answer.update(outcome='warning',detail_code='diagnostic_incomplete')
    elif d.get('markers',{}).get('smtp') and answer['outcome'] in ('success','no_mail','limit_reached'):
        answer.update(outcome='warning',detail_code='smtp_legacy_unverified')
    return answer


def classify_fetch_stderr(raw, diagnostic, stream='stderr'):
    need(stream in ('stdout', 'stderr') and len(raw) <= 32768, 'diagnostic_shape')
    diagnostic[stream + '_inspected_bytes'] = len(raw)
    phrases = {'connection_refused': (b'connection refused',), 'connection_reset': (b'connection reset',), 'connection_closed': (b'connection closed', b'unexpected eof', b'end of file'), 'timeout': (b'timed out', b'timeout after'), 'tls': (b'ssl connection failed', b'ssl handshake', b'tls handshake'), 'certificate': (b'certificate verification', b'certificate verify failed', b'certificate validation', b'certificate mismatch'), 'authentication': (b'authorization failure', b'authentication failed', b'authentication failure'), 'smtp': (), 'protocol': (b'protocol error',), 'syntax': (b'syntax error',)}
    lower = bytes(raw).lower()
    scrub = re.sub(b'<[^>\\r\\n]*>|https?://\\S+|[^\\s<>]+@[^\\s<>]+', b' ', lower)
    for k, values in phrases.items():
        diagnostic['markers'][k] |= any((v in scrub for v in values))
    for line in bytes(raw).splitlines():
        text = line.decode('utf-8', 'replace')
        recognized = False
        m = re.fullmatch('(?:fetchmail: )?timeout after ([0-9]{1,4}) seconds( waiting to connect to server [^\\r\\n]{1,512}| waiting for server [^\\r\\n]{1,512}| waiting for SMTP| waiting for listener to respond)?\\.', text)
        if m and 1 <= int(m[1]) <= 900:
            tail = m[2] or ''
            phase = 'connect' if tail.startswith(' waiting to connect') else 'server' if tail.startswith(' waiting for server') else 'smtp' if tail else 'unknown'
            diagnostic.update(detail_code='socket_connect_timeout' if phase == 'connect' else 'socket_server_timeout' if phase == 'server' else 'smtp_timeout' if phase == 'smtp' else 'timeout', transport_phase=phase, timeout_seconds=int(m[1]))
            recognized = True
        errs = {'Connection refused': ('ECONNREFUSED', 'socket_refused'), 'Connection reset by peer': ('ECONNRESET', 'socket_reset'), 'Network is unreachable': ('ENETUNREACH', 'network_unreachable'), 'No route to host': ('EHOSTUNREACH', 'host_unreachable'), 'Temporary failure in name resolution': ('EAI_AGAIN', 'dns_temporary')}
        m = re.fullmatch('(?:fetchmail: )?POP3 connection to [A-Za-z0-9.:-]{1,253} failed: (.{1,100})', text)
        if m and m[1] in errs:
            symbol, detail = errs[m[1]]
            diagnostic.update(detail_code=detail, reported_errno_symbol=symbol, transport_phase='connect')
            recognized = True
        if re.fullmatch('(?:fetchmail: )?socket error while fetching from [^\\r\\n]{1,1024}', text):
            if diagnostic['detail_code'] == 'none':
                diagnostic['detail_code'] = 'socket_unclassified'
            if ' and delivering to SMTP host ' in text:
                diagnostic['transport_phase'] = 'smtp'
            recognized = True
        if re.match('(?:fetchmail: )?(?:Write error on fetchids file|Cannot rename fetchids file|Cannot open fetchids file|Error writing to fetchids file) ', text):
            diagnostic.update(detail_code='uidl_write_failed')
            recognized = True
        if _smtp_line(text, diagnostic):
            recognized = True
        if not recognized and line.strip():
            diagnostic['unclassified_records'] = min(1000, diagnostic['unclassified_records'] + 1)
    _smtp_refresh(diagnostic)


def main():
    result={'status':'fail','stage':'preconditions','account_id':'1','retrieval_attempted':False,
            'automatic_retry':False,'source_delete':False,'service_action':False,'raw_error_output':False}
    started=False;lock=None;row=None;run_id=None;history_before=None;saved=None;user=None;retry_streak=0;retry_binding=None
    try:
        import fcntl
        import pwd
        user=pwd.getpwnam('mailpop')
        need(len(sys.argv)==2 and sys.argv[1]=='--account1' and os.getuid()==os.geteuid()==user.pw_uid
             and os.getgid()==os.getegid()==user.pw_gid and user.pw_uid!=0,'mailpop_caller')
        for path in (STATE,STATE/'accounts',ACCOUNT,STATE/'locks'):
            info=path.lstat();need(stat.S_ISDIR(info.st_mode) and not path.is_symlink() and info.st_uid==user.pw_uid
                and info.st_gid==user.pw_gid and stat.S_IMODE(info.st_mode)==0o700,'state_directory')
        for path in (BASE,Path('/etc/mail-pop')):
            info=path.lstat();need(stat.S_ISDIR(info.st_mode) and not path.is_symlink() and info.st_uid==0
                and info.st_gid==user.pw_gid and stat.S_IMODE(info.st_mode)==0o750,'runtime_directory')
        lock=os.open(STATE/'locks/account-1.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        info=os.fstat(lock);need(stat.S_ISREG(info.st_mode) and info.st_uid==user.pw_uid and info.st_gid==user.pw_gid
            and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600,'lock_metadata')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        run_id=bridge('--history-start')['run_id']
        need(isinstance(run_id,str) and re.fullmatch(r'[1-9][0-9]{0,19}',run_id),'run_id')
        result['stage']='policy';_mail_pop_compat_load()['worker_check']()
        result['stage']='policy';row=bridge('--metadata')['source'];source_allowed(row)
        previous=None
        if os.path.lexists(ACCOUNT/'attempt.json'):
            previous_raw=read_file(ACCOUNT/'attempt.json',user.pw_uid,user.pw_gid,0o600,4096)
            previous=json.loads(previous_raw)
            decision=retry_previous(previous,previous_raw,user,row);retry_streak=decision['streak']
            if decision['wait']:
                result.update(status='ok',result='retry_wait',retry=decision,scheduled_retry_allowed=True)
                return 0
            need(type(previous.get('started_at')) is int and time.time()-previous['started_at']>=row['seconds'],'poll_not_due')
        result['stage']='binding'
        saved=json.loads(read_file(ACCOUNT/'binding.json',0,user.pw_gid,0o640,4096))
        init=json.loads(read_file(ACCOUNT/'initialization.json',0,user.pw_gid,0o640,65536))
        ids=read_file(ACCOUNT/'fetchids',user.pw_uid,user.pw_gid,0o600,128*1024*1024)
        need(init.get('complete') is True and init.get('source_id')=='1' and init.get('seeded_uidls')==45322,'initialization_binding')
        if previous is None:
            need(len(ids)==init['fetchids']['bytes'] and hashlib.sha256(ids).hexdigest()==init['fetchids']['sha256'],'first_history_changed')
        history_before=history_ids(ids,saved);del ids
        raw=read_file(BASE/'fetchmail_history.py',0,user.pw_gid,0o640,8192)
        need(len(raw)==2750 and hashlib.sha256(raw).hexdigest()=='d624d6d53122a77d37cbccaf2c5c774384c0e3d6bd6233838c199684d7363a5c','history_code_pin')
        spec=importlib.util.spec_from_file_location('fixed_history',BASE/'fetchmail_history.py');history=importlib.util.module_from_spec(spec);spec.loader.exec_module(history)
        ip=endpoint(saved,row,history)
        retry_binding=retry_snapshot(user)
        started_at=int(time.time());attempt={'account_id':'1','phase':'started','started_at':started_at}
        record(attempt);started=True
        result['stage']='private_config';reply=bridge('--config',{'source':row,'queryname':ip})
        need(reply.get('argv')==FETCH and isinstance(reply.get('config'),str) and len(reply['config'].encode())<=8192,'fetchmail_argv')
        config=reply['config'].encode();del reply
        result['stage']='native_fetch';result['retrieval_attempted']=True
        # No shell, plaintext file, verbose/protocol logs, fetchall, DELE, MDA or daemon.
        diagnostic=new_fetch_diagnostic();result['diagnostic']=diagnostic
        try:native=diagnostic_fetch(config,diagnostic)
        finally:
            del config
            attempt['diagnostic']=diagnostic
            record(attempt)
        need(0<=native.returncode<=255,'native_exit_unverified')
        result['native_exit']=native.returncode
        result['stage']='result_update';done=bridge('--result',{'source':row,'exit':native.returncode})
        need(done.get('result') in ('retrieved','no_mail','limit_reached','unverified'),'result_shape')
        retry_complete(attempt,result,user,history_before,saved,row,retry_streak,retry_binding)
        attempt.update(phase='complete',native_exit=native.returncode,database_result_verified=True)
        result.update(status='ok' if native.returncode in (0,1,13) else 'fail',stage='complete',result=done['result'],database_result_verified=True)
    except BaseException as error:
        result['error_class']=type(error).__name__
        result['failure']=retry_error(error,result['stage'])
        if result['failure']['reason'] in RETRY_REASONS:result['history_reason']=result['failure']['reason']
        if type(error) is ValueError and str(error)=='source_not_allowed':result['history_reason']='source_not_allowed'
        if started:
            # Leave started marker: native submission/ID-state uncertainty never authorizes automatic retry.
            result['reservation_retained']=True
    finally:
        if run_id is not None:
            try:
                finish_run_history(run_id,result,history_before,saved,user)
                result['run_history_recorded']=True
                if started and attempt.get('phase')=='complete':record(attempt)
            except Exception as history_error:
                result.update(status='fail',run_history_recorded=False,reservation_retained=started)
                result['history_failure']=retry_error(history_error,'result_update')
        if lock is not None:os.close(lock)
    print(json.dumps(result,sort_keys=True));return 0 if result['status']=='ok' else 1

if __name__=='__main__':sys.exit(main())
