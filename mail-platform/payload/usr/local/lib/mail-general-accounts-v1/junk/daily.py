"""Candidate daily sender: per-owner reviewed ledger/counter/SMTP, opt-in twice."""
from datetime import datetime,timezone
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import types

BASE=Path('/usr/local/lib/mail-general-accounts-v1/junk')
STATE=Path('/var/lib/mail-junk-digest-general-v1')
PHP=['/usr/bin/php','-d','display_errors=0','-d','log_errors=0','-d','auto_prepend_file=',
     '-d','auto_append_file=','-d','opcache.enable_cli=0']
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'}


def need(value,reason):
    if not value:raise ValueError(reason)


def load(name,manifest):
    path=BASE/name;m=path.lstat()
    need(stat.S_ISREG(m.st_mode) and m.st_uid==0 and not m.st_mode&0o022 and m.st_nlink==1,'code_boundary')
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as f:raw=f.read(65537)
    need([len(raw),hashlib.sha256(raw).hexdigest()]==manifest[name],'code_pin')
    value=types.ModuleType('general_daily_'+name.replace('.','_'));value.__file__=str(path)
    exec(compile(raw,str(path),'exec'),value.__dict__);return value


def recipient(value):
    need(type(value) is dict and set(value)=={'roundcube_id','owner_id','email','login'},'recipient_shape')
    for key in ('roundcube_id','owner_id'):
        need(type(value[key]) is str and re.fullmatch('[1-9][0-9]{0,19}',value[key])
             and int(value[key])<=18446744073709551615,'recipient_id')
    for key in ('email','login'):
        email=value[key];need(type(email) is str and email==email.lower() and 3<=len(email)<=254
            and email.count('@')==1 and not email.startswith('@') and not email.endswith('@')
            and all(33<=ord(c)<=126 for c in email),'recipient_address')
    return value


def preference(mode,value=None):
    need(mode in ('--list','--eligible'),'preference_mode')
    r=subprocess.run(PHP+[str(BASE/'preferences.php'),mode],input=None if value is None else json.dumps(value).encode(),
        stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30,env=ENV,cwd='/')
    need(r.returncode==0 and len(r.stdout)<=512*1024,'preference_read')
    result=json.loads(r.stdout);need(result.get('status')=='ok','preference_read');return result


def message(account,sender,snapshot,rendered,now):
    digest=hashlib.sha256((account+'\0'+snapshot['day']).encode()).hexdigest()
    m=EmailMessage(policy=SMTP);m['From']=sender;m['To']=account;m['Subject']=rendered['subject']
    m['Date']=format_datetime(now.astimezone(timezone.utc));m['Message-ID']='<junk-digest-'+digest+'@mi-sys.jp>'
    m.set_content(rendered['body']+'この日報は非原子的な取得時点の件数です。\n',charset='utf-8');return m.as_bytes()


def execute_owner(item,pilot,counter,renderer,eligible,clock,transport=None):
    item=recipient(item)
    if not eligible(item):return {'status':'skipped','mail_submission':False,'reason':'opted_out'}
    # Isolated module objects per recipient; never mutate shared globals concurrently.
    pilot.ACCOUNT=item['email'];pilot.STATE=STATE/item['owner_id'];counter.ACCOUNT=item['email']
    pilot.message_bytes=lambda snapshot,rendered,now:message(item['email'],pilot.SENDER,snapshot,rendered,now)
    if not os.path.lexists(pilot.STATE):pilot.initialize_state()
    with pilot.ledger() as db:
        try:
            return pilot.execute(db,eligibility=lambda:eligible(item),collect=counter.collect,
                render=renderer.render_pilot_message,window=counter.window,clock=clock,
                transport=pilot.send_once if transport is None else transport)
        except Exception as error:
            error.native_diagnostic = getattr(counter, 'native_reader', None)
            raise


def main():
    result={'status':'fail','phase':'identity','accepted':0,'skipped':0,'failed':0,'failures':[],
            'automatic_retry':False,'raw_error_output':False}
    try:
        need(sys.argv[1:]==['--run-daily'] and os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode,'execution_context')
        os.umask(0o077)
        for p in (BASE,STATE):
            m=p.lstat();need(stat.S_ISDIR(m.st_mode) and m.st_uid==0 and not m.st_mode&0o077,'private_directory')
        # Installation must bind this manifest and every source before timer activation.
        manifest=json.loads((BASE/'manifest.json').read_text())
        required={'ken_digest_pilot_v2.py','junk_previous_day_probe_v2.py','pilot_message.py',
            'preferences.php','Recipients.php','PilotPreferenceDecoder.php','native_read.py'}
        need(set(manifest)==required,'manifest_shape')
        for name in required:
            p=BASE/name;m=p.lstat();need(stat.S_ISREG(m.st_mode) and m.st_uid==0 and not m.st_mode&0o022 and m.st_nlink==1,'code_boundary')
            raw=p.read_bytes();need([len(raw),hashlib.sha256(raw).hexdigest()]==manifest[name],'code_pin')
        probe=load('junk_previous_day_probe_v2.py',manifest);probe.window(datetime.now(probe.JST))
        result['phase']='eligibility';items=preference('--list')['recipients']
        need(type(items) is list and len(items)<=1000,'recipient_bound')
        owners=set()
        for item in items:
            item=recipient(item);need(item['owner_id'] not in owners,'duplicate_recipient');owners.add(item['owner_id'])
        for item in items:
            result['phase']='owner_daily'
            try:
                pilot=load('ken_digest_pilot_v2.py',manifest);counter=load('junk_previous_day_probe_v2.py',manifest)
                renderer=load('pilot_message.py',manifest)
                native=load('native_read.py',manifest);reader=native.Reader(item['email'])
                original_collect=counter.collect
                counter.native_reader=reader
                counter.collect=lambda:original_collect(read=reader)
                clock=lambda:datetime.now(counter.JST);counter.window(clock())
                value=execute_owner(item,pilot,counter,renderer,lambda v:preference('--eligible',v).get('eligible') is True,clock)
                if value['status']=='skipped':result['skipped']+=1
                elif value['status']=='ok':result['accepted']+=1
                else:result['failed']+=1
            except Exception as error:
                result['failed']+=1
                if len(result['failures'])<10:result['failures'].append({'owner_id':item['owner_id'],**safe_failure(error)})
        result.update(status='ok' if result['failed']==0 else 'fail',phase='complete')
    except Exception as error:result['failures'].append(safe_failure(error))
    print(json.dumps(result,sort_keys=True));return 0 if result['status']=='ok' else 1


def safe_failure(error):
    frames=[];tb=error.__traceback__
    while tb:
        frames.append({'function':tb.tb_frame.f_code.co_name,'line':tb.tb_lineno});tb=tb.tb_next
    allowed={'recipient_shape','recipient_id','recipient_address','code_boundary','code_pin','manifest_shape',
        'private_directory','preference_read','recipient_bound','duplicate_recipient','execution_context',
        'collect_mailbox_unverified','collect_status_unverified','collect_search_unverified','collect_snapshot_unstable',
        'collect_collection_failed','source_binding','ledger_mode','ledger_invalid','ledger_parent','ledger_directory',
        'ledger_inventory','ledger_file','ledger_lock','ledger_transition','snapshot_window','send_window','invalid_outcome',
        'outside_daily_window'}
    reason=str(error) if isinstance(error,ValueError) and str(error) in allowed else 'runtime_unverified'
    reader=getattr(error,'native_diagnostic',None)
    return {'error_class':type(error).__name__,'reason':reason,'errno':getattr(error,'errno',None),'frames':frames[-6:],
            'native_diagnostic':None if reader is None else reader.last}


if __name__=='__main__':sys.exit(main())
