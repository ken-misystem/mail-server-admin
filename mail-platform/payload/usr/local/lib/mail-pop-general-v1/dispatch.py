"""Root timer dispatcher: enumerate allowed IDs, start only numeric template units."""
import json,os,re,stat,subprocess,sys,time
from pathlib import Path
BASE=Path('/usr/local/lib/mail-pop-general-v1')
STATE=Path('/var/lib/mail-pop')
PHP=['/usr/bin/php','-d','display_errors=0','-d','log_errors=0','-d','auto_prepend_file=',
     '-d','auto_append_file=','-d','opcache.enable_cli=0']
ENV={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C','LC_ALL':'C'}


def need(v,reason):
    if not v:raise ValueError(reason)


def account(value):
    need(type(value) is str and re.fullmatch('[1-9][0-9]{0,19}',value)
         and int(value)<=18446744073709551615,'source_id');return value


def due(previous,seconds,now):
    need(type(seconds) is int and 60<=seconds<=86400,'poll_interval')
    if previous is None:return True
    need(type(previous) is dict and type(previous.get('started_at')) is int and 0<previous['started_at']<=now,'attempt_shape')
    if previous.get('phase')!='complete' or previous.get('database_result_verified') is not True:return False
    code=previous.get('native_exit');need(type(code) is int and 0<=code<=255,'attempt_exit')
    if code not in (0,1,2,13):return False
    when=previous['started_at']+seconds
    if code==2:
        context=previous.get('retry_context')
        if type(context) is not dict:return False # Legacy native2 still requires its reviewed bootstrap.
        completed=context.get('completed_at');delay=context.get('delay_seconds')
        need(type(completed) is int and 0<completed<=now and type(delay) is int and 300<=delay<=86400,'retry_context')
        when=max(when,completed+delay)
    return now>=when


def dispatch(rows,active,attempt,launch,now,capacity=2):
    need(type(rows) is list and len(rows)<=1000 and type(active) is set and 1<=capacity<=8,'dispatch_bounds')
    seen=set();ready=[];blocked=0
    for row in rows:
        need(type(row) is dict and set(row)=={'id','seconds'},'source_shape');id=account(row['id'])
        need(id not in seen,'duplicate_source');seen.add(id)
        if id in active:continue
        previous=attempt(id)
        if previous is not None:need(previous.get('account_id')==id,'attempt_identity')
        if due(previous,row['seconds'],now):ready.append((0 if previous is None else previous['started_at'],int(id),id))
        else:blocked+=1
    selected=sorted(ready)[:max(0,capacity-len(active))]
    for _,_,id in selected:launch('mail-pop-source@'+id+'.service')
    return {'eligible_sources':len(rows),'started':len(selected),'active':len(active),'waiting_or_blocked':blocked}


def main():
    phase='identity'
    try:
        import pwd
        need(sys.argv[1:]==['--dispatch'] and os.geteuid()==0 and sys.flags.isolated,'execution_context')
        user=pwd.getpwnam('mailpop')
        def read(argv):
            r=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,env=ENV,cwd='/')
            need(r.returncode==0 and len(r.stdout)<=131072 and not r.stderr,'native_read');return r.stdout
        phase='sources'
        rows=json.loads(read(['/usr/sbin/runuser','-u','mailpop','--',*PHP,str(BASE/'bridge.php'),'--sources','1']))
        need(rows.get('status')=='ok','source_read')
        phase='active_units';active=set()
        raw=read(['/usr/bin/systemctl','list-units','--all','--type=service','--state=active,activating','--plain','--no-legend','mail-pop-source@*.service'])
        for line in raw.decode().splitlines():
            m=re.match(r'^mail-pop-source@([1-9][0-9]{0,19})\.service\s',line)
            need(m is not None,'unit_shape');active.add(account(m[1]))
        def attempt(id):
            path=STATE/'accounts'/account(id)/'attempt.json'
            directory=path.parent
            if not os.path.lexists(directory):return None
            m=directory.lstat();need(stat.S_ISDIR(m.st_mode) and m.st_uid==user.pw_uid and stat.S_IMODE(m.st_mode)==0o700,'state_directory')
            if not os.path.lexists(path):return None
            with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW),'rb') as f:
                m=os.fstat(f.fileno());need(stat.S_ISREG(m.st_mode) and m.st_uid==user.pw_uid and m.st_nlink==1 and stat.S_IMODE(m.st_mode)==0o600 and m.st_size<=4096,'attempt_boundary')
                return json.loads(f.read(4097))
        def launch(name):read(['/usr/bin/systemctl','start','--no-block',name])
        phase='dispatch';facts=dispatch(rows['sources'],active,attempt,launch,int(time.time()))
        print(json.dumps({'status':'ok','phase':'complete',**facts,'raw_error_output':False}));return 0
    except Exception as error:
        tb=error.__traceback__;frames=[]
        while tb:frames.append({'function':tb.tb_frame.f_code.co_name,'line':tb.tb_lineno});tb=tb.tb_next
        print(json.dumps({'status':'fail','phase':phase,'error_class':type(error).__name__,
            'errno':getattr(error,'errno',None),'frames':frames[-6:],'raw_error_output':False}));return 1


if __name__=='__main__':sys.exit(main())
