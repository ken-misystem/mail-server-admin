"""Only fixed native configuration queries/validation and the named Rspamd reload."""
import os,selectors,signal,subprocess,time
from forwarding import need

COMMANDS={
 'settings':['/usr/bin/rspamadm','configdump','settings','-j'],
 'antivirus':['/usr/bin/rspamadm','configdump','antivirus','-j'],
 'dkim':['/usr/bin/rspamadm','configdump','dkim_signing','-j'],
 'mime_types':['/usr/bin/rspamadm','configdump','mime_types','-j'],
 'rspamd_check':['/usr/bin/rspamadm','configtest'],
 'rspamd_reload':['/usr/bin/systemctl','reload','rspamd.service'],
 'relayhost':['/usr/sbin/postconf','-h','relayhost'],
 'relay_maps':['/usr/sbin/postconf','-h','sender_dependent_relayhost_maps'],
 'sasl_maps':['/usr/sbin/postconf','-h','smtp_sasl_password_maps'],
 'clamd_state':['/usr/bin/systemctl','show','--all','--no-pager','--property=LoadState,ActiveState','clamav-daemon.service'],
}
def run(name,capture):
    need(name in COMMANDS,'configuration_command_scope');argv=COMMANDS[name];buffers=[bytearray(),bytearray()];child=None;start=time.monotonic();row={'command':name,'exit':None,'timeout':False,'overflow':False,'exception_class':None}
    try:
        child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        with selectors.DefaultSelector()as events:
            for index,stream in enumerate((child.stdout,child.stderr)):events.register(stream,selectors.EVENT_READ,index)
            while events.get_map():
                if time.monotonic()-start>20:row['timeout']=True;break
                for key,_ in events.select(.05):
                    raw=os.read(key.fileobj.fileno(),8192)
                    if not raw:events.unregister(key.fileobj);continue
                    remaining=2097152-sum(map(len,buffers));buffers[key.data].extend(raw[:max(0,remaining)])
                    if len(raw)>remaining:row['overflow']=True;break
                if row['overflow']:break
        if row['timeout']or row['overflow']:os.killpg(child.pid,signal.SIGKILL)
        row['exit']=child.wait(timeout=3)
    except BaseException as error:row['exception_class']=type(error).__name__;raise
    finally:
        if child is not None:
            if child.poll()is None:os.killpg(child.pid,signal.SIGKILL);row['exit']=child.wait(timeout=3)
            child.stdout.close();child.stderr.close()
        row.update(stdout_bytes=len(buffers[0]),stderr_bytes=len(buffers[1]),seconds=time.monotonic()-start);capture(row,bytes(buffers[0]),bytes(buffers[1]))
    need(row['exit']==0 and not row['timeout']and not row['overflow'],'configuration_native_failed')
    # Configtest normally prints a success sentence; callers classify it explicitly.
    need(not buffers[1],'configuration_native_stderr');return bytes(buffers[0])
