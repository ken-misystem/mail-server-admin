"""Fixed existing Rspamd relay service. No source message/error logging."""
from pathlib import Path
import sys
sys.dont_write_bytecode=True
sys.path[:0]=[str(Path(__file__).resolve().parent),str(Path(__file__).resolve().parents[1]/'final-integration-v1'),str(Path(__file__).resolve().parents[1]/'production-runtime-v1')]
import json
import os
import signal
import threading
import time
from safety import Audit,held,need
def main():
    from boot import notify
    from server import Listener
    from milter_ipc import MilterIPC
    config=json.loads(held('/etc/mail-client-certificates-v1/milter.json'));need(os.geteuid()==config['postfix_uid']and os.getegid()==config['postfix_gid'],'milter_actor_identity')
    class Runtime:
        def require_armed(self):
            need(os.geteuid()==config['postfix_uid']and os.getegid()==config['postfix_gid'],'milter_actor_changed')
    def ready():
        # Guard is a fresh root-owned observation, no invented TCP peer identity.
        value=json.loads(held('/run/mail-client-certificates-v1/coordination/ready.json',8192))
        need(value['valid']is True and 0<=time.time()-value['observed_at']<=5,'milter_readiness_stale')
    stop=threading.Event();signal.signal(signal.SIGTERM,lambda *_:stop.set())
    handler=MilterIPC(Runtime(),config['postfix_uid'],config['postfix_gid'],ready,Audit())
    listener=Listener('/run/mail-client-certificates-v1/milter/milter.sock',config['postfix_gid'],handler.one)
    thread=threading.Thread(target=listener.loop,daemon=True);thread.start();notify('READY=1\nSTATUS=fixed Milter IPC ready')
    try:
        while not stop.wait(1):need(thread.is_alive(),'milter_listener_failed')
    finally:listener.close();thread.join(3)
    return 0
if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as e:Audit().failure(e,'milter_startup');raise SystemExit(1)
