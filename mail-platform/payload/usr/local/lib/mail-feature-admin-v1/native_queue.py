"""Fixed commands with bounded streams/deadline. No shell, postcat, delete or flush."""
import os,selectors,signal,subprocess,time
from queue_admin import ACTIONS,identity,need

class NativeQueue:
    def __init__(self,on_failure=None):self.on_failure=on_failure;self.deadline=None
    def __call__(self,args):
        allowed=args==('/usr/sbin/postqueue','-j')
        if len(args)==3:
            allowed=tuple(args[:2]) in ACTIONS.values()
            if allowed:identity(args[2])
        need(allowed,'native_command_not_allowed')
        buffers=[bytearray(),bytearray()];process=None;timed_out=overflow=False;code=None;failure=None
        try:
            process=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'},start_new_session=True)
            with selectors.DefaultSelector() as events:
                events.register(process.stdout,selectors.EVENT_READ,0);events.register(process.stderr,selectors.EVENT_READ,1)
                deadline=min(time.monotonic()+15,self.deadline) if self.deadline is not None else time.monotonic()+15
                while events.get_map():
                    if time.monotonic()>deadline:timed_out=True;break
                    for key,_ in events.select(.05):
                        raw=os.read(key.fileobj.fileno(),8192)
                        if not raw:events.unregister(key.fileobj);continue
                        remaining=(8*1024*1024 if key.data==0 else 65536)-len(buffers[key.data]);buffers[key.data].extend(raw[:remaining])
                        if len(raw)>remaining:overflow=True;break
                    if overflow:break
            if timed_out or overflow:os.killpg(process.pid,signal.SIGKILL)
            try:code=process.wait(timeout=3)
            except subprocess.TimeoutExpired:timed_out=True
        except Exception as error:
            failure=error
        finally:
            if process is not None:
                if process.poll()is None:os.killpg(process.pid,signal.SIGKILL);code=process.wait(timeout=3)
                process.stdout.close();process.stderr.close()
        if timed_out or overflow or code!=0 or failure is not None:
            if self.on_failure:self.on_failure({'exit':code,'timeout':timed_out,'overflow':overflow,'exception_class':type(failure).__name__ if failure is not None else None},bytes(buffers[0]),bytes(buffers[1]))
        if failure is not None:raise failure
        need(not timed_out and not overflow,'native_capture_failed')
        return code,bytes(buffers[0]),bytes(buffers[1])
