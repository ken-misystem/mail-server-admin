"""Bounded fixed compiler invocation; all original output is privately retained."""
import os,selectors,signal,subprocess,time
from forwarding import need

def compile_sieve(config,directory,capture,seconds=30):
    need(type(seconds)is int and 1<=seconds<=60,'compiler_deadline')
    argv=['/usr/bin/sievec','-c',str(config),str(directory)];buffers=[bytearray(),bytearray()];child=None;started=time.monotonic()
    result={'stage':'sieve_compile','exit':None,'timeout':False,'overflow':False,'exception_class':None}
    try:
        child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
        with selectors.DefaultSelector()as events:
            for index,stream in enumerate((child.stdout,child.stderr)):events.register(stream,selectors.EVENT_READ,index)
            while events.get_map():
                if time.monotonic()-started>seconds:result['timeout']=True;break
                for key,_ in events.select(.05):
                    raw=os.read(key.fileobj.fileno(),8192)
                    if not raw:events.unregister(key.fileobj);continue
                    remaining=1048576-sum(map(len,buffers));buffers[key.data].extend(raw[:max(0,remaining)])
                    if len(raw)>remaining:result['overflow']=True;break
                if result['overflow']:break
        if result['timeout']or result['overflow']:os.killpg(child.pid,signal.SIGKILL)
        result['exit']=child.wait(timeout=3)
    except BaseException as error:
        result['exception_class']=type(error).__name__;raise
    finally:
        if child is not None:
            if child.poll()is None:os.killpg(child.pid,signal.SIGKILL);result['exit']=child.wait(timeout=3)
            child.stdout.close();child.stderr.close()
        result.update(seconds=time.monotonic()-started,stdout_bytes=len(buffers[0]),stderr_bytes=len(buffers[1]))
        capture(result,bytes(buffers[0]),bytes(buffers[1]))
    need(result['exit']==0 and not result['timeout']and not result['overflow']and not buffers[0]and not buffers[1],'forward_native_compile_failed')
    return result
