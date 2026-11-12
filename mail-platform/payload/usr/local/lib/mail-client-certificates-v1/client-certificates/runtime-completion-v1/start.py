"""Only explicit production/private-validation actor entry; no apply or CA creation."""
from pathlib import Path
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
def main():
    import signal
    import threading
    from boot import load,notify
    from safety import Audit,need,shape
    context=application=None;audit=Audit();phase='startup';stop=threading.Event()
    try:
        need(len(sys.argv)==4 and sys.argv[2]=='--config','actor_entry_arguments');actor=sys.argv[1]
        config,release,manifest,runtime=load(actor,sys.argv[3])
        from assembly import Context
        context=Context(config,release,manifest,runtime,audit)
        phase='actor_assembly'
        if actor=='gate':
            from gate_runtime import Runtime
            application=Runtime(context)
        else:
            import assembly
            application=getattr(assembly,actor)(context)
        signal.signal(signal.SIGTERM,lambda *_:stop.set());signal.signal(signal.SIGINT,lambda *_:stop.set())
        notify('READY=1\nSTATUS=actor startup guards and IPC ready')
        while not stop.wait(1):
            runtime.require_armed()
            need(all(thread.is_alive()for thread in context.threads),'actor_listener_thread_failed')
            if actor=='issuer':application['broker'].expire()
            if actor=='owner':application['owner_lifecycle_tick']()
            if actor=='gate':application.require_healthy();application.publish_health()
        return 0
    except BaseException as error:
        audit.failure(error,phase);return 1
    finally:
        if application is not None and hasattr(application,'close'):application.close()
        if context is not None:context.close()
if __name__=='__main__':raise SystemExit(main())
