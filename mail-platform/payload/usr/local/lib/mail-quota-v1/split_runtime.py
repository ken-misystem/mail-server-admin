"""One persistent collector, one asynchronous initializer, one shared service resource limit."""
import base64
import copy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import signal
import stat
import threading
import time
import traceback
import runtime as legacy
from collector_core import inventory
from scale_core import user_list,parse_batch,combine,need
import split_core as core


@dataclass(frozen=True)
class Settings:
    root:Path=legacy.ROOT
    state:Path=legacy.STATE
    main_conf:str|None=None
    backend_conf:str=legacy.BACKEND
    inventory_argv:tuple=tuple(legacy.PHP_READER)


def private_bytes(path,raw):
    parent=path.parent;s=os.lstat(parent)
    need(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o700,'private_list_parent')
    try:
        s=os.lstat(path);need(stat.S_ISREG(s.st_mode)and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600,'private_list_existing')
    except FileNotFoundError:pass
    tmp=parent/('.'+path.name+'.'+str(os.getpid())+'.'+str(time.time_ns()))
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
    os.replace(tmp,path)


def failure_document(exc,phase):
    value={'safe':legacy.failure(exc,phase),'traceback_private':''.join(traceback.format_exception(type(exc),exc,exc.__traceback__))}
    if isinstance(exc,legacy.NativeFailure):
        value.update(stdout_base64=base64.b64encode(exc.stdout).decode(),stderr_base64=base64.b64encode(exc.stderr).decode())
    return value


class Collector:
    def __init__(self,settings=Settings(),*,native=legacy.native,wall=time.time,clock=time.monotonic,executor=None):
        self.s=settings;self.native=native;self.wall=wall;self.clock=clock
        self.pool=executor or ThreadPoolExecutor(max_workers=1,thread_name_prefix='quota-initializer')
        self.future=None;self.completed=None;self.running_job=None

    def argv(self,instance,action):
        conf=self.s.main_conf if instance=='main'else self.s.backend_conf
        return ['/usr/bin/doveadm',*(['-c',conf]if conf else[]),*action]

    def config_args(self,instance):
        conf=self.s.main_conf if instance=='main'else self.s.backend_conf
        return ['/usr/bin/doveconf',*(['-c',conf]if conf else[]),'-n']

    def initialize(self,job):
        """Private readiness proof only. Never writes snapshot, applied state or observation timestamps."""
        proof={**copy.deepcopy(job),'ready':[],'failures':[],'native':[],'finished_at':None}
        deadline=self.clock()+core.COLD_BUDGET
        raw_errors=[]
        def call(label,argv,limit=131072):
            remaining=deadline-self.clock();need(remaining>0,'initialization_deadline')
            begin=self.clock()
            try:
                out=self.native(label,['/usr/bin/python3','-I','-B',str(self.s.root/'cold_exec.py'),*argv],min(15,remaining),limit=limit)
                proof['native'].append({'label':label,'exit':0,'stderr_bytes':0,'elapsed_ms':round((self.clock()-begin)*1000),'stdout_sha256':legacy.digest(out)})
                return out
            except Exception as exc:
                proof['native'].append(legacy.failure(exc,label));raise
        try:
            selected=[]
            for row in job['rows']:
                try:
                    if job['previous'][row['id']]!=core.binding(row):
                        for instance in ('main','backend'):call('prepare_reconnect_'+instance,self.argv(instance,['kick',row['email']]),8192)
                    selected.append(row)
                except Exception as exc:raw_errors.append(failure_document(exc,'prepare_reconnect'))
            if selected:
                path=self.s.state/'private/bootstrap-users.txt';private_bytes(path,user_list(selected))
                observations={};outputs={}
                for instance in ('main','backend'):
                    out=call('prepare_quota_'+instance,self.argv(instance,['-f','tab','quota','get','-F',str(path)]))
                    outputs[instance]=out
                    try:observations[instance]=parse_batch(out,selected)
                    except Exception as exc:
                        raw_errors.append({'parser_exit':0,'raw_output_base64':base64.b64encode(out).decode(),**failure_document(exc,'prepare_parser')});raise
                joined=combine(observations['main'],observations['backend']);proof['ready']=sorted(joined['ok'],key=int)
                if joined['errors']:
                    raw_errors.append({'safe':{'phase':'preparation_rows','class':'ValueError','reason':'initialization_rows_unverified'},
                        'actual_exit':0,'outputs_base64':{k:base64.b64encode(v).decode()for k,v in outputs.items()},'row_errors':joined['errors']})
        except Exception as exc:raw_errors.append(failure_document(exc,'initialization'))
        finally:
            proof['finished_at']=int(self.wall());proof['failures']=[x['safe']for x in raw_errors]
            # Preserve raw failure reasons even when service shutdown interrupts the normal warm loop.
            legacy.atomic(self.s.state/'private/bootstrap-last.json',{'proof':proof,'raw_private':raw_errors})
            if raw_errors:legacy.atomic(self.s.state/'private/bootstrap-last-failure.json',{'proof':proof,'raw_private':raw_errors})
        return proof

    def cycle(self):
        started=self.clock();deadline=started+core.WARM_BUDGET;generation='0'*64;phase='configuration';native_rows=[];failures=[]
        def call(label,args,maximum=1,limit=2097152):
            remaining=deadline-self.clock();need(remaining>0,'warm_deadline');begin=self.clock()
            try:
                raw=self.native(label,args,min(maximum,remaining),limit=limit)
                native_rows.append({'label':label,'exit':0,'stderr_bytes':0,'elapsed_ms':round((self.clock()-begin)*1000),'stdout_sha256':legacy.digest(raw)})
                return raw
            except Exception as exc:native_rows.append(legacy.failure(exc,label));raise
        try:
            cfg=legacy.read_json(self.s.root/'deployment.json');generation=cfg['deployment_hash']
            need(cfg['version']==1 and re.fullmatch('[a-f0-9]{64}',generation)is not None,'deployment_shape')
            need(cfg.get('split_policy')=={'revision':1,'period':core.PERIOD,'warm_budget':core.WARM_BUDGET,'cold_budget':core.COLD_BUDGET},'split_policy')
            need(set(cfg.get('split_sources',{}))=={'split_core.py','split_runtime.py','cold_exec.py','scale_core.py'},'split_sources')
            for name,pin in {**cfg['artifact_pins'],**cfg['split_sources']}.items():
                need(re.fullmatch('[A-Za-z0-9_.-]+',name)is not None,'artifact_name')
                need(legacy.digest((self.s.root/name).read_bytes())==pin,'artifact_pin')
            for i,instance in enumerate(('main','backend')):
                need(legacy.digest(call('config_'+instance,self.config_args(instance)))==cfg['effective_hashes'][i],'effective_config_drift')
            phase='inventory';rows=json.loads(call('inventory',list(self.s.inventory_argv)))
            state=legacy.read_json(self.s.state/'private/state.json',absent={'version':1,'deployment_hash':generation,'cursor':'0','applied':cfg['initial_applied']})
            snapshot=legacy.read_json(self.s.state/'snapshot.json',absent={})
            readiness=legacy.read_json(self.s.state/'private/readiness.json',absent={})or None
            now=int(self.wall());current,readiness=core.reconcile(rows,snapshot,state,readiness,generation,now)
            if self.future is not None and self.future.done():
                try:self.completed=self.future.result()
                except Exception as exc:
                    legacy.atomic(self.s.state/'private/bootstrap-worker-exception.json',failure_document(exc,'background_worker'))
                    failures.append(legacy.failure(exc,'background_worker'))
                    self.completed={**copy.deepcopy(self.running_job),'ready':[]}
                self.future=None
            if self.completed is not None:
                failures.extend(self.completed.get('failures',[]))
                # Same active identity, quota and both config pins are required at acceptance.
                if self.completed['generation']==generation and self.completed['config_hashes']==cfg['effective_hashes']:
                    readiness,_=core.accept_preparation(current,state,readiness,self.completed,generation,cfg['effective_hashes'],now)
                # A stale-generation proof is discarded and cannot grant readiness.
            plan=core.plan(current,snapshot,state,readiness,generation,now)
            phase='normal_measurement';observations={};errors={};observed_at=int(self.wall())
            selected=[current[key]for key in plan['selected']]
            if selected:
                try:
                    path=self.s.state/'private/batch-users.txt';private_bytes(path,user_list(selected));observed_at=int(self.wall())
                    remaining=deadline-self.clock()-.6;need(remaining>0,'normal_measurement_budget')
                    main_raw=call('warm_main',self.argv('main',['-f','tab','quota','get','-F',str(path)]),min(3,remaining/2),131072)
                    try:main=parse_batch(main_raw,selected)
                    except Exception as exc:
                        legacy.atomic(self.s.state/'private/warm-parser-main.json',{'actual_exit':0,'raw_base64':base64.b64encode(main_raw).decode(),**failure_document(exc,'warm_parser')});raise
                    remaining=deadline-self.clock()-.6;need(remaining>0,'normal_measurement_budget')
                    backend_raw=call('warm_backend',self.argv('backend',['-f','tab','quota','get','-F',str(path)]),min(3,remaining),131072)
                    try:backend=parse_batch(backend_raw,selected)
                    except Exception as exc:
                        legacy.atomic(self.s.state/'private/warm-parser-backend.json',{'actual_exit':0,'raw_base64':base64.b64encode(backend_raw).decode(),**failure_document(exc,'warm_parser')});raise
                    joined=combine(main,backend);observations=joined['ok'];errors=joined['errors']
                except Exception as exc:
                    errors={row['id']:'normal_measurement_unverified'for row in selected}
                    legacy.atomic(self.s.state/'private/warm-last-failure.json',failure_document(exc,'normal_measurement'));failures.append(legacy.failure(exc,'normal_measurement'))
            phase='inventory_recheck'
            need(inventory(json.loads(call('inventory_after',list(self.s.inventory_argv))))==current,'inventory_race')
            need(self.clock()<=deadline,'warm_deadline')
            out=core.publish(plan,readiness,observations,errors,observed_at,int(self.wall()))
            prior=core.fresh_records(current,snapshot,generation,now)
            before_publish=int(self.wall())
            phase='publication'
            legacy.atomic(self.s.state/'private/state.json',out['state'])
            legacy.atomic(self.s.state/'private/readiness.json',out['readiness'])
            legacy.atomic(self.s.state/'snapshot.json',out['snapshot'],0o640)
            self.completed=None
            # Submit only after fresh observations are published; never future.result() on an unfinished job.
            if self.future is None:
                pending=core.plan(current,out['snapshot'],out['state'],out['readiness'],generation,int(self.wall()))['cold']
                if pending:
                    job={'generation':generation,'config_hashes':cfg['effective_hashes'],'rows':[current[k]for k in pending],
                         'previous':{k:out['state']['applied'].get(k)for k in pending}}
                    self.running_job=copy.deepcopy(job);self.future=self.pool.submit(self.initialize,job)
            report=out['report'];elapsed=round((self.clock()-started)*1000)
            report['measurement_failure_count']=report['failures'];report['failures']=list(failures)
            report.update(warm_elapsed_ms=elapsed,elapsed_ms=elapsed,cycle_within_budget=elapsed<=core.WARM_BUDGET*1000,
                initializer_running=self.future is not None,native=native_rows,diagnostic_failures=failures,
                previous_fresh_records=len(prior),previous_snapshot_oldest_age_seconds=max((before_publish-x['observed_at']for x in prior.values()),default=None))
            if not report['cycle_within_budget']:report['capacity_within_expiry']=False;report['status']='slow'
            legacy.atomic(self.s.state/'private/last-result.json',report)
            return report
        except Exception as exc:
            detail=legacy.failure(exc,phase)
            for path,value,mode in [
                (self.s.state/'snapshot.json',{'version':1,'deployment_hash':generation,'enforcement_verified':False,'records':{}},0o640),
                (self.s.state/'private/split-last-failure.json',failure_document(exc,phase),0o600)]:
                try:legacy.atomic(path,value,mode)
                except Exception as saving:detail.setdefault('evidence_failures',[]).append(legacy.failure(saving,'failure_save'))
            elapsed=round((self.clock()-started)*1000)
            report={'status':'fail','failure':detail,'native':native_rows,'warm_elapsed_ms':elapsed,'elapsed_ms':elapsed}
            try:legacy.atomic(self.s.state/'private/last-result.json',report)
            except Exception as saving:detail.setdefault('evidence_failures',[]).append(legacy.failure(saving,'report_save'))
            return report

    def close(self):self.pool.shutdown(wait=True,cancel_futures=True)


def daemon():
    need(os.geteuid()==0,'root_required');os.umask(0o077);s=Settings()
    for path in (s.state,s.state/'private'):
        st=os.lstat(path);need(stat.S_ISDIR(st.st_mode)and st.st_uid==0 and not st.st_mode&0o022,'state_parent')
    stop=threading.Event()
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,lambda *_:stop.set())
    with legacy.locked(s.state/'private/collector.lock'):
        collector=Collector(s)
        try:
            while not stop.is_set():
                begin=time.monotonic();report=collector.cycle();print(json.dumps(report),flush=True)
                elapsed=time.monotonic()-begin
                stop.wait(core.PERIOD if elapsed>=core.PERIOD else core.PERIOD-elapsed)
        finally:collector.close()


if __name__=='__main__':daemon()
