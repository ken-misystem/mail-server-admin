"""Explicit initial gate adoption. This entry never updates mail or shared actor data."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

root=Path(__file__).resolve().parent
if root.stat().st_uid!=0 or root.stat().st_mode&0o022:
    raise ValueError('enrollment_bootstrap_trust')
sys.path.insert(0,str(root))
from certificate_enrollment import (Adoption,CONFIG,GATE_UNIT,RELEASE,encoded,gate_unit,
                                    stage,trusted,verify_stage)
from host_transaction import CommandFailure,Commands

def execute(plan_path,operation):
    if os.geteuid()!=0:raise ValueError('enrollment_root_required')
    plan=json.loads(trusted(plan_path,1048576)[0])
    if set(plan)!={'format','hostname','release','configuration','payload','destination','expected','unit','dropins','payload_pins'} or plan['format']!=1:
        raise ValueError('enrollment_plan_fields')
    if plan['release']!=RELEASE or plan['configuration']!=CONFIG:
        raise ValueError('enrollment_production_paths')
    if subprocess.check_output(['/usr/bin/hostname','-f'],timeout=5).decode().strip()!=plan['hostname']:
        raise ValueError('enrollment_hostname')
    destination=Path(plan['destination'])
    if not str(destination).startswith('/var/lib/mail-platform-update/enrollment/'):
        raise ValueError('enrollment_destination')
    from availability_plan import path
    path(str(destination));path(plan['payload'])
    if operation=='prepare':
        from certificate_enrollment import MODULES
        if set(plan['payload_pins'])!=set(MODULES):raise ValueError('enrollment_payload_fields')
        for name,digest in plan['payload_pins'].items():
            if trusted(Path(plan['payload'])/name)[1]['sha256']!=digest:
                raise ValueError('enrollment_payload_pin')
        if trusted(GATE_UNIT)[1]!=plan['unit']:raise ValueError('enrollment_unit_baseline')
        for name,expected in plan['dropins'].items():
            if not name.startswith(GATE_UNIT+'.d/') or not name.endswith('.conf'):
                raise ValueError('enrollment_dropin_path')
            if trusted(name)[1]!=expected:raise ValueError('enrollment_dropin_drift')
        return stage(RELEASE,CONFIG,plan['payload'],destination,plan['expected'])
    if operation=='adopt':verify_stage(destination)
    transaction=Adoption('/',destination/'transaction')
    commands=Commands(destination/'transaction')
    # Commands is reused across processes; never overwrite earlier original output.
    commands.sequence=len(list((destination/'transaction').glob('*.stdout')))
    if operation=='adopt':
        if set(str(p) for p in Path(GATE_UNIT+'.d').glob('*.conf'))!=set(plan['dropins']):
            raise ValueError('enrollment_dropin_inventory')
        for name,expected in plan['dropins'].items():
            if trusted(name)[1]!=expected:raise ValueError('enrollment_dropin_drift')
        for name in ('submission','imaps','pop3s'):
            commands.run('front_active',['/usr/bin/systemctl','is-active','--quiet','mail-platform-'+name+'-front.service'],timeout=10)
        # Recheck baseline after stage; never carry stale actor configuration into adoption.
        for name,expected in ((CONFIG,plan['expected']['config']),
                              (RELEASE+'/runtime-manifest.json',plan['expected']['manifest'])):
            if trusted(name)[1]!=expected:raise ValueError('enrollment_live_baseline_drift')
        original=trusted(GATE_UNIT)[0]
        transaction.adopt(GATE_UNIT,gate_unit(original,RELEASE,CONFIG,destination),plan['unit'])
        for operation_name,args in (('daemon_reload',['daemon-reload']),('gate_restart',['restart','mail-client-cert-gate.service'])):
            transaction.operation_started(operation_name)
            try:commands.run(operation_name,['/usr/bin/systemctl',*args],timeout=60)
            except CommandFailure as failure:
                if not failure.record['timed_out'] and not failure.record['spawn_error']:
                    transaction.operation_finished()
                raise
            transaction.operation_finished()
        commands.run('gate_active',['/usr/bin/systemctl','is-active','--quiet','mail-client-cert-gate.service'],timeout=10)
        return {'status':'unit_adopted','application_health':'requires_site_specific_confirmation'}
    restored=transaction.recover()
    if restored['status']=='restored':
        for operation_name,args in (('daemon_reload',['daemon-reload']),('gate_restart',['restart','mail-client-cert-gate.service'])):
            transaction.operation_started(operation_name)
            commands.run(operation_name,['/usr/bin/systemctl',*args],timeout=60)
            transaction.operation_finished()
    return restored

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--plan',type=Path,required=True)
    parser.add_argument('operation',choices=('prepare','adopt','recover'))
    args=parser.parse_args()
    print(json.dumps(execute(args.plan,args.operation),sort_keys=True))
