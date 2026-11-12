"""Fresh root-owned delivery generation; stale/changed IPC blocks gate admission."""
import json
import os
from pathlib import Path
import time
from safety import need,held
class Readiness:
    def __init__(self,path,namespace=None,max_age=5):self.path,self.namespace,self.max_age=path,namespace,max_age
    def require_current(self,stage):
        need(stage in {'external_certificate_routes','smtp_policy','roundcube_db_session_schema_serializer_and_least_privilege'},'readiness_stage')
        value=json.loads(held(self.path,8192));now=time.time()
        need(value.get('version')==1 and value.get('valid')is True and value.get('boot_id')==Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            and type(value.get('observed_at'))in(int,float)and 0<=now-value['observed_at']<=self.max_age,'delivery_readiness_stale_or_invalid')
        if self.namespace is not None:need(value.get('private_namespace')==list(self.namespace.verify()),'delivery_readiness_namespace')
        return value
