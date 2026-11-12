<?php
declare(strict_types=1);
namespace MailServer\Management;
use PDO;

final class PdoManagedSettingsStore implements ManagedSettingsStore
{
    public function __construct(private readonly PDO $db){$db->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);$db->setAttribute(PDO::ATTR_EMULATE_PREPARES,false);}
    private function query(string $sql,array $args=[]):\PDOStatement{$q=$this->db->prepare($sql);$q->execute($args);return $q;}
    private function actor(AdminUser $actor,bool $lock):void
    {
        if(!$actor->active||!$actor->systemAdmin){throw new \DomainException('system_admin_required');}
        $row=$this->query('SELECT email,active,is_system_admin,auth_epoch FROM mail_admin_users WHERE id=?'.($lock?' FOR UPDATE':''),[$actor->id])->fetch(PDO::FETCH_ASSOC);
        if(!$row||(string)$row['active']!=='1'||(string)$row['is_system_admin']!=='1'||(string)$row['auth_epoch']!==$actor->epoch||$row['email']!==$actor->getUserIdentifier()){throw new \DomainException('admin_session_changed');}
    }
    private function current(string $kind,bool $lock):array
    {
        if(!in_array($kind,ManagedSettings::KINDS,true)){throw new \DomainException('invalid_setting_kind');}
        $row=$this->query('SELECT revision,payload FROM mail_feature_settings WHERE kind=?'.($lock?' FOR UPDATE':''),[$kind])->fetch(PDO::FETCH_ASSOC);
        if(!$row){return ['kind'=>$kind,'revision'=>0,'payload'=>ManagedSettings::defaults($kind)];}
        if(strlen($row['payload'])>2097152||!preg_match('/^[1-9][0-9]{0,9}$/D',(string)$row['revision'])){throw new \DomainException('setting_state_invalid');}
        return ['kind'=>$kind,'revision'=>(int)$row['revision'],'payload'=>ManagedSettings::validate($kind,json_decode($row['payload'],true,32,JSON_THROW_ON_ERROR))];
    }
    private function failure(\Throwable $error,string $stage,bool $committing):never
    {
        try{if($this->db->inTransaction()&&!$this->db->rollBack()){throw new \RuntimeException('rollback_unverified');}}catch(\Throwable $cleanup){throw new FeatureStorageFailure('result_unverified',$stage,$error,$cleanup,$committing);}
        if($committing){throw new FeatureStorageFailure('result_unverified',$stage,$error,null,true);}if($error instanceof \DomainException){throw $error;}throw new FeatureStorageFailure('settings_storage_failed',$stage,$error,null,false);
    }
    public function lookup(AdminUser $actor,string $kind):array
    {
        if($this->db->inTransaction()){throw new \DomainException('transaction_active');}$stage='begin';
        try{$this->db->exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');$this->db->exec('START TRANSACTION READ ONLY');$stage='actor_refresh';$this->actor($actor,false);$stage='settings_read';$row=$this->current($kind,false);if(!$this->db->rollBack()){throw new \RuntimeException('read_close');}return $row;}catch(\Throwable $error){$this->failure($error,$stage,false);}
    }
    public function save(AdminUser $actor,string $kind,int $revision,array $payload,string $requestId):array
    {
        $payload=ManagedSettings::validate($kind,$payload);$encoded=json_encode($payload,JSON_THROW_ON_ERROR|JSON_PRESERVE_ZERO_FRACTION);
        if($this->db->inTransaction()||$revision<0||$revision>=2147483647||strlen($encoded)>2097152||!preg_match('/^[a-f0-9]{32}$/D',$requestId)){throw new \DomainException('invalid_settings_request');}
        $stage='begin';$committing=false;
        try{
            if(!$this->db->beginTransaction()){throw new \RuntimeException('transaction_unavailable');}
            foreach(['alias_namespace','admin_roles']as $name){$stage='lock_'.$name;if($this->query('SELECT name FROM mail_management_locks WHERE name=? FOR UPDATE',[$name])->fetchColumn()!==$name){throw new \DomainException('schema_not_ready');}}
            $stage='actor_refresh';$this->actor($actor,true);$stage='receipt_read';if($this->query('SELECT request_id FROM mail_feature_setting_runs WHERE request_id=? FOR UPDATE',[$requestId])->fetchColumn()!==false){throw new \DomainException('operation_already_recorded');}
            $stage='settings_read';$before=$this->current($kind,true);if($before['revision']!==$revision){throw new \DomainException('stale_revision');}
            $stage='domains_check';foreach($payload[$kind==='access'?'rules':'profiles']as $row){if($row['domain_id']>0&&$this->query('SELECT id FROM mailserver.virtual_domains WHERE id=?',[$row['domain_id']])->fetchColumn()===false){throw new \DomainException('unknown_domain');}}
            $stage='settings_write';$q=$revision===0?$this->query('INSERT INTO mail_feature_settings(kind,revision,payload,updated_at) VALUES(?,1,?,CURRENT_TIMESTAMP)',[$kind,$encoded]):$this->query('UPDATE mail_feature_settings SET revision=?,payload=?,updated_at=CURRENT_TIMESTAMP WHERE kind=? AND revision=?',[$revision+1,$encoded,$kind,$revision]);if($q->rowCount()!==1){throw new \DomainException('write_row_count');}
            $action=$kind==='access'?'rules_change':'spam_change';$stage='audit_insert';if($this->query('INSERT INTO mail_admin_audit(admin_id,action,target_type,target_id) VALUES(?,?,?,?)',[$actor->id,$action,'settings',$kind])->rowCount()!==1){throw new \DomainException('audit_row_count');}
            $stage='receipt_insert';if($this->query('INSERT INTO mail_feature_setting_runs(request_id,admin_id,action,target_id,revision,before_json,after_json) VALUES(?,?,?,0,?,?,?)',[$requestId,$actor->id,$action,$revision+1,json_encode($before['payload'],JSON_THROW_ON_ERROR),$encoded])->rowCount()!==1){throw new \DomainException('receipt_row_count');}
            $stage='commit';$committing=true;if(!$this->db->commit()){throw new \DomainException('result_unverified');}return ['state'=>'saved_pending_publication','kind'=>$kind,'revision'=>$revision+1];
        }catch(\Throwable $error){$this->failure($error,$stage,$committing);}
    }
}
