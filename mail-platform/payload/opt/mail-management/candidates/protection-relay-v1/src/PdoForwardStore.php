<?php
declare(strict_types=1);
namespace MailServer\Management;
use PDO;

/** Configuration only; root publisher owns Sieve and never accepts shell commands. */
final class PdoForwardStore implements ForwardStore
{
    public function __construct(private readonly PDO $db){$db->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);$db->setAttribute(PDO::ATTR_EMULATE_PREPARES,false);}
    private function query(string $sql,array $args=[]):\PDOStatement{$q=$this->db->prepare($sql);$q->execute($args);return $q;}
    private function authority(AdminUser $actor,bool $lock):DomainAuthority
    {
        $tail=$lock?' FOR UPDATE':'';$row=$this->query('SELECT email,active,is_system_admin,auth_epoch FROM mail_admin_users WHERE id=?'.$tail,[$actor->id])->fetch(PDO::FETCH_ASSOC);
        if(!$actor->active||!$row||(string)$row['active']!=='1'||$row['email']!==$actor->getUserIdentifier()||(string)$row['auth_epoch']!==$actor->epoch||((string)$row['is_system_admin']==='1')!==$actor->systemAdmin){throw new \DomainException('admin_session_changed');}
        $grants=[];if(!$actor->systemAdmin){foreach($this->query('SELECT domain_id,capability FROM mail_feature_domain_grants WHERE admin_id=? AND active=1'.$tail,[$actor->id])->fetchAll(PDO::FETCH_ASSOC)as $g){$grants[(string)$g['domain_id']][]=$g['capability'];}}
        return new DomainAuthority($actor,$grants,1);
    }
    private function target(string $id,bool $lock):?array
    {
        return $this->query('SELECT u.id,u.domain_id,u.email,u.active,d.active AS domain_active FROM mailserver.virtual_users u JOIN mailserver.virtual_domains d ON d.id=u.domain_id WHERE u.id=?'.($lock?' FOR UPDATE':''),[$id])->fetch(PDO::FETCH_ASSOC)?:null;
    }
    private function current(string $id,bool $lock):array
    {
        $row=$this->query('SELECT destinations,enabled,revision,UNIX_TIMESTAMP(health_reset_at) AS health_reset_at FROM mail_feature_forwards WHERE user_id=?'.($lock?' FOR UPDATE':''),[$id])->fetch(PDO::FETCH_ASSOC);
        if(!$row){return ['destinations'=>[],'enabled'=>false,'revision'=>0,'health_reset_at'=>null];}
        if(!in_array((string)$row['enabled'],['0','1'],true)||!preg_match('/^[1-9][0-9]{0,9}$/D',(string)$row['revision'])){throw new \DomainException('forward_state_invalid');}
        return ['destinations'=>ForwardPlan::targets(json_decode($row['destinations'],true,32,JSON_THROW_ON_ERROR)),'enabled'=>(string)$row['enabled']==='1','revision'=>(int)$row['revision'],'health_reset_at'=>(int)$row['health_reset_at']];
    }
    public function lookup(AdminUser $actor,string $userId):?array
    {
        ScopedAdminQuery::id($userId);if($this->db->inTransaction()){throw new \DomainException('transaction_active');}$stage='begin';
        try{$this->db->exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');$this->db->exec('START TRANSACTION READ ONLY');$stage='actor_refresh';$authority=$this->authority($actor,false);$target=$this->target($userId,false);
            if(!$target){$this->db->rollBack();return null;}try{$authority->require('forward.read',[(string)$target['domain_id']]);}catch(\DomainException){$this->db->rollBack();return null;}
            $stage='forward_read';$row=$this->current($userId,false);$mayChange=true;try{$authority->require('forward.change',[(string)$target['domain_id']]);}catch(\DomainException){$mayChange=false;}
            $this->db->rollBack();return ['user_id'=>(string)$target['id'],'domain_id'=>(string)$target['domain_id'],'email'=>$target['email'],'mailbox_active'=>(string)$target['active']==='1','domain_active'=>(string)$target['domain_active']==='1','can_change'=>$mayChange,...$row];
        }catch(\Throwable $error){$this->failed($error,$stage,false);}
    }
    private function failed(\Throwable $error,string $stage,bool $committing):never
    {
        try{if($this->db->inTransaction()&&!$this->db->rollBack()){throw new \RuntimeException('rollback_unverified');}}catch(\Throwable $cleanup){throw new FeatureStorageFailure('result_unverified',$stage,$error,$cleanup,$committing);}
        if($committing){throw new FeatureStorageFailure('result_unverified',$stage,$error,null,true);}if($error instanceof \DomainException){throw $error;}throw new FeatureStorageFailure('forward_storage_failed',$stage,$error,null,false);
    }
    public function save(AdminUser $actor,string $userId,int $revision,array $destinations,bool $enabled,string $confirmation,string $requestId):array
    {
        ScopedAdminQuery::id($userId);$destinations=ForwardPlan::targets($destinations);
        if($this->db->inTransaction()||$revision<0||$revision>=2147483647||!preg_match('/^[a-f0-9]{32}$/D',$requestId)||($enabled&&!$destinations)){throw new \DomainException('invalid_forward_request');}
        $stage='begin';$committing=false;
        try{
            if(!$this->db->beginTransaction()){throw new \DomainException('transaction_unavailable');}
            foreach(['alias_namespace','admin_roles']as $name){$stage='lock_'.$name;if($this->query('SELECT name FROM mail_management_locks WHERE name=? FOR UPDATE',[$name])->fetchColumn()!==$name){throw new \DomainException('schema_not_ready');}}
            $stage='actor_refresh';$authority=$this->authority($actor,true);$target=$this->target($userId,true);if(!$target){throw new \DomainException('unknown_target');}$authority->require('forward.change',[(string)$target['domain_id']]);AdminMailPolicy::confirmation($target['email'],$confirmation);
            if($enabled&&((string)$target['active']!=='1'||(string)$target['domain_active']!=='1')){throw new \DomainException('inactive_forward_source');}
            $stage='receipt_read';if($this->query('SELECT request_id FROM mail_feature_setting_runs WHERE request_id=? FOR UPDATE',[$requestId])->fetchColumn()!==false){throw new \DomainException('operation_already_recorded');}
            $before=$this->current($userId,true);if($before['revision']!==$revision){throw new \DomainException('stale_revision');}
            $stage='complete_graph';$domains=$this->query('SELECT id,name FROM mailserver.virtual_domains ORDER BY id LIMIT 10001')->fetchAll(PDO::FETCH_ASSOC);
            $domainAliases=$this->query('SELECT alias_domain,target_domain_id FROM mailserver.virtual_domain_aliases ORDER BY id LIMIT 1001')->fetchAll(PDO::FETCH_ASSOC);
            $users=$this->query('SELECT id,domain_id,email FROM mailserver.virtual_users ORDER BY id LIMIT 10001')->fetchAll(PDO::FETCH_ASSOC);
            $aliases=$this->query('SELECT domain_id,source,destination FROM mailserver.virtual_aliases ORDER BY id LIMIT 10001')->fetchAll(PDO::FETCH_ASSOC);
            $routes=[];foreach($this->query('SELECT f.user_id,u.email,f.destinations FROM mail_feature_forwards f JOIN mailserver.virtual_users u ON u.id=f.user_id ORDER BY f.user_id LIMIT 10001')->fetchAll(PDO::FETCH_ASSOC)as $row){if((string)$row['user_id']!==$userId){$routes[]=['source'=>$row['email'],'destinations'=>json_decode($row['destinations'],true,32,JSON_THROW_ON_ERROR)];}}
            $routes[]=['source'=>$target['email'],'destinations'=>$destinations];$projected=ForwardPlan::project($routes,$domains,$domainAliases,$users,$aliases);$authority->require('forward.change',$projected[$target['email']]['domain_ids']);
            $after=['destinations'=>$destinations,'enabled'=>$enabled,'revision'=>$revision+1];$stage='configuration_write';$encoded=json_encode($destinations,JSON_THROW_ON_ERROR);
            if($revision===0){$q=$this->query('INSERT INTO mail_feature_forwards(user_id,destinations,enabled,revision,health_reset_at,updated_at) VALUES(?,?,?,1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)',[$userId,$encoded,$enabled?1:0]);}
            else{$q=$this->query('UPDATE mail_feature_forwards SET destinations=?,enabled=?,revision=?,health_reset_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE user_id=? AND revision=?',[$encoded,$enabled?1:0,$revision+1,$userId,$revision]);}
            if($q->rowCount()!==1){throw new \DomainException('write_row_count');}
            $stage='audit_insert';if($this->query('INSERT INTO mail_admin_audit(admin_id,action,target_type,target_id) VALUES(?,?,?,?)',[$actor->id,'forward_change','mailbox',$userId])->rowCount()!==1){throw new \DomainException('audit_row_count');}
            $stage='receipt_insert';if($this->query('INSERT INTO mail_feature_setting_runs(request_id,admin_id,action,target_id,revision,before_json,after_json) VALUES(?,?,?,?,?,?,?)',[$requestId,$actor->id,'forward_change',$userId,$revision+1,json_encode($before,JSON_THROW_ON_ERROR),json_encode($after,JSON_THROW_ON_ERROR)])->rowCount()!==1){throw new \DomainException('receipt_row_count');}
            $stage='commit';$committing=true;if(!$this->db->commit()){throw new \DomainException('result_unverified');}return ['state'=>'saved_pending_publication','user_id'=>$userId,'revision'=>$revision+1];
        }catch(\Throwable $error){$this->failed($error,$stage,$committing);}
    }
}
