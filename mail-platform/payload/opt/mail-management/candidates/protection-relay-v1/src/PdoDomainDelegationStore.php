<?php
declare(strict_types=1);
namespace MailServer\Management;
use PDO;

/** Grants never promote system admins. Role lock, epoch and audit share one transaction. */
final class PdoDomainDelegationStore implements DomainDelegationStore
{
    public function __construct(private readonly PDO $db){$db->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);$db->setAttribute(PDO::ATTR_EMULATE_PREPARES,false);}
    private static function id(string $id):void{if(!preg_match('/^[1-9][0-9]{0,9}$/D',$id)){throw new \DomainException('invalid_identifier');}}
    private function actor(AdminUser $actor,bool $lock):void
    {
        if(!$actor->active||!$actor->systemAdmin){throw new \DomainException('not_authorized');}
        $q=$this->db->prepare('SELECT active,is_system_admin,auth_epoch,email FROM mail_admin_users WHERE id=?'.($lock?' FOR UPDATE':''));$q->execute([$actor->id]);$row=$q->fetch(PDO::FETCH_ASSOC);
        if(!$row||(string)$row['active']!=='1'||(string)$row['is_system_admin']!=='1'||(string)$row['auth_epoch']!==$actor->epoch||$row['email']!==$actor->getUserIdentifier()){throw new \DomainException('admin_session_changed');}
    }
    private function scope(string $adminId,string $domainId,bool $lock):array
    {
        $q=$this->db->prepare('SELECT email,active,is_system_admin,auth_epoch FROM mail_admin_users WHERE id=?'.($lock?' FOR UPDATE':''));$q->execute([$adminId]);$admin=$q->fetch(PDO::FETCH_ASSOC);
        if(!$admin||(string)$admin['active']!=='1'||(string)$admin['is_system_admin']!=='0'){throw new \DomainException('active_delegate_required');}
        $q=$this->db->prepare('SELECT name,active FROM mailserver.virtual_domains WHERE id=?'.($lock?' FOR UPDATE':''));$q->execute([$domainId]);$domain=$q->fetch(PDO::FETCH_ASSOC);
        if(!$domain||(string)$domain['active']!=='1'){throw new \DomainException('active_domain_required');}
        $q=$this->db->prepare('SELECT capability,active,revision FROM mail_feature_domain_grants WHERE admin_id=? AND domain_id=? ORDER BY capability'.($lock?' FOR UPDATE':''));$q->execute([$adminId,$domainId]);
        $revision=0;$capabilities=[];
        foreach($q->fetchAll(PDO::FETCH_ASSOC) as $row){if(!in_array($row['capability'],DomainAuthority::OPERATIONS,true)||(int)$row['revision']<1){throw new \DomainException('invalid_grant_state');}$revision=max($revision,(int)$row['revision']);if((string)$row['active']==='1'){$capabilities[]=$row['capability'];}}
        return ['admin_id'=>$adminId,'admin_label'=>$admin['email'],'domain_id'=>$domainId,'domain_label'=>$domain['name'],'revision'=>$revision,'capabilities'=>$capabilities];
    }
    public function lookup(AdminUser $actor,string $adminId,string $domainId):array
    {
        self::id($adminId);self::id($domainId);$this->actor($actor,false);return $this->scope($adminId,$domainId,false);
    }
    public function save(AdminUser $actor,array $r):array
    {
        if(array_keys($r)!==['admin_id','domain_id','revision','capabilities','request_id']||!is_string($r['admin_id'])||!is_string($r['domain_id'])||!is_int($r['revision'])||$r['revision']<0||!is_array($r['capabilities'])||count($r['capabilities'])>count(DomainAuthority::OPERATIONS)||!is_string($r['request_id'])||!preg_match('/^[a-f0-9]{32}$/D',$r['request_id'])||$this->db->inTransaction()){throw new \DomainException('invalid_request');}
        self::id($r['admin_id']);self::id($r['domain_id']);$caps=$r['capabilities'];foreach($caps as $cap){if(!is_string($cap)||!in_array($cap,DomainAuthority::OPERATIONS,true)){throw new \DomainException('invalid_capability');}}
        if(count(array_unique($caps))!==count($caps)){throw new \DomainException('duplicate_capability');}sort($caps,SORT_STRING);$digest=hash('sha256',json_encode([$actor->id,$r['admin_id'],$r['domain_id'],$r['revision'],$caps],JSON_THROW_ON_ERROR));$committing=false;$stage='begin';
        try{
            $this->db->beginTransaction();$stage='roles_lock';$q=$this->db->query("SELECT name FROM mail_management_locks WHERE name='admin_roles' FOR UPDATE");if($q->fetchColumn()!=='admin_roles'){throw new \DomainException('schema_not_ready');}$stage='actor_refresh';$this->actor($actor,true);
            $stage='prior_receipt';$q=$this->db->prepare('SELECT request_digest,revision FROM mail_feature_delegation_runs WHERE request_id=? FOR UPDATE');$q->execute([$r['request_id']]);$prior=$q->fetch(PDO::FETCH_ASSOC);
            if($prior){if(!hash_equals($prior['request_digest'],$digest)){throw new \DomainException('request_id_reused');}$this->db->rollBack();return ['state'=>'applied','revision'=>(int)$prior['revision'],'replayed_receipt'=>true];}
            $stage='scope_lock';$before=$this->scope($r['admin_id'],$r['domain_id'],true);if($before['revision']!==$r['revision']){throw new \DomainException('stale_revision');}
            if($before['capabilities']===$caps){throw new \DomainException('no_change');}$next=$before['revision']+1;
            $stage='grants_disable';$this->db->prepare('UPDATE mail_feature_domain_grants SET active=0,revision=? WHERE admin_id=? AND domain_id=?')->execute([$next,$r['admin_id'],$r['domain_id']]);
            $stage='grants_prepare';$enable=$this->db->prepare('UPDATE mail_feature_domain_grants SET active=1,revision=? WHERE admin_id=? AND domain_id=? AND capability=?');
            $insert=$this->db->prepare('INSERT INTO mail_feature_domain_grants(admin_id,domain_id,capability,active,revision) VALUES(?,?,?,1,?)');
            foreach($caps as $cap){
                $stage='grants_update';$enable->execute([$next,$r['admin_id'],$r['domain_id'],$cap]);$changed=$enable->rowCount();
                if($changed===0){$stage='grants_insert';$insert->execute([$r['admin_id'],$r['domain_id'],$cap,$next]);}
                elseif($changed!==1){throw new \DomainException('grant_write_ambiguous');}
            }
            $stage='epoch_advance';$q=$this->db->prepare('UPDATE mail_admin_users SET auth_epoch=auth_epoch+1 WHERE id=? AND active=1 AND is_system_admin=0');$q->execute([$r['admin_id']]);if($q->rowCount()!==1){throw new \DomainException('delegate_changed');}
            $stage='receipt_insert';$this->db->prepare('INSERT INTO mail_feature_delegation_runs(request_id,actor_id,target_admin_id,domain_id,request_digest,revision,before_capabilities,after_capabilities) VALUES(?,?,?,?,?,?,?,?)')->execute([$r['request_id'],$actor->id,$r['admin_id'],$r['domain_id'],$digest,$next,json_encode($before['capabilities'],JSON_THROW_ON_ERROR),json_encode($caps,JSON_THROW_ON_ERROR)]);
            $stage='audit_insert';$this->db->prepare('INSERT INTO mail_admin_audit(admin_id,action,target_type,target_id) VALUES(?,?,?,?)')->execute([$actor->id,'domain_delegation_change','admin',$r['admin_id']]);
            $stage='commit';$committing=true;if(!$this->db->commit()){throw new \DomainException('result_unverified');}return ['state'=>'applied','revision'=>$next,'replayed_receipt'=>false];
        }catch(\Throwable $error){try{if($this->db->inTransaction()){$this->db->rollBack();}}catch(\Throwable $cleanup){throw new FeatureStorageFailure('result_unverified',$stage,$error,$cleanup,$committing);}if($committing){throw new FeatureStorageFailure('result_unverified',$stage,$error,null,true);}if($error instanceof \DomainException){throw $error;}throw new FeatureStorageFailure('delegation_operation_failed',$stage,$error,null,false);}
    }
}
