<?php
declare(strict_types=1);
namespace MailServer\Management;
use PDO;

/** One selected batch, namespace exclusion, live authority and audit in one transaction. */
final class PdoBulkMailboxStore implements BulkMailboxStore
{
    public function __construct(private readonly PDO $db) {$db->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);$db->setAttribute(PDO::ATTR_EMULATE_PREPARES,false);}
    public function domains(AdminUser $actor):array
    {
        $q=$this->db->prepare('SELECT active,is_system_admin,auth_epoch,email FROM mail_admin_users WHERE id=?');$q->execute([$actor->id]);$current=$q->fetch(PDO::FETCH_ASSOC);
        if(!$current||(string)$current['active']!=='1'||(string)$current['auth_epoch']!==$actor->epoch||$current['email']!==$actor->getUserIdentifier()||((string)$current['is_system_admin']==='1')!==$actor->systemAdmin){throw new \DomainException('admin_session_changed');}
        if($actor->systemAdmin){$q=$this->db->query('SELECT id,name FROM mailserver.virtual_domains WHERE active=1 ORDER BY id LIMIT 10001');}
        else{$q=$this->db->prepare("SELECT d.id,d.name FROM mailserver.virtual_domains d WHERE d.active=1 AND EXISTS(SELECT 1 FROM mail_feature_domain_grants g WHERE g.admin_id=? AND g.domain_id=d.id AND g.active=1 AND g.capability='csv.preview') ORDER BY d.id LIMIT 10001");$q->execute([$actor->id]);}
        $rows=$q->fetchAll(PDO::FETCH_ASSOC);if(count($rows)>10000){throw new \DomainException('domain_inventory_bound');}
        $out=[];foreach($rows as $row){$out[(string)$row['id']]=$row['name'];}return $out;
    }
    public function apply(AdminUser $actor,#[\SensitiveParameter] BulkMailboxPlan $plan,array $lines,string $requestId):array
    {
        if(!$actor->active||$this->db->inTransaction()||!preg_match('/^[a-f0-9]{32}$/D',$requestId)){throw new \DomainException('not_authorized');}
        $rows=$plan->selected($lines);$committing=false;$stage='begin';
        try{
            $this->db->beginTransaction();
            foreach(['alias_namespace','admin_roles'] as $name){$stage='lock_'.$name;$q=$this->db->prepare('SELECT name FROM mail_management_locks WHERE name=? FOR UPDATE');$q->execute([$name]);if($q->fetchColumn()!==$name){throw new \DomainException('schema_not_ready');}}
            $stage='actor_refresh';
            $q=$this->db->prepare('SELECT active,is_system_admin,auth_epoch,email FROM mail_admin_users WHERE id=? FOR UPDATE');$q->execute([$actor->id]);$current=$q->fetch(PDO::FETCH_ASSOC);
            if(!$current||(string)$current['active']!=='1'||(string)$current['auth_epoch']!==$actor->epoch||$current['email']!==$actor->getUserIdentifier()||((string)$current['is_system_admin']==='1')!==$actor->systemAdmin){throw new \DomainException('admin_session_changed');}
            $stage='prior_receipt';$q=$this->db->prepare('SELECT request_id FROM mail_feature_bulk_runs WHERE request_id=? FOR UPDATE');$q->execute([$requestId]);if($q->fetchColumn()!==false){throw new \DomainException('bulk_request_already_recorded');}
            $grants=[];
            if(!$actor->systemAdmin){$stage='grants_read';$q=$this->db->prepare('SELECT domain_id,capability FROM mail_feature_domain_grants WHERE admin_id=? AND active=1 FOR UPDATE');$q->execute([$actor->id]);foreach($q->fetchAll(PDO::FETCH_ASSOC) as $g){$grants[(string)$g['domain_id']][]=$g['capability'];}}
            $authority=new DomainAuthority($actor,$grants,1);$ids=array_values(array_unique(array_column($rows,'domain_id')));
            $authority->require('csv.apply',$ids);$authority->require('mailbox.create',$ids);
            $out=[];
            foreach($rows as $row){
                $stage='domain_lock';$q=$this->db->prepare('SELECT name,active FROM mailserver.virtual_domains WHERE id=? FOR UPDATE');$q->execute([$row['domain_id']]);$domain=$q->fetch(PDO::FETCH_ASSOC);
                if(!$domain||(string)$domain['active']!=='1'||!str_ends_with($row['email'],'@'.$domain['name'])){throw new \DomainException('domain_changed');}
                $stage='namespace_check';MailboxNamespaceGuard::available($this->db,substr($row['email'],0,strpos($row['email'],'@')),['id'=>$row['domain_id'],...$domain]);
                $stage='mailbox_insert';$q=$this->db->prepare('INSERT INTO mailserver.virtual_users(domain_id,email,password,active,quota_bytes,auth_epoch,created_at) VALUES(?,?,?,0,?,1,CURRENT_TIMESTAMP)');
                $q->execute([$row['domain_id'],$row['email'],$row['hash'],$row['quota_bytes']]);$id=$this->db->lastInsertId();
                $stage='audit_insert';$this->db->prepare('INSERT INTO mail_admin_audit(admin_id,action,target_type,target_id) VALUES(?,?,?,?)')->execute([$actor->id,'bulk_mailbox_create','mailbox',$id]);
                $out[]=['line'=>$row['line'],'id'=>$id,'state'=>'無効'];
            }
            $stage='receipt_insert';$this->db->prepare('INSERT INTO mail_feature_bulk_runs(request_id,admin_id,row_count,created_at) VALUES(?,?,?,CURRENT_TIMESTAMP)')->execute([$requestId,$actor->id,count($out)]);
            $stage='commit';$committing=true;if(!$this->db->commit()){throw new \DomainException('result_unverified');}return $out;
        }catch(\Throwable $error){
            try{if($this->db->inTransaction()){$this->db->rollBack();}}catch(\Throwable $cleanup){throw new FeatureStorageFailure('result_unverified',$stage,$error,$cleanup,$committing);}
            if($committing){throw new FeatureStorageFailure('result_unverified',$stage,$error,null,true);}
            if($error instanceof \DomainException){throw $error;}throw new FeatureStorageFailure('bulk_operation_failed',$stage,$error,null,false);
        }
    }
}
