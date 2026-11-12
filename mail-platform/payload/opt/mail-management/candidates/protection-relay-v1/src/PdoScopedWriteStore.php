<?php
declare(strict_types=1);
namespace MailServer\Management;
use PDO;
use MailServer\Management\Preparation\MailboxQuotaChange;
require_once __DIR__.'/MailboxQuotaChange.php';

/** Actor, namespace, all affected domains, mutation, receipt and audit share one transaction. */
final class PdoScopedWriteStore implements ScopedWriteStore
{
    private ?DomainAuthority $authority=null;
    public function __construct(private readonly PDO $db,private readonly QuotaUsageProvider $usage)
    {$db->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);$db->setAttribute(PDO::ATTR_EMULATE_PREPARES,false);}
    private function query(string $sql,array $args=[]):\PDOStatement{$q=$this->db->prepare($sql);$q->execute($args);return $q;}
    private function row(string $table,string $id):array
    {
        $columns=match($table){'mailserver.virtual_domains'=>'id,name,active','mailserver.virtual_users'=>'id,domain_id,email,active,auth_epoch,quota_bytes',
            'mailserver.virtual_aliases'=>'id,domain_id,source,destination,active'};
        $row=$this->query('SELECT '.$columns.' FROM '.$table.' WHERE id=? FOR UPDATE',[$id])->fetch(PDO::FETCH_ASSOC);
        if(!$row){throw new \DomainException('unknown_target');}return $row;
    }
    private function permit(string $operation,array $ids):void
    {$this->authority?->require($operation,array_map(strval(...),array_values(array_unique($ids))));if($this->authority===null){throw new \LogicException('authority_missing');}}
    public function apply(AdminUser $actor,#[\SensitiveParameter] ScopedMutation $m,string $requestId):array
    {
        if(!$actor->active||$this->db->inTransaction()||!preg_match('/^[a-f0-9]{32}$/D',$requestId)){throw new \DomainException('not_authorized');}
        $stage='begin';$committing=false;
        try{
            if(!$this->db->beginTransaction()){throw new \DomainException('transaction_unavailable');}
            foreach(['alias_namespace','admin_roles'] as $lock){$stage='lock_'.$lock;if($this->query('SELECT name FROM mail_management_locks WHERE name=? FOR UPDATE',[$lock])->fetchColumn()!==$lock){throw new \DomainException('schema_not_ready');}}
            $stage='actor_refresh';$current=$this->query('SELECT active,is_system_admin,auth_epoch,email FROM mail_admin_users WHERE id=? FOR UPDATE',[$actor->id])->fetch(PDO::FETCH_ASSOC);
            if(!$current||(string)$current['active']!=='1'||(string)$current['auth_epoch']!==$actor->epoch||$current['email']!==$actor->getUserIdentifier()||((string)$current['is_system_admin']==='1')!==$actor->systemAdmin){throw new \DomainException('admin_session_changed');}
            $stage='prior_receipt';if($this->query('SELECT request_id FROM mail_feature_operation_runs WHERE request_id=? FOR UPDATE',[$requestId])->fetchColumn()!==false){throw new \DomainException('operation_already_recorded');}
            $grants=[];if(!$actor->systemAdmin){$stage='grants_read';foreach($this->query('SELECT domain_id,capability FROM mail_feature_domain_grants WHERE admin_id=? AND active=1 FOR UPDATE',[$actor->id])->fetchAll(PDO::FETCH_ASSOC) as $g){$grants[(string)$g['domain_id']][]=$g['capability'];}}
            $this->authority=new DomainAuthority($actor,$grants,1);$stage='authorized_mutation';
            $target=str_starts_with($m->action,'mailbox_')?$this->mailbox($m):$this->alias($m);$type=str_starts_with($m->action,'mailbox_')?'mailbox':'alias';
            $stage='audit_insert';$q=$this->query('INSERT INTO mail_admin_audit(admin_id,action,target_type,target_id) VALUES(?,?,?,?)',[$actor->id,$m->action,$type,$target]);if($q->rowCount()!==1){throw new \DomainException('audit_row_count');}
            $stage='receipt_insert';$q=$this->query('INSERT INTO mail_feature_operation_runs(request_id,admin_id,action,target_id) VALUES(?,?,?,?)',[$requestId,$actor->id,$m->action,$target]);if($q->rowCount()!==1){throw new \DomainException('receipt_row_count');}
            $stage='commit';$committing=true;if(!$this->db->commit()){throw new \DomainException('result_unverified');}
            return ['state'=>'applied','action'=>$m->action,'target_id'=>$target,'target_type'=>$type];
        }catch(\Throwable $error){
            try{if($this->db->inTransaction()&&!$this->db->rollBack()){throw new \RuntimeException('rollback_unverified');}}catch(\Throwable $cleanup){throw new FeatureStorageFailure('result_unverified',$stage,$error,$cleanup,$committing);}
            if($committing){throw new FeatureStorageFailure('result_unverified',$stage,$error,null,true);}if($error instanceof \DomainException){throw $error;}throw new FeatureStorageFailure('scoped_operation_failed',$stage,$error,null,false);
        }finally{$this->authority=null;}
    }
    private function mailbox(ScopedMutation $m):string
    {
        $cap=ScopedMutation::OPERATIONS[$m->action];
        if($m->action==='mailbox_create'){
            $domain=$this->row('mailserver.virtual_domains',$m->value('domain_id'));$this->permit($cap,[(string)$domain['id']]);
            MailboxNamespaceGuard::available($this->db,$m->value('local'),$domain);$email=AliasPolicy::registrationAddress($m->value('local'),$domain['name']);
            $q=$this->query('INSERT INTO mailserver.virtual_users(domain_id,email,password,active,quota_bytes,auth_epoch,created_at) VALUES(?,?,?,0,0,1,CURRENT_TIMESTAMP)',[$domain['id'],$email,$m->value('hash')]);
            if($q->rowCount()!==1){throw new \DomainException('write_row_count');}return $this->db->lastInsertId();
        }
        $row=$this->row('mailserver.virtual_users',$m->value('id'));$this->permit($cap,[(string)$row['domain_id']]);
        AdminMailPolicy::confirmation($row['email'],$m->value('confirm'));AdminMailPolicy::protectMailbox($row['email']);
        if($m->action==='mailbox_quota'){
            if((string)$row['active']!=='1'||(string)$this->row('mailserver.virtual_domains',(string)$row['domain_id'])['active']!=='1'){throw new \DomainException('inactive_mailbox');}
            $bytes=(string)$row['quota_bytes'];ScopedAdminQuery::id($bytes,true);
            if(strlen($bytes)>strlen((string)PHP_INT_MAX)||(strlen($bytes)===strlen((string)PHP_INT_MAX)&&strcmp($bytes,(string)PHP_INT_MAX)>0)){throw new \DomainException('quota_integer_range');}
            $current=(int)$bytes;$usage=$this->usage->lookup((string)$row['id'],$row['email'],$current,time());
            if(!is_int($usage['used_bytes_upper_bound']??null)||$usage['used_bytes_upper_bound']<0||($usage['enforcement_verified']??null)!==true){throw new \DomainException('quota_backend_unverified');}
            $input=[];foreach(['expected_bytes','mode','limit_kib','confirm_unlimited'] as $field){$input[$field]=$m->value($field);}
            $value=MailboxQuotaChange::plan($input,$current,$usage['used_bytes_upper_bound'],true);
            if($value!==$current&&$this->query('UPDATE mailserver.virtual_users SET quota_bytes=? WHERE id=? AND quota_bytes=?',[$value,$row['id'],$current])->rowCount()!==1){throw new \DomainException('write_row_count');}
            return (string)$row['id'];
        }
        if($m->action==='mailbox_state'&&(string)$row['active']===($m->value('enabled')?'1':'0')){return (string)$row['id'];}
        if($m->action==='mailbox_state'&&$m->value('enabled')&&(string)$this->row('mailserver.virtual_domains',(string)$row['domain_id'])['active']!=='1'){throw new \DomainException('inactive_domain');}
        if((string)$row['auth_epoch']==='18446744073709551615'){throw new \DomainException('epoch_exhausted');}
        $field=$m->action==='mailbox_state'?'active':'password';$value=$m->action==='mailbox_state'?($m->value('enabled')?1:0):$m->value('hash');
        if($this->query('UPDATE mailserver.virtual_users SET auth_epoch=auth_epoch+1,'.$field.'=? WHERE id=?',[$value,$row['id']])->rowCount()!==1){throw new \DomainException('write_row_count');}
        $epoch=$this->query('SELECT auth_epoch FROM mailserver.virtual_users WHERE id=?',[$row['id']])->fetchColumn();AdminMailPolicy::requireEpochAdvance((string)$row['auth_epoch'],(string)$epoch);return (string)$row['id'];
    }
    private function destination(string $id,string $cap,string $sourceDomain):array
    {
        $target=$this->row('mailserver.virtual_users',$id);$this->permit($cap,[$sourceDomain,(string)$target['domain_id']]);$domain=$this->row('mailserver.virtual_domains',(string)$target['domain_id']);
        if((string)$target['active']!=='1'||(string)$domain['active']!=='1'){throw new \DomainException('inactive_destination');}
        if(strcasecmp(explode('@',$target['email'],2)[1]??'',$domain['name'])!==0){throw new \DomainException('invalid_binding');}return $target;
    }
    private function alias(ScopedMutation $m):string
    {
        $cap=ScopedMutation::OPERATIONS[$m->action];
        if($m->action==='alias_create'){
            $domain=$this->row('mailserver.virtual_domains',$m->value('domain_id'));$this->permit($cap,[(string)$domain['id']]);
            $target=$this->destination($m->value('destination_id'),$cap,(string)$domain['id']);MailboxNamespaceGuard::available($this->db,$m->value('local'),$domain);
            $q=$this->query('INSERT INTO mailserver.virtual_aliases(domain_id,source,destination,active,created_at) VALUES(?,?,?,0,CURRENT_TIMESTAMP)',[$domain['id'],AliasPolicy::registrationAddress($m->value('local'),$domain['name']),$target['email']]);
            if($q->rowCount()!==1){throw new \DomainException('write_row_count');}return $this->db->lastInsertId();
        }
        $row=$this->row('mailserver.virtual_aliases',$m->value('id'));$this->permit($cap,[(string)$row['domain_id']]);AdminMailPolicy::confirmation($row['source'],$m->value('confirm'));AdminMailPolicy::address($row['source']);
        $owner=$this->query('SELECT user_id FROM mail_owned_aliases WHERE virtual_alias_id=? FOR UPDATE',[$row['id']])->fetchColumn();
        if($m->action==='alias_destination'){
            if($owner!==false){throw new \DomainException('owned_alias_binding');}$target=$this->destination($m->value('destination_id'),$cap,(string)$row['domain_id']);
            $this->query('UPDATE mailserver.virtual_aliases SET destination=? WHERE id=?',[$target['email'],$row['id']]);
        }else{
            if($m->value('enabled')){
                if((string)$this->row('mailserver.virtual_domains',(string)$row['domain_id'])['active']!=='1'){throw new \DomainException('inactive_domain');}
                $id=$this->query('SELECT id FROM mailserver.virtual_users WHERE email=?',[$row['destination']])->fetchColumn();if($id===false){throw new \DomainException('local_destination_required');}
                $this->destination((string)$id,$cap,(string)$row['domain_id']);
            }
            $this->query('UPDATE mailserver.virtual_aliases SET active=? WHERE id=?',[$m->value('enabled')?1:0,$row['id']]);
        }
        return (string)$row['id'];
    }
}
