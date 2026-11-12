<?php
declare(strict_types=1);
namespace MailServer\Management;
use PDO;

/** MariaDB-only, fixed SELECTs; no authentication secrets or row-lock statements. */
final class PdoAdminAuditStore implements AdminAuditStore
{
    public function __construct(private readonly PDO $db) {}
    public function search(AdminUser $actor,AdminAuditQuery $query,int $now): array
    {
        if(!$actor->active||!$actor->systemAdmin||$this->db->inTransaction())throw new \DomainException('audit_not_authorized');
        $opened=false;$stage='transaction';$error=null;$cleanup=null;$result=null;
        try {
            if($this->db->exec('START TRANSACTION READ ONLY')===false)throw new \DomainException('audit_transaction');
            $opened=true;
            $stage='actor';
            $q=$this->db->prepare('SET STATEMENT max_statement_time=1 FOR SELECT id,email,active,is_system_admin,auth_epoch FROM mail_admin_users WHERE id=CAST(? AS UNSIGNED) LIMIT 1');
            if(!$q||!$q->execute([$actor->id]))throw new \DomainException('audit_actor_query');
            $live=$q->fetch(PDO::FETCH_ASSOC);
            if(!is_array($live)||(string)($live['id']??'')!==$actor->id||($live['email']??null)!==$actor->getUserIdentifier()
                ||(string)($live['active']??'')!=='1'||(string)($live['is_system_admin']??'')!=='1'||(string)($live['auth_epoch']??'')!==$actor->epoch)throw new \DomainException('audit_actor_changed');
            $stage='rows';
            $sql='SET STATEMENT max_statement_time=1 FOR SELECT id,admin_id,action,target_type,target_id,UNIX_TIMESTAMP(created_at) AS occurred_at FROM mail_admin_audit FORCE INDEX(PRIMARY)';
            $params=[];
            if($query->before!==null){$sql.=' WHERE id<CAST(? AS UNSIGNED)';$params[]=$query->before;}
            $q=$this->db->prepare($sql.' ORDER BY id DESC LIMIT 201');
            if(!$q||!$q->execute($params))throw new \DomainException('audit_rows_query');
            $rows=$q->fetchAll(PDO::FETCH_ASSOC);
            foreach($rows as&$row){
                foreach(['id','admin_id','target_id']as$key)if(is_int($row[$key]??null))$row[$key]=(string)$row[$key];
                $t=$row['occurred_at']??null;
                if(is_string($t)&&preg_match('/^(0|[1-9][0-9]{0,11})$/D',$t)&&strlen($t)<=12)$row['occurred_at']=(int)$t;
            }
            unset($row);
            $stage='row_validation';$result=$query->select($rows,$now);
        } catch(\Throwable $e){$error=$e;}
        if($opened){
            try {if(!$this->db->inTransaction()||!$this->db->rollBack())throw new \DomainException('audit_close_failed');}
            catch(\Throwable $e){$cleanup=$e;}
        }
        if($error!==null||$cleanup!==null)throw new AdminAuditReadFailure($stage,$error??$cleanup,$error!==null?$cleanup:null);
        return $result;
    }
}
