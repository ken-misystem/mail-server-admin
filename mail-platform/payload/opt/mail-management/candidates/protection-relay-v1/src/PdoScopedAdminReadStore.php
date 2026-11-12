<?php
declare(strict_types=1);
namespace MailServer\Management;
use PDO;

/** Fixed projections, read-only snapshot, live epoch and EXISTS before LIMIT. No secrets. */
final class PdoScopedAdminReadStore implements ScopedAdminReadStore
{
    public function __construct(private readonly PDO $db, private readonly ?QuotaUsageProvider $usage = null)
    {
        $db->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
        $db->setAttribute(PDO::ATTR_EMULATE_PREPARES,false);
    }
    private function query(string $sql,array $args=[]): \PDOStatement
    {
        $q=$this->db->prepare('SET STATEMENT max_statement_time=2 FOR '.$sql);
        $q->execute($args); return $q;
    }
    private function read(AdminUser $actor,callable $work): array
    {
        if (!$actor->active || $this->db->inTransaction()) { throw new \DomainException('not_authorized'); }
        $stage='scoped_read_begin';
        try {
            $this->db->exec('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
            $this->db->exec('START TRANSACTION READ ONLY');
            $stage='scoped_actor_refresh';
            $current=$this->query('SELECT active,is_system_admin,auth_epoch,email FROM mail_admin_users WHERE id=?',[$actor->id])->fetch(PDO::FETCH_ASSOC);
            if (!$current || (string)$current['active']!=='1' || (string)$current['auth_epoch']!==$actor->epoch
                || $current['email']!==$actor->getUserIdentifier() || ((string)$current['is_system_admin']==='1')!==$actor->systemAdmin) { throw new \DomainException('admin_session_changed'); }
            $stage='scoped_rows'; $out=$work();
            $stage='scoped_read_close'; if (!$this->db->rollBack()) { throw new \RuntimeException('read_close'); }
            return $out;
        } catch (\Throwable $error) {
            try { if ($this->db->inTransaction() && !$this->db->rollBack()) { throw new \RuntimeException('rollback_unverified'); } }
            catch (\Throwable $cleanup) { throw new FeatureStorageFailure('scoped_read_failed',$stage,$error,$cleanup,false); }
            if ($error instanceof \DomainException) { throw $error; }
            throw new FeatureStorageFailure('scoped_read_failed',$stage,$error,null,false);
        }
    }
    private function permission(AdminUser $actor,string $operation,array &$args): string
    {
        if ($actor->systemAdmin) { return '1=1'; }
        $args[]=$actor->id; $args[]=$operation;
        return 'EXISTS(SELECT 1 FROM mail_feature_domain_grants g WHERE g.admin_id=? AND g.domain_id=d.id AND g.active=1 AND g.capability=?)';
    }
    public function domains(AdminUser $actor): array
    {
        return $this->read($actor,function()use($actor):array {
            // Only domains having at least one live capability are named to a delegate.
            $args=[]; $where='1=1';
            if (!$actor->systemAdmin) { $where='EXISTS(SELECT 1 FROM mail_feature_domain_grants g WHERE g.admin_id=? AND g.domain_id=d.id AND g.active=1)'; $args[]=$actor->id; }
            $rows=$this->query('SELECT d.id,d.name,d.active FROM mailserver.virtual_domains d WHERE '.$where.' ORDER BY d.id LIMIT 10001',$args)->fetchAll(PDO::FETCH_ASSOC);
            if (count($rows)>10000) { throw new \DomainException('domain_inventory_bound'); }
            $grants=[];
            if (!$actor->systemAdmin) {
                $items=$this->query('SELECT domain_id,capability FROM mail_feature_domain_grants WHERE admin_id=? AND active=1 ORDER BY domain_id,capability LIMIT 130001',[$actor->id])->fetchAll(PDO::FETCH_ASSOC);
                if(count($items)>130000){throw new \DomainException('grant_inventory_bound');}
                foreach($items as $g){if(!in_array($g['capability'],DomainAuthority::OPERATIONS,true)){throw new \DomainException('invalid_grant_state');}$grants[(string)$g['domain_id']][]=$g['capability'];}
            }
            return array_map(static fn(array $r):array=>['id'=>(string)$r['id'],'name'=>$r['name'],'active'=>(string)$r['active'],
                'capabilities'=>$actor->systemAdmin?DomainAuthority::OPERATIONS:($grants[(string)$r['id']]??[])],$rows);
        });
    }
    public function listing(AdminUser $actor,string $section,array $filter): array
    {
        ScopedAdminQuery::section($section); $filter=ScopedAdminQuery::filter($filter);
        return $this->read($actor,fn():array=>$this->rows($actor,$section,$filter,null));
    }
    public function record(AdminUser $actor,string $section,string $id): ?array
    {
        ScopedAdminQuery::section($section); ScopedAdminQuery::id($id);
        $out=$this->read($actor,fn():array=>$this->rows($actor,$section,ScopedAdminQuery::filter([]),$id));
        return $out['rows'][0]??null; // Identical result for absent and ungranted IDs.
    }
    private function rows(AdminUser $actor,string $section,array $f,?string $id): array
    {
        $operation=ScopedAdminQuery::section($section); $args=[]; $where=[$this->permission($actor,$operation,$args)];
        [$projection,$from,$key,$address,$state]=match($section){
            'mailboxes','usage'=>['u.id,u.domain_id,u.email,u.active,u.quota_bytes,d.name AS domain_name,d.active AS domain_active',
                'mailserver.virtual_users u JOIN mailserver.virtual_domains d ON d.id=u.domain_id','u.id','u.email','u.active'],
            'aliases'=>['a.id,a.domain_id,a.source,a.destination,a.active,d.name AS domain_name,d.active AS domain_active',
                'mailserver.virtual_aliases a JOIN mailserver.virtual_domains d ON d.id=a.domain_id','a.id','a.source','a.active'],
            'forwards'=>["u.id,u.domain_id,u.email AS source,COALESCE(f.destinations,'[]') AS destinations,COALESCE(f.enabled,0) AS active,d.name AS domain_name,d.active AS domain_active",
                'mailserver.virtual_users u JOIN mailserver.virtual_domains d ON d.id=u.domain_id LEFT JOIN mail_feature_forwards f ON f.user_id=u.id','u.id','u.email','COALESCE(f.enabled,0)'],
        };
        if($id!==null){$where[]=$key.'=CAST(? AS UNSIGNED)';$args[]=$id;}
        else{
            $where[]=$key.'>CAST(? AS UNSIGNED)';$args[]=$f['after'];
            if($f['domain_id']!=='0'){$where[]='d.id=?';$args[]=$f['domain_id'];}
            if($f['prefix']!==''){$where[]=$address." LIKE ? ESCAPE '='";$args[]=ScopedAdminQuery::pattern($f['prefix']);}
            if($f['state']!=='any'){$where[]=$state.'=?';$args[]=$f['state'];}
        }
        $size=(int)$f['size'];$limit=$id===null?$size+1:1;
        $rows=$this->query('SELECT '.$projection.' FROM '.$from.' WHERE '.implode(' AND ',$where).' ORDER BY '.$key.' LIMIT '.$limit,$args)->fetchAll(PDO::FETCH_ASSOC);
        if(count($rows)>$limit){throw new \DomainException('row_bound');}
        $more=$id===null&&count($rows)>$size;if($more){array_pop($rows);}
        foreach($rows as &$row){
            foreach(['id','domain_id','active','domain_active'] as $field){$row[$field]=(string)$row[$field];}
            if(isset($row['quota_bytes'])){$row['quota_bytes']=(string)$row['quota_bytes'];}
            if($section==='forwards'){$row['destinations']=ForwardPlan::targets(json_decode($row['destinations'],true,32,JSON_THROW_ON_ERROR));}
            if($section==='usage'){
                $row['usage']=null;$row['usage_reason']='quota_backend_unverified';
                if($this->usage!==null){
                    try{
                        $bytes=$row['quota_bytes'];if(!preg_match('/^(?:0|[1-9][0-9]{0,18})$/D',$bytes)||strlen($bytes)>strlen((string)PHP_INT_MAX)||(strlen($bytes)===strlen((string)PHP_INT_MAX)&&strcmp($bytes,(string)PHP_INT_MAX)>0)){throw new \DomainException('quota_integer_range');}
                        $row['usage']=$this->usage->lookup($row['id'],$row['email'],(int)$bytes,time());$row['usage_reason']=null;
                    }catch(\DomainException $error){$row['usage_reason']=in_array($error->getMessage(),['quota_usage_stale','quota_binding_changed','quota_snapshot_invalid','quota_integer_range'],true)?$error->getMessage():'quota_backend_unverified';}
                }
            }
        }unset($row);
        return ['rows'=>$rows,'next_after'=>$more?(string)$rows[count($rows)-1]['id']:null,'filter'=>$f];
    }
}
