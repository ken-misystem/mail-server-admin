<?php
declare(strict_types=1);
namespace MailServer\Management;
use PDO;

final class PdoDomainDeliveryStore implements DomainDeliveryStore
{
    public function __construct(private readonly PDO $db)
    { $db->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);$db->setAttribute(PDO::ATTR_EMULATE_PREPARES,false); }

    private function actor(AdminUser $actor,bool $locked): void
    {
        if (!$actor->active||!$actor->systemAdmin) { throw new \DomainException('not_authorized'); }
        $q=$this->db->prepare('SELECT email,active,is_system_admin,auth_epoch FROM mail_admin_users WHERE id=?'.($locked?' FOR UPDATE':''));
        $q->execute([$actor->id]);$r=$q->fetch(PDO::FETCH_ASSOC);
        if (!$r||$r['email']!==$actor->getUserIdentifier()||(string)$r['active']!=='1'
            ||(string)$r['is_system_admin']!=='1'||(string)$r['auth_epoch']!==$actor->epoch) { throw new \DomainException('admin_session_changed'); }
    }

    public static function decimal(string $v,bool $zero=false): bool
    { return (bool)preg_match($zero?'/^(?:0|[1-9][0-9]{0,19})$/D':'/^[1-9][0-9]{0,19}$/D',$v)
        &&(strlen($v)<20||strcmp($v,'18446744073709551615')<=0); }

    public function overview(AdminUser $actor): array
    {
        if ($this->db->inTransaction()) { throw new \DomainException('nested_transaction'); }
        try {
            $this->db->exec('START TRANSACTION READ ONLY'); $this->actor($actor,false);
            $q=$this->db->query('SET STATEMENT max_statement_time=2 FOR SELECT d.id,d.name,d.active,'
                .'COALESCE(p.follow_mx,0) AS follow_mx,COALESCE(p.revision,0) AS revision '
                .'FROM mailserver.virtual_domains d LEFT JOIN mail_domain_delivery_policy p ON p.domain_id=d.id '
                .'ORDER BY d.name LIMIT 201');
            $rows=$q->fetchAll(PDO::FETCH_ASSOC);$this->db->rollBack();
            return ['rows'=>array_slice($rows,0,200),'truncated'=>count($rows)>200];
        } catch (\Throwable $e) { $this->fail($e,'overview',false); }
    }

    public function save(AdminUser $actor,string $id,bool $followMx,string $version,string $confirm): void
    {
        if (!self::decimal($id)||!self::decimal($version,true)||$this->db->inTransaction()) { throw new \DomainException('invalid_routing_input'); }
        $phase='begin';$committing=false;
        try {
            if (!$this->db->beginTransaction()) { throw new \DomainException('transaction_unavailable'); }
            // Reuse established lock order; no inverse domain/actor locking against existing mutations.
            foreach (['alias_namespace','admin_roles'] as $name) {
                $q=$this->db->prepare('SELECT name FROM mail_management_locks WHERE name=? FOR UPDATE');$q->execute([$name]);
                if ($q->fetchColumn()!==$name) { throw new \DomainException('schema_not_ready'); }
            }
            $phase='actor';$this->actor($actor,true);
            $phase='domain';$q=$this->db->prepare('SELECT id,name,active FROM mailserver.virtual_domains WHERE id=? FOR UPDATE');
            $q->execute([$id]);$d=$q->fetch(PDO::FETCH_ASSOC);
            if (!$d||(string)$d['active']!=='1') { throw new \DomainException('inactive_domain'); }
            AdminMailPolicy::confirmation($d['name'],$confirm);
            $q=$this->db->prepare('SELECT follow_mx,revision FROM mail_domain_delivery_policy WHERE domain_id=? FOR UPDATE');
            $q->execute([$id]);$current=$q->fetch(PDO::FETCH_ASSOC);
            if (($current?(string)$current['revision']:'0')!==$version) { throw new \DomainException('routing_version_changed'); }
            if ($current&&(string)$current['follow_mx']===($followMx?'1':'0')) { $this->db->rollBack();return; }
            if ($version==='18446744073709551615') { throw new \DomainException('revision_exhausted'); }
            $phase='save';
            if ($current) {
                $q=$this->db->prepare('UPDATE mail_domain_delivery_policy SET follow_mx=?,revision=revision+1 WHERE domain_id=?');
                $q->execute([$followMx?1:0,$id]);
            } else {
                $q=$this->db->prepare('INSERT INTO mail_domain_delivery_policy(domain_id,follow_mx,revision) VALUES(?,?,1)');
                $q->execute([$id,$followMx?1:0]);
            }
            $phase='audit';$q=$this->db->prepare('INSERT INTO mail_admin_audit(admin_id,action,target_type,target_id) VALUES(?,?,?,?)');
            $q->execute([$actor->id,$followMx?'domain_mx_follow_enabled':'domain_mx_follow_disabled','domain',$id]);
            $phase='commit';$committing=true;
            if (!$this->db->commit()) { throw new \DomainException('routing_result_unverified'); }
        } catch (\Throwable $e) { $this->fail($e,$phase,$committing); }
    }

    private function fail(\Throwable $e,string $phase,bool $uncertain): never
    {
        try { if ($this->db->inTransaction()) { $this->db->rollBack(); } }
        catch (\Throwable $rollback) { throw new DomainDeliveryFailure($phase,$e,true,$rollback); }
        if (!$uncertain&&$e instanceof \DomainException) { throw $e; }
        throw new DomainDeliveryFailure($phase,$e,$uncertain);
    }
}
