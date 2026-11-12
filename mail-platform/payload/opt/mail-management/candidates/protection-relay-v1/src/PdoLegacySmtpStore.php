<?php
declare(strict_types=1);
namespace MailServer\Management;
use PDO;

final class PdoLegacySmtpStore implements LegacySmtpStore
{
    private const PROJECTION='c.id,c.login_id,c.user_id,c.enabled,c.revision,c.created_at,c.updated_at,COALESCE(c.sender_address,u.email) AS sender_address';
    public function __construct(private readonly PDO $db)
    { $db->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);$db->setAttribute(PDO::ATTR_EMULATE_PREPARES,false); }
    private function actor(AdminUser $actor): void
    {
        if (!$actor->active||!$actor->systemAdmin) { throw new \DomainException('not_authorized'); }
        $q=$this->db->prepare('SELECT id,email,active,is_system_admin,auth_epoch FROM mail_admin_users WHERE id=?');$q->execute([$actor->id]);$row=$q->fetch(PDO::FETCH_ASSOC);
        if (!is_array($row)||(string)$row['active']!=='1'||(string)$row['is_system_admin']!=='1'
            ||(string)$row['auth_epoch']!==$actor->epoch||$row['email']!==$actor->getUserIdentifier()) { throw new \DomainException('admin_session_changed'); }
    }
    public function overview(AdminUser $actor,?string $before=null):array
    {
        if ($this->db->inTransaction()) { throw new \DomainException('transaction_unavailable'); }
        if ($before!==null) { LegacySmtpMutation::number($before); }
        $stage='read_begin';
        try {
            $this->db->exec('START TRANSACTION READ ONLY');$stage='read_actor';$this->actor($actor);
            $stage='read_rows';
            $q=$this->db->prepare('SET STATEMENT max_statement_time=2 FOR SELECT '.self::PROJECTION
                .' FROM mail_legacy_smtp_credentials c FORCE INDEX(PRIMARY) LEFT JOIN mailserver.virtual_users u ON u.id=c.user_id'
                .($before===null?'':' WHERE c.id<CAST(? AS UNSIGNED)').' ORDER BY c.id DESC LIMIT 51');
            $q->execute($before===null?[]:[$before]);$rows=$q->fetchAll(PDO::FETCH_ASSOC);
            if (count($rows)>51) { throw new \DomainException('row_bound'); }
            $more=count($rows)===51;if($more){array_pop($rows);}
            foreach($rows as$row){LegacySmtpMutation::number((string)$row['id']);LegacySmtpMutation::number((string)$row['revision']);LegacySmtpMutation::login($row['login_id']);}
            $stage='read_close';if(!$this->db->rollBack()){throw new \RuntimeException('read_close');}
            return ['rows'=>$rows,'next_before'=>$more?(string)$rows[count($rows)-1]['id']:null];
        }catch(\Throwable $e){$this->failed($e,$stage);}
    }
    public function save(AdminUser $actor,LegacySmtpMutation $m):void
    {
        if ($this->db->inTransaction()) { throw new \DomainException('transaction_unavailable'); }
        $stage='begin';$committing=false;
        try {
            if(!$this->db->beginTransaction()){throw new \RuntimeException('transaction_unavailable');}
            $stage='locks';
            foreach(['alias_namespace','admin_roles']as$name){$q=$this->db->prepare('SELECT name FROM mail_management_locks WHERE name=? FOR UPDATE');$q->execute([$name]);if($q->fetchColumn()!==$name){throw new \DomainException('schema_not_ready');}}
            $stage='actor';$this->actor($actor);
            if($m->action==='create'){
                $stage='duplicate';$q=$this->db->prepare('SELECT id FROM mail_legacy_smtp_credentials WHERE login_id=? FOR UPDATE');$q->execute([$m->value('login')]);if($q->fetchColumn()!==false){throw new \DomainException('duplicate_login');}
                $stage='insert';$q=$this->db->prepare('INSERT INTO mail_legacy_smtp_credentials(login_id,sender_address,password_hash,enabled,revision) VALUES(?,?,?,0,1)');$q->execute([$m->value('login'),$m->value('sender'),$m->value('hash')]);
                if($q->rowCount()!==1){throw new \DomainException('row_count');}$target=LegacySmtpMutation::number($this->db->lastInsertId());
            }else{
                $stage='target';$q=$this->db->prepare('SELECT id,login_id,user_id,sender_address,enabled,revision FROM mail_legacy_smtp_credentials WHERE id=? FOR UPDATE');$q->execute([$m->value('id')]);$row=$q->fetch(PDO::FETCH_ASSOC);
                if(!is_array($row)||!hash_equals($row['login_id'],$m->value('confirm'))){throw new \DomainException('confirmation_required');}
                if((string)$row['revision']!==$m->value('revision')){throw new \DomainException('revision_changed');}
                if($m->action==='state'&&$m->value('enabled')&&$row['user_id']!==null){
                    $stage='owner';$q=$this->db->prepare('SELECT u.active,d.active AS domain_active FROM mailserver.virtual_users u JOIN mailserver.virtual_domains d ON d.id=u.domain_id WHERE u.id=? FOR UPDATE');$q->execute([$row['user_id']]);$owner=$q->fetch(PDO::FETCH_ASSOC);
                    if(!is_array($owner)||(string)$owner['active']!=='1'||(string)$owner['domain_active']!=='1'){throw new \DomainException('inactive_owner');}
                }
                if($m->action==='state'&&$m->value('enabled')&&$row['user_id']===null){
                    if(!is_string($row['sender_address']) || LegacySmtpMutation::sender($row['sender_address'])!==$row['sender_address']){
                        throw new \DomainException('invalid_sender');
                    }
                }
                $stage='update';
                $q=$this->db->prepare('UPDATE mail_legacy_smtp_credentials SET '.($m->action==='password'?'password_hash=?':'enabled=?')
                    .',revision=revision+1 WHERE id=? AND revision=? AND revision<18446744073709551615');
                $q->execute([$m->action==='password'?$m->value('hash'):($m->value('enabled')?1:0),$row['id'],$m->value('revision')]);
                if($q->rowCount()!==1){throw new \DomainException('revision_changed');}$target=(string)$row['id'];
            }
            $stage='audit';$q=$this->db->prepare('INSERT INTO mail_admin_audit(admin_id,action,target_type,target_id) VALUES(?,?,?,?)');
            $q->execute([$actor->id,'legacy_smtp_'.$m->action,'legacy_smtp',$target]);if($q->rowCount()!==1){throw new \DomainException('row_count');}
            $stage='commit';$committing=true;if(!$this->db->commit()){throw new \RuntimeException('commit_unverified');}
        }catch(\Throwable $e){$this->failed($e,$stage,$committing);}
    }
    private function failed(\Throwable $e,string $stage,bool $committing=false):never
    {
        $cleanup=null;try{if($this->db->inTransaction()&&!$this->db->rollBack()){throw new \RuntimeException('rollback_failed');}}
        catch(\Throwable $failure){$cleanup=$failure;}
        $safe=['not_authorized','admin_session_changed','inactive_owner','invalid_sender','duplicate_login','confirmation_required','revision_changed','schema_not_ready'];
        if(!$committing&&$cleanup===null&&$e instanceof \DomainException&&in_array($e->getMessage(),$safe,true)){throw $e;}
        throw new LegacySmtpFailure($stage,$e,$cleanup);
    }
}
