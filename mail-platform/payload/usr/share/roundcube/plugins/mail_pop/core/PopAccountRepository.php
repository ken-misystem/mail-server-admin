<?php
declare(strict_types=1);
namespace MailServer\Pop;
use PDO;

/** Session actor only, same active-mailbox/domain-alias binding as existing AliasRepository. */
final class PopAccountRepository
{
    public function __construct(private readonly PDO $db,private readonly \Closure $seal)
    {
        $db->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
        $db->setAttribute(PDO::ATTR_EMULATE_PREPARES,false);
    }
    public function overview(string $actor):array
    {
        return $this->transaction(false,function()use($actor):array{
            $account=$this->account($actor,false);
            $settings=$this->settings((string)$account['id']);
            $list=$this->db->prepare('SELECT id,remote_host,remote_port,remote_username,label,enabled,last_success_at,last_result '
                .'FROM mail_pop_accounts WHERE user_id=? ORDER BY id LIMIT 101');
            $list->execute([$account['id']]);$rows=$list->fetchAll(PDO::FETCH_ASSOC);
            if(count($rows)>100)throw new \DomainException('pop_storage_unavailable');
            foreach($rows as &$row){
                $row['id']=(string)$row['id'];$row['enabled']=(int)$row['enabled']===1;
                // Actor/account binding comes from the server, never an RPC user_id.
                $history=$this->db->prepare("SELECT DATE_FORMAT(h.started_at,'%Y-%m-%dT%H:%i:%sZ') AS started_at,"
                    ."DATE_FORMAT(h.finished_at,'%Y-%m-%dT%H:%i:%sZ') AS finished_at,h.outcome,h.phase,h.detail_code,h.fetched_count,h.native_exit "
                    .'FROM mail_pop_run_history h JOIN mail_pop_accounts a ON a.id=h.account_id '
                    .'WHERE a.user_id=? AND a.id=? ORDER BY h.id DESC LIMIT 10');
                $history->execute([$account['id'],$row['id']]);$row['run_history']=$history->fetchAll(PDO::FETCH_ASSOC);
                foreach($row['run_history'] as &$run){
                    foreach(['fetched_count','native_exit'] as $key)$run[$key]=$run[$key]===null?null:(int)$run[$key];
                }
                unset($run);
            }
            unset($row);
            return ['accounts'=>$rows,'usage'=>['count'=>count($rows),'limit'=>$settings['limit']],
                'poll_seconds'=>$settings['seconds']]; // Never SELECT ciphertext/reference/key or return a stored password.
        });
    }
    public function create(string $actor,string $host,int $port,string $username,string $label,#[\SensitiveParameter]string $password):string
    {
        $host=PopSourcePolicy::host($host);$port=PopSourcePolicy::port($port);
        PopSourcePolicy::username($username);self::label($label);PopSourcePolicy::password($password);
        return $this->transaction(true,function()use($actor,$host,$port,$username,$label,$password):string{
            $account=$this->account($actor,true);$settings=$this->settings((string)$account['id']);
            $count=$this->db->prepare('SELECT COUNT(*) FROM mail_pop_accounts WHERE user_id=?');$count->execute([$account['id']]);
            if($settings['limit']<1 || (int)$count->fetchColumn()>=$settings['limit'])throw new \DomainException('pop_limit');
            $box=$this->box($password);$reference=bin2hex(random_bytes(32));
            $insert=$this->db->prepare('INSERT INTO mail_pop_accounts(user_id,remote_host,remote_port,remote_username,label,secret_reference,enabled) VALUES(?,?,?,?,?,?,0)');
            $insert->execute([$account['id'],$host,$port,$username,$label,$reference]);
            $id=PopSourcePolicy::accountId($this->db->lastInsertId());
            $this->db->prepare('INSERT INTO mail_pop_password_boxes(reference,account_id,sealed_password) VALUES(?,?,?)')->execute([$reference,$id,$box]);
            return $id; // New sources are paused, never start polling just because a password was saved.
        });
    }
    public function setEnabled(string $actor,string $id,bool $enabled):void
    {
        $this->transaction(true,function()use($actor,$id,$enabled):void{
            $account=$this->account($actor,true);$row=$this->owned((string)$account['id'],$id);
            if($enabled){
                if($row['last_result']==='source_changed')throw new \DomainException('pop_source_review_required');
                $limit=$this->settings((string)$account['id'])['limit'];
                if($limit<1)throw new \DomainException('pop_limit');
                if((int)$row['enabled']===0){
                    $active=$this->db->prepare('SELECT COUNT(*) FROM mail_pop_accounts WHERE user_id=? AND enabled=1');
                    $active->execute([$account['id']]);
                    if((int)$active->fetchColumn()>=$limit)throw new \DomainException('pop_limit');
                }
                PopSourcePolicy::host($row['remote_host']);PopSourcePolicy::port((int)$row['remote_port']);
                $present=$this->db->prepare('SELECT reference FROM mail_pop_password_boxes WHERE account_id=? AND reference=?');
                $present->execute([$id,$row['secret_reference']]);
                if($present->fetchColumn()===false)throw new \DomainException('pop_storage_unavailable');
            }
            $this->db->prepare('UPDATE mail_pop_accounts SET enabled=? WHERE id=? AND user_id=?')->execute([(int)$enabled,$id,$account['id']]);
        });
    }
    public function edit(string $actor,string $id,string $host,int $port,string $username,string $label,#[\SensitiveParameter]string $password):void
    {
        $host=PopSourcePolicy::host($host);$port=PopSourcePolicy::port($port);
        PopSourcePolicy::username($username);self::label($label);
        if($password!=='')PopSourcePolicy::password($password);
        $this->transaction(true,function()use($actor,$id,$host,$port,$username,$label,$password):void{
            $account=$this->account($actor,true);$row=$this->owned((string)$account['id'],$id);
            if($this->settings((string)$account['id'])['limit']<1)throw new \DomainException('pop_limit');
            $changed=$host!==$row['remote_host'] || $port!==(int)$row['remote_port'] || $username!==$row['remote_username'];
            if($changed && $password==='')throw new \DomainException('pop_source_password_required');
            $present=$this->db->prepare('SELECT reference FROM mail_pop_password_boxes WHERE account_id=? AND reference=?');
            $present->execute([$id,$row['secret_reference']]);
            if($present->fetchColumn()===false)throw new \DomainException('pop_storage_unavailable');
            // Never reuse a different source's history or clear its review latch by editing back.
            $review=$changed || $row['last_result']==='source_changed';
            $sql='UPDATE mail_pop_accounts SET remote_host=?,remote_port=?,remote_username=?,label=?,enabled=0'
                .($review?",last_result='source_changed',last_success_at=NULL":'').' WHERE id=? AND user_id=?';
            $this->db->prepare($sql)->execute([$host,$port,$username,$label,$id,$account['id']]);
            if($password!==''){
                $query=$this->db->prepare('UPDATE mail_pop_password_boxes SET sealed_password=? WHERE account_id=? AND reference=?');
                $query->execute([$this->box($password),$id,$row['secret_reference']]);
                if($query->rowCount()!==1)throw new \DomainException('pop_storage_unavailable');
            }
            // Files/UIDLs are untouched. Source changes require separate history review before enabling.
        });
    }
    public function replacePassword(string $actor,string $id,#[\SensitiveParameter]string $password):void
    {
        PopSourcePolicy::password($password);
        $this->transaction(true,function()use($actor,$id,$password):void{
            $account=$this->account($actor,true);$row=$this->owned((string)$account['id'],$id);
            if($this->settings((string)$account['id'])['limit']<1)throw new \DomainException('pop_limit');
            // Source identity/ID/UIDL stay fixed; password replacement pauses retrieval.
            $this->db->prepare('UPDATE mail_pop_accounts SET enabled=0 WHERE id=? AND user_id=?')->execute([$id,$account['id']]);
            $query=$this->db->prepare('UPDATE mail_pop_password_boxes SET sealed_password=? WHERE account_id=? AND reference=?');
            $query->execute([$this->box($password),$id,$row['secret_reference']]);
            if($query->rowCount()!==1)throw new \DomainException('pop_storage_unavailable');
        });
    }
    public function remove(string $actor,string $id):void
    {
        $this->transaction(true,function()use($actor,$id):void{
            $account=$this->account($actor,true);$row=$this->owned((string)$account['id'],$id);
            if((int)$row['enabled']!==0)throw new \DomainException('pop_pause_required');
            $this->db->prepare('DELETE FROM mail_pop_password_boxes WHERE account_id=? AND reference=?')->execute([$id,$row['secret_reference']]);
            $query=$this->db->prepare('DELETE FROM mail_pop_accounts WHERE id=? AND user_id=? AND enabled=0');$query->execute([$id,$account['id']]);
            if($query->rowCount()!==1)throw new \DomainException('pop_storage_unavailable');
            // Settings only: no source mail, Maildir, worker directory or retained UIDL deletion.
        });
    }
    private function account(string $mailbox,bool $locked):array
    {
        $login=explode('@',$mailbox);if(count($login)!==2 || $login[0]==='' || $login[1]==='')throw new \DomainException('not_authorized');
        $query=$this->db->prepare('SELECT u.id,u.email,d.name AS domain_name FROM mailserver.virtual_users u '
            .'JOIN mailserver.virtual_domains d ON d.id=u.domain_id WHERE u.active=1 AND d.active=1 AND (u.email=? OR '
            .'(u.email=CONCAT(?,\'@\',d.name) AND EXISTS(SELECT 1 FROM mailserver.virtual_domain_aliases a '
            .'WHERE a.alias_domain=? AND a.target_domain_id=d.id AND a.active=1)))'.($locked?' FOR UPDATE':''));
        $query->execute([$mailbox,$login[0],$login[1]]);$rows=$query->fetchAll(PDO::FETCH_ASSOC);
        if(count($rows)!==1)throw new \DomainException('not_authorized');
        PopSourcePolicy::recipient($rows[0]['email']);
        if(strcasecmp(explode('@',$rows[0]['email'],2)[1],$rows[0]['domain_name'])!==0)throw new \DomainException('not_authorized');
        return $rows[0];
    }
    private function settings(string $id):array
    {
        $query=$this->db->prepare('SELECT pop_account_limit,pop_poll_seconds FROM mail_user_settings WHERE user_id=?');$query->execute([$id]);$row=$query->fetch(PDO::FETCH_ASSOC);
        $limit=$row===false?0:(int)$row['pop_account_limit'];$seconds=$row===false?300:(int)$row['pop_poll_seconds'];
        if($limit<0 || $limit>100 || $seconds<60 || $seconds>86400)throw new \DomainException('pop_storage_unavailable');
        return ['limit'=>$limit,'seconds'=>$seconds];
    }
    private function owned(string $owner,string $id):array
    {
        PopSourcePolicy::accountId($id);
        $query=$this->db->prepare('SELECT user_id,remote_host,remote_port,remote_username,secret_reference,enabled,last_result FROM mail_pop_accounts WHERE id=? FOR UPDATE');$query->execute([$id]);$row=$query->fetch(PDO::FETCH_ASSOC);
        if(!$row || !hash_equals($owner,(string)$row['user_id']))throw new \DomainException('not_authorized');return $row;
    }
    private function box(#[\SensitiveParameter]string $password):string
    {
        $box=($this->seal)($password);if(!is_string($box) || strlen($box)!==strlen($password)+48)throw new \DomainException('pop_storage_unavailable');return $box;
    }
    private static function label(string $label):void
    {
        if($label==='' || strlen($label)>128 || preg_match('//u',$label)!==1 || preg_match('/[\x00-\x1f\x7f]/',$label))throw new \DomainException('invalid_request');
    }
    private function transaction(bool $write,callable $action):mixed
    {
        if($this->db->inTransaction())throw new \DomainException('pop_storage_unavailable');$committing=false;
        try{
            if($write){
                if(!$this->db->beginTransaction())throw new \DomainException('result_unverified');
                $lock=$this->db->query("SELECT name FROM mail_management_locks WHERE name='alias_namespace' FOR UPDATE");
                if($lock->fetchColumn()!=='alias_namespace')throw new \DomainException('pop_storage_unavailable');
            }else{$this->db->exec('START TRANSACTION READ ONLY');}
            $result=$action();
            if($write){$committing=true;if(!$this->db->commit())throw new \DomainException('result_unverified');}
            else{$this->db->rollBack();}return $result;
        }catch(\Throwable $error){
            try{if($this->db->inTransaction())$this->db->rollBack();}catch(\Throwable){throw new \DomainException('result_unverified');}
            if($committing)throw new \DomainException('result_unverified');
            if($error instanceof \DomainException)throw $error;
            throw new \DomainException($write?'result_unverified':'pop_storage_unavailable');
        }
    }
}
