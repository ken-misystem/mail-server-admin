<?php
declare(strict_types=1);
namespace MailServer\GeneralAccounts;
use PDO;

/** All owner IDs are resolved from the verified Roundcube session, never form IDs. */
final class OwnerAppPasswords
{
    public function __construct(private PDO $db) {}
    private function owner(string $email,bool $lock=false):string
    {
        if(!preg_match('/\A[\x21-\x7e]{3,254}\z/D',$email) || substr_count($email,'@')!==1)throw new \DomainException('owner_identity');
        [$local,$domain]=explode('@',$email,2);
        $q=$this->db->prepare('SELECT u.id FROM virtual_users u JOIN virtual_domains d ON d.id=u.domain_id WHERE u.active=1 AND d.active=1 AND '
            .'(u.email=? OR (u.email=CONCAT(?,\'@\',d.name) AND EXISTS(SELECT 1 FROM virtual_domain_aliases a WHERE a.alias_domain=? AND a.target_domain_id=d.id AND a.active=1)))'.($lock?' FOR UPDATE':''));
        $q->execute([$email,$local,$domain]);$rows=$q->fetchAll(PDO::FETCH_COLUMN);
        if(count($rows)!==1 || !preg_match('/\A[1-9][0-9]{0,19}\z/D',(string)$rows[0]))throw new \DomainException('owner_inactive_or_ambiguous');
        return (string)$rows[0];
    }
    public function listing(string $email,?string $before=null):array
    {
        $owner=$this->owner($email);
        if($before!==null && !preg_match('/\A[1-9][0-9]{0,19}\z/D',$before))throw new \DomainException('invalid_cursor');
        $q=$this->db->prepare('SELECT id,label,created_at,revoked_at,last_used_at FROM app_passwords WHERE user_id=?'.($before===null?'':' AND id<?').' ORDER BY id DESC LIMIT 51');
        $q->execute($before===null?[$owner]:[$owner,$before]);$rows=$q->fetchAll(PDO::FETCH_ASSOC);
        $more=count($rows)>50;$rows=array_slice($rows,0,50);
        return ['items'=>$rows,'next'=>$more?(string)$rows[49]['id']:null];
    }
    public static function material(string $label):array
    {
        $label=trim($label);
        if($label==='' || strlen($label)>400 || preg_match('//u',$label)!==1
            || preg_match('/[\x00-\x1f\x7f]/',$label) || preg_match_all('/./us',$label)>100)throw new \DomainException('invalid_label');
        if(!defined('PASSWORD_ARGON2ID'))throw new \RuntimeException('argon2id_unavailable');
        $selector=bin2hex(random_bytes(16));
        $credential='misp_'.$selector.'_'.rtrim(strtr(base64_encode(random_bytes(32)),'+/','-_'),'=');
        $hash='{ARGON2ID}'.password_hash($credential,PASSWORD_ARGON2ID);
        if(strlen($hash)>255 || !str_starts_with($hash,'{ARGON2ID}$argon2id$v=19$'))throw new \RuntimeException('argon2id_format');
        return [$label,$selector,$credential,$hash];
    }
    public function issue(string $email,string $label):string
    {
        [$label,$selector,$credential,$hash]=self::material($label);
        if($this->db->inTransaction())throw new \RuntimeException('nested_transaction');
        $this->db->beginTransaction();
        try {
            $owner=$this->owner($email,true);
            $q=$this->db->prepare('INSERT INTO app_passwords(user_id,selector,password_hash,label) VALUES(?,UNHEX(?),?,?)');
            $q->execute([$owner,$selector,$hash,$label]);
            if($q->rowCount()!==1 || !$this->db->commit())throw new \RuntimeException('issue_commit_unverified');
            return $credential; // One authenticated response only, never the list or diagnostics.
        } catch(\Throwable $e) {if($this->db->inTransaction())$this->db->rollBack();throw $e;}
        finally {unset($hash,$credential);}
    }
    public function revoke(string $email,string $id):void
    {
        if(!preg_match('/\A[1-9][0-9]{0,19}\z/D',$id))throw new \DomainException('invalid_credential_id');
        if($this->db->inTransaction())throw new \RuntimeException('nested_transaction');
        $this->db->beginTransaction();
        try {
            $owner=$this->owner($email,true);
            $q=$this->db->prepare('SELECT id FROM app_passwords WHERE id=? AND user_id=? FOR UPDATE');
            $q->execute([$id,$owner]);
            $rows=$q->fetchAll(PDO::FETCH_COLUMN);
            if(count($rows)!==1 || (string)$rows[0]!==$id)throw new \DomainException('credential_not_owned');
            $q=$this->db->prepare('UPDATE app_passwords SET revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP(6)) WHERE id=? AND user_id=?');
            $q->execute([$id,$owner]);
            if(!in_array($q->rowCount(),[0,1],true) || !$this->db->commit())throw new \RuntimeException('revoke_commit_unverified');
        }catch(\Throwable $e){if($this->db->inTransaction())$this->db->rollBack();throw $e;}
    }
}
