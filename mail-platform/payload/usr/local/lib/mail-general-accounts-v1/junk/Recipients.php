<?php
declare(strict_types=1);
namespace MailServer\GeneralAccounts;
use PDO;

/** Preference text is decoded by the already reviewed bounded decoder. */
final class Recipients
{
    public function __construct(private PDO $roundcube,private PDO $mail) {}
    private function address(string $value):?string
    {
        $value=strtolower($value);
        return preg_match('/\A[\x21-\x7e]{3,254}\z/D',$value) && substr_count($value,'@')===1
            && !str_starts_with($value,'@') && !str_ends_with($value,'@')?$value:null;
    }
    public function candidates():array
    {
        $rows=$this->roundcube->query('SELECT user_id,username,mail_host,preferences FROM users ORDER BY user_id LIMIT 1001')->fetchAll(PDO::FETCH_ASSOC);
        if(count($rows)>1000)throw new \RuntimeException('recipient_inventory_bound');
        $groups=[];$eligible=[];
        foreach($rows as $row){$email=is_string($row['username']??null)?$this->address($row['username']):null;if($email!==null)$groups[$email][]=$row;}
        $duplicates=[];
        foreach($groups as $email=>$matches){
            $value=$this->select($email,$matches);if($value===null)continue;
            $id=$value['owner_id'];if(isset($eligible[$id]))$duplicates[$id]=true;else $eligible[$id]=$value;
        }
        return array_values(array_diff_key($eligible,$duplicates));
    }
    private function select(string $email,array $rows):?array
    {
        if(count($rows)!==1 || ($rows[0]['mail_host']??null)!=='mx.mi-sys.jp'
            || !\PilotPreferenceDecoder::enabled($rows[0]['preferences']??null))return null;
        [$local,$domain]=explode('@',$email,2);
        $q=$this->mail->prepare('SELECT u.id,u.email,u.active,d.active AS domain_active FROM virtual_users u JOIN virtual_domains d ON d.id=u.domain_id WHERE '
            .'(u.email=? OR (u.email=CONCAT(?,\'@\',d.name) AND EXISTS(SELECT 1 FROM virtual_domain_aliases a WHERE a.alias_domain=? AND a.target_domain_id=d.id AND a.active=1))) LIMIT 2');
        $q->execute([$email,$local,$domain]);$accounts=$q->fetchAll(PDO::FETCH_ASSOC);
        if(count($accounts)!==1 || $this->address($accounts[0]['email'])!==$accounts[0]['email'] || (string)$accounts[0]['active']!=='1'
            || (string)$accounts[0]['domain_active']!=='1')return null;
        foreach([(string)$rows[0]['user_id'],(string)$accounts[0]['id']] as $id){if(!preg_match('/\A[1-9][0-9]{0,19}\z/D',$id))return null;}
        return ['roundcube_id'=>(string)$rows[0]['user_id'],'owner_id'=>(string)$accounts[0]['id'],'email'=>$accounts[0]['email'],'login'=>$email];
    }
    public function stillEligible(array $expected):bool
    {
        if(array_keys($expected)!==['roundcube_id','owner_id','email','login'] || !is_string($expected['email']) || !is_string($expected['login'])
            || $this->address($expected['email'])!==$expected['email'] || $this->address($expected['login'])!==$expected['login'])return false;
        $q=$this->roundcube->prepare('SELECT user_id,username,mail_host,preferences FROM users WHERE username=? LIMIT 2');
        $q->execute([$expected['login']]);
        return $this->select($expected['login'],$q->fetchAll(PDO::FETCH_ASSOC))===$expected;
    }
}
