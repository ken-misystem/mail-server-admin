<?php
declare(strict_types=1);
namespace MailServer\Management;

/** A bounded primary-key window, not an unbounded historical search. */
final class AdminAuditQuery
{
    public const ACTIONS = [
        'legacy_smtp_create'=>'互換SMTP ID登録','legacy_smtp_state'=>'互換SMTP 有効状態','legacy_smtp_password'=>'互換SMTP パスワード再設定',
        'domain_create'=>'ドメイン追加','domain_state'=>'ドメイン有効状態',
        'mailbox_create'=>'メールアカウント追加','mailbox_state'=>'メールアカウント有効状態','mailbox_password'=>'メールパスワード変更',
        'alias_create'=>'エイリアス追加','alias_state'=>'エイリアス有効状態','alias_destination'=>'エイリアス転送先変更','alias_remove'=>'エイリアス削除',
        'admin_create'=>'管理者追加','admin_state'=>'管理者有効状態','admin_password'=>'管理者パスワード変更','admin_identity'=>'管理者識別情報変更',
        'user_policy_updated'=>'利用者ポリシー変更','passkey_registered'=>'管理者パスキー登録','bootstrap_admin'=>'初期管理者作成',
    ];
    public const TYPES = ['legacy_smtp'=>'互換SMTP','domain'=>'ドメイン','mailbox'=>'メールアカウント','alias'=>'エイリアス','admin'=>'管理者','mail_user'=>'利用者','admin_passkey'=>'管理者パスキー'];
    public function __construct(public readonly int $hours=24,public readonly string $action='',public readonly string $type='',
        public readonly string $actor='',public readonly string $target='',public readonly ?string $before=null)
    {
        if(!in_array($hours,[24,168,720],true)||($action!==''&&!isset(self::ACTIONS[$action]))||($type!==''&&!isset(self::TYPES[$type]))
            ||($actor!==''&&!self::id($actor))||($target!==''&&!self::id($target))||($before!==null&&!self::id($before)))throw new \DomainException('audit_query');
    }
    public static function id(mixed $value): bool
    {
        return is_string($value)&&preg_match('/^[1-9][0-9]{0,19}$/D',$value)===1
            &&(strlen($value)<20||strcmp($value,'18446744073709551615')<=0);
    }
    public static function fromArray(array $v): self
    {
        if(array_diff(array_keys($v),['_token','hours','action','type','actor','target','before']))throw new \DomainException('audit_query');
        foreach($v as$value)if(!is_string($value))throw new \DomainException('audit_query');
        $hours=$v['hours']??'24';if(!in_array($hours,['24','168','720'],true))throw new \DomainException('audit_query');
        return new self((int)$hours,$v['action']??'',$v['type']??'',$v['actor']??'',$v['target']??'',($v['before']??'')===''?null:$v['before']);
    }
    public static function compare(string $a,string $b): int {return strlen($a)<=>strlen($b)?:strcmp($a,$b);}
    public function select(array $rows,int $now): array
    {
        if(count($rows)>201)throw new \DomainException('audit_row_bound');
        $previous=$this->before;
        foreach($rows as$row){
            if(!is_array($row)||array_keys($row)!==['id','admin_id','action','target_type','target_id','occurred_at']
                ||!self::id($row['id'])||($row['admin_id']!==null&&!self::id($row['admin_id']))
                ||($row['target_id']!==null&&!self::id($row['target_id']))
                ||!is_string($row['action'])||!preg_match('/^[a-z_]{1,64}$/D',$row['action'])
                ||!is_string($row['target_type'])||!preg_match('/^[a-z_]{1,32}$/D',$row['target_type'])
                ||!is_int($row['occurred_at'])||$row['occurred_at']<0||$row['occurred_at']>253402300799
                ||($previous!==null&&self::compare($row['id'],$previous)>=0))throw new \DomainException('audit_row_shape');
            $previous=$row['id'];
        }
        $matches=[];$scanned=0;$cursor=null;
        foreach(array_slice($rows,0,200)as$row){
            ++$scanned;$cursor=$row['id'];
            if($row['occurred_at']<=$now&&$row['occurred_at']>=$now-$this->hours*3600
                &&($this->action===''||$row['action']===$this->action)&&($this->type===''||$row['target_type']===$this->type)
                &&($this->actor===''||$row['admin_id']===$this->actor)&&($this->target===''||$row['target_id']===$this->target))$matches[]=$row;
            if(count($matches)===50)break;
        }
        return ['rows'=>$matches,'scanned'=>$scanned,'next_before'=>count($rows)>$scanned?$cursor:null,'checked_at'=>$now];
    }
}
