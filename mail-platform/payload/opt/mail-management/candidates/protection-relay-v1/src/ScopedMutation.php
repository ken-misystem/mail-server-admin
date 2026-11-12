<?php
declare(strict_types=1);
namespace MailServer\Management;

/** No domain/admin/delete operations. Secrets never enter serialization or receipts. */
final readonly class ScopedMutation
{
    public const OPERATIONS=['mailbox_create'=>'mailbox.create','mailbox_state'=>'mailbox.state','mailbox_password'=>'mailbox.password',
        'mailbox_quota'=>'mailbox.quota','alias_create'=>'alias.create','alias_state'=>'alias.change','alias_destination'=>'alias.change'];
    private function __construct(public string $action,#[\SensitiveParameter] private ?AdminMutation $regular,private array $quota){}
    public function value(string $key):mixed{return $this->regular!==null?$this->regular->value($key):$this->quota[$key];}
    public function __debugInfo():array{return ['action'=>$this->action,'values'=>'[omitted]'];}
    public function __serialize():array{throw new \LogicException('mutation_not_serializable');}
    public static function fromForm(string $action,#[\SensitiveParameter] array $input):self
    {
        if(!isset(self::OPERATIONS[$action])){throw new \DomainException('unknown_operation');}
        if($action!=='mailbox_quota'){return new self($action,AdminMutation::fromForm($action,$input),[]);}
        $q=[];foreach(['id','confirm','expected_bytes','mode','limit_kib','confirm_unlimited'] as $field){$value=$input[$field]??'';if(!is_string($value)||strlen($value)>1024){throw new \DomainException('invalid_input');}$q[$field]=$value;}
        UserPolicyLimits::userId($q['id']);return new self($action,null,$q);
    }
}
