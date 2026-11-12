<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Applies to new scoped routes only; existing global routes remain system-admin-only. */
final readonly class DomainAuthority
{
    public const OPERATIONS=['mailbox.read','mailbox.create','mailbox.state','mailbox.password','mailbox.quota','alias.read','alias.create','alias.change','forward.read','forward.change','usage.read','csv.preview','csv.apply'];
    public function __construct(public AdminUser $actor,private array $grants,public int $revision) {}
    public function require(string $operation,array $domainIds):void
    {
        if(!$this->actor->active||!in_array($operation,self::OPERATIONS,true)||!$domainIds){throw new \DomainException('not_authorized');}
        foreach($domainIds as $id){
            if(!is_string($id)||!preg_match('/^[1-9][0-9]{0,9}$/D',$id)){throw new \DomainException('invalid_domain');}
            if(!$this->actor->systemAdmin&&($this->revision<1||!in_array($operation,$this->grants[$id]??[],true))){throw new \DomainException('domain_not_delegated');}
        }
    }
}
