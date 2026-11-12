<?php
declare(strict_types=1);
namespace MailServer\Management;
interface DomainDelegationStore
{
    public function lookup(AdminUser $actor,string $adminId,string $domainId):array;
    public function save(AdminUser $actor,array $request):array;
}
