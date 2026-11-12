<?php
declare(strict_types=1);
namespace MailServer\Management;
interface ForwardStore
{
    public function lookup(AdminUser $actor,string $userId):?array;
    public function save(AdminUser $actor,string $userId,int $revision,array $destinations,bool $enabled,string $confirmation,string $requestId):array;
}
