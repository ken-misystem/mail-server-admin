<?php
declare(strict_types=1);
namespace MailServer\Management;
interface ManagedSettingsStore
{
    public function lookup(AdminUser $actor,string $kind):array;
    public function save(AdminUser $actor,string $kind,int $revision,array $payload,string $requestId):array;
}
