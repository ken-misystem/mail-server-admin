<?php
declare(strict_types=1);
namespace MailServer\Management;
interface ScopedWriteStore
{
    public function apply(AdminUser $actor,#[\SensitiveParameter] ScopedMutation $mutation,string $requestId):array;
}
