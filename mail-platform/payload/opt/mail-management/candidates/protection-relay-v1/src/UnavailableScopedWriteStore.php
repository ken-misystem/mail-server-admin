<?php
declare(strict_types=1);
namespace MailServer\Management;
final class UnavailableScopedWriteStore implements ScopedWriteStore
{
    public function apply(AdminUser $actor,#[\SensitiveParameter] ScopedMutation $mutation,string $requestId):array{throw new \DomainException('scoped_storage_unavailable');}
}
