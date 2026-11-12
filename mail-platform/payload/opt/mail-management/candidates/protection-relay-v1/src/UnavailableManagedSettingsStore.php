<?php
declare(strict_types=1);
namespace MailServer\Management;
final class UnavailableManagedSettingsStore implements ManagedSettingsStore
{
    public function lookup(AdminUser $actor,string $kind):array{throw new \RuntimeException('managed_settings_unavailable');}
    public function save(AdminUser $actor,string $kind,int $revision,array $payload,string $requestId):array{throw new \RuntimeException('managed_settings_unavailable');}
}
