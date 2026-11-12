<?php
declare(strict_types=1);
namespace MailServer\Management;

interface ProtectionStore
{
    public function read(AdminUser $actor, string $kind): array;
    public function save(AdminUser $actor, string $kind, int $revision, array $payload, array $credential, string $requestId): array;
}
