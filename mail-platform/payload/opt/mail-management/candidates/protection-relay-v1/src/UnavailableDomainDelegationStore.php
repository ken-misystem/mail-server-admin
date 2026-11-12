<?php
declare(strict_types=1);
namespace MailServer\Management;
final class UnavailableDomainDelegationStore implements DomainDelegationStore
{
    public function lookup(AdminUser $actor, string $adminId, string $domainId): array { throw new \DomainException('delegation_storage_unavailable'); }
    public function save(AdminUser $actor, array $request): array { throw new \DomainException('delegation_storage_unavailable'); }
}
