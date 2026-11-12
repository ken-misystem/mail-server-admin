<?php
declare(strict_types=1);
namespace MailServer\Management;
final class UnavailableScopedAdminReadStore implements ScopedAdminReadStore
{
    public function domains(AdminUser $actor): array { throw new \DomainException('scoped_storage_unavailable'); }
    public function listing(AdminUser $actor, string $section, array $filter): array { throw new \DomainException('scoped_storage_unavailable'); }
    public function record(AdminUser $actor, string $section, string $id): ?array { throw new \DomainException('scoped_storage_unavailable'); }
}
