<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Every call refreshes the actor and applies domain permissions in storage. */
interface ScopedAdminReadStore
{
    public function domains(AdminUser $actor): array;
    public function listing(AdminUser $actor, string $section, array $filter): array;
    public function record(AdminUser $actor, string $section, string $id): ?array;
}
