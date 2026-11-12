<?php

declare(strict_types=1);

namespace MailServer\Management;

final class UnavailableAdminOperationsStore implements AdminOperationsStore
{
    public function apply(AdminUser $actor, AdminMutation $mutation): void { throw new \DomainException('operations_storage_unavailable'); }
}
