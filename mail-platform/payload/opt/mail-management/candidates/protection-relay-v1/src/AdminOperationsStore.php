<?php

declare(strict_types=1);

namespace MailServer\Management;

interface AdminOperationsStore
{
    public function apply(AdminUser $actor, AdminMutation $mutation): void;
}
