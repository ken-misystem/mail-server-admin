<?php

declare(strict_types=1);

namespace MailServer\Management;

interface AdminSettingsStore
{
    /** Four non-secret inventories, limited to 200 rows each plus explicit truncation flags. */
    public function overview(AdminUser $actor): array;
    public function setUserPolicy(AdminUser $actor, string $userId, UserPolicyLimits $limits): void;
}
