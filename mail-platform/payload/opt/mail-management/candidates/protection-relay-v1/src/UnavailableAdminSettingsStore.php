<?php

declare(strict_types=1);

namespace MailServer\Management;

final class UnavailableAdminSettingsStore implements AdminSettingsStore
{
    public function overview(AdminUser $actor): array { throw new \DomainException('settings_storage_unavailable'); }
    public function setUserPolicy(AdminUser $actor, string $userId, UserPolicyLimits $limits): void
    { throw new \DomainException('settings_storage_unavailable'); }
}
