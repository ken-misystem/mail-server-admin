<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

interface MfaPolicyRepository
{
    public function requirement(int $roundcubeUserId): MfaRequirement;
}
