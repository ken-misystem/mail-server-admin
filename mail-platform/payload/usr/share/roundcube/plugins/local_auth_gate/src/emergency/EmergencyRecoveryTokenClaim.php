<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

interface EmergencyRecoveryTokenClaim
{
    public function claim(
        int $roundcubeUserId,
        string $accountIdentifier,
        string $presented,
        EmergencyRecoverySession $session,
        ?int $now = null,
    ): bool;
}
