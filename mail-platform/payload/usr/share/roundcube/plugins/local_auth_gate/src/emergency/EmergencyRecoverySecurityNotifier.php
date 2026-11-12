<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

interface EmergencyRecoverySecurityNotifier
{
    /** Notify the pre-verified address without exposing it to the caller. */
    public function notify(string $accountIdentifier): bool;
}
