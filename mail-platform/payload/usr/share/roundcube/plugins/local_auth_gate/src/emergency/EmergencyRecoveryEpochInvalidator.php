<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

interface EmergencyRecoveryEpochInvalidator
{
    /** Invalidate existing web sessions before Roundcube factor rows change. */
    public function bump(string $accountIdentifier): void;
}
