<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

use MailServer\RoundcubeAuthManagement\SessionEpochInvalidator;
use Throwable;

final class MailAuthEmergencyRecoveryEpochInvalidator implements EmergencyRecoveryEpochInvalidator
{
    public function __construct(private readonly SessionEpochInvalidator $delegate)
    {
    }

    public function bump(string $accountIdentifier): void
    {
        try {
            $this->delegate->bump($accountIdentifier);
        } catch (Throwable $e) {
            throw new EmergencyRecoveryException('Session invalidation failed.', 'storage');
        }
    }
}
