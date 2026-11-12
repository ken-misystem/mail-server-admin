<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

final readonly class EmergencyRecoveryCompletionResult
{
    public function __construct(
        public bool $sessionDestroyed,
        public bool $notificationSent,
    ) {
    }
}
