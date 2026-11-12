<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

interface EmergencyRecoveryTokenDelivery
{
    /** Deliver once to the server-selected verified address without logging it. */
    public function deliver(int $roundcubeUserId, string $plaintextToken): bool;
}
