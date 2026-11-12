<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

interface EmergencyRecoveryTokenHasher
{
    public function hash(string $token): string;

    public function verify(string $token, string $hash): bool;
}
