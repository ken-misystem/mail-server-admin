<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

final class PhpEmergencyRecoveryTokenHasher implements EmergencyRecoveryTokenHasher
{
    public function hash(string $token): string
    {
        $hash = password_hash($token, PASSWORD_ARGON2ID);
        if (!is_string($hash) || $hash === '') {
            throw new EmergencyRecoveryException('Recovery token hashing failed.', 'internal');
        }
        return $hash;
    }

    public function verify(string $token, string $hash): bool
    {
        return $hash !== '' && password_verify($token, $hash);
    }
}
