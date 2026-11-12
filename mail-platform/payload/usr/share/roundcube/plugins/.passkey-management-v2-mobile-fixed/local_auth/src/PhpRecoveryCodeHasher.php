<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

final class PhpRecoveryCodeHasher implements RecoveryCodeHasher
{
    public function hash(string $code): string
    {
        $hash = password_hash($code, PASSWORD_ARGON2ID);
        if (!is_string($hash)) {
            throw new ManagementException('Recovery Code hashing failed.', 'internal');
        }
        return $hash;
    }

    public function verify(string $code, string $hash): bool
    {
        return password_verify($code, $hash);
    }
}
