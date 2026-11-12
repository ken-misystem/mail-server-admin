<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

interface RecoveryCodeHasher
{
    public function hash(string $code): string;

    public function verify(string $code, string $hash): bool;
}
