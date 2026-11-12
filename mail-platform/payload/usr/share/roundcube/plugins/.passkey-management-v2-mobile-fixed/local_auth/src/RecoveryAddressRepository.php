<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

interface RecoveryAddressRepository
{
    public function verifiedAddress(string $account): string;
}
