<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

interface SessionEpochInvalidator
{
    public function bump(string $username): int;
}
