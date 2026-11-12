<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

final readonly class NewRecoveryCode
{
    public function __construct(
        public string $selector,
        public string $hash,
    ) {
    }
}
