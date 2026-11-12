<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

final readonly class MfaRequirement
{
    public function __construct(
        public bool $required,
        public bool $passkeyAvailable,
        public bool $recoveryCodeAvailable,
    ) {
    }
}
