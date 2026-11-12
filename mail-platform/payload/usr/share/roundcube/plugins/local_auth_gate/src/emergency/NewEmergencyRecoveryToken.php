<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

final readonly class NewEmergencyRecoveryToken
{
    public function __construct(
        public string $selector,
        public string $hash,
        public int $issuedAt,
        public int $expiresAt,
    ) {
    }
}
