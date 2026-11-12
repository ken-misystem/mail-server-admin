<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

final readonly class StoredEmergencyRecoveryToken
{
    public function __construct(
        public int $id,
        public string $hash,
        public int $issuedAt,
        public int $expiresAt,
    ) {
    }
}
