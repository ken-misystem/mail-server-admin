<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

final readonly class EmergencyRecoverySessionState
{
    public function __construct(
        public int $roundcubeUserId,
        public string $accountIdentifier,
        public int $tokenId,
        public string $nonceHash,
        public int $verifiedAt,
        public int $expiresAt,
    ) {
    }
}
