<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

interface EmergencyRecoveryRegistrationCeremony
{
    /** @return array{ceremony_id: string, publicKey: array<string, mixed>} */
    public function begin(int $roundcubeUserId, string $accountIdentifier): array;

    public function finish(
        int $roundcubeUserId,
        string $ceremonyId,
        string $responseJson,
    ): EmergencyRecoveryCredential;
}
