<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

interface EmergencyRecoveryWebauthnSource
{
    public function userHandle(int $roundcubeUserId): string;

    /** @return list<array{id: string, transports: list<string>}> */
    public function allCredentialDescriptors(int $roundcubeUserId): array;

    public function credentialExists(string $credentialId): bool;
}
