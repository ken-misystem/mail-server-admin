<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuth;

interface CredentialRepository
{
    public function getOrCreateUserHandle(int $roundcubeUserId): string;

    /** @return list<array{id: string, transports: list<string>}> */
    public function enabledCredentialDescriptors(int $roundcubeUserId): array;

    public function credentialExists(string $credentialId): bool;

    public function saveNewCredential(
        int $roundcubeUserId,
        ValidatedCredential $credential,
        string $label,
    ): void;
}
