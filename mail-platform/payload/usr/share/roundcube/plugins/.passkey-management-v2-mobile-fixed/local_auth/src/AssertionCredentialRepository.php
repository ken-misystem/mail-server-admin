<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuth;

interface AssertionCredentialRepository
{
    public function getUserHandle(int $roundcubeUserId): ?string;

    /** @return list<array{id: string, transports: list<string>}> */
    public function enabledCredentialDescriptors(int $roundcubeUserId): array;

    public function lockEnabledCredential(
        int $roundcubeUserId,
        string $credentialId,
    ): StoredCredential;

    public function completeAssertion(
        int $roundcubeUserId,
        StoredCredential $stored,
        ValidatedAssertion $validated,
    ): void;

    public function rollbackAssertion(): void;
}
