<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuth;

interface RegistrationValidator
{
    /**
     * @param list<array{id: string, transports: list<string>}> $excludedCredentials
     */
    public function createOptions(
        string $username,
        string $displayName,
        string $userHandle,
        string $challenge,
        array $excludedCredentials,
    ): string;

    public function validate(string $responseJson, string $optionsJson): ValidatedCredential;
}
