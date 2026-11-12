<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuth;

interface AssertionValidator
{
    /**
     * @param list<array{id: string, transports: list<string>}> $allowedCredentials
     */
    public function createOptions(
        string $challenge,
        array $allowedCredentials,
    ): string;

    public function validate(
        string $responseJson,
        string $optionsJson,
        StoredCredential $stored,
        string $expectedUserHandle,
    ): ValidatedAssertion;
}
