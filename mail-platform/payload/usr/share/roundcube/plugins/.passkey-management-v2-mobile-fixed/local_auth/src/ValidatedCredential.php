<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuth;

final readonly class ValidatedCredential
{
    /** @param list<string> $transports */
    public function __construct(
        public string $credentialId,
        public string $userHandle,
        public string $credentialRecordJson,
        public int $signCount,
        public array $transports,
    ) {
    }
}
