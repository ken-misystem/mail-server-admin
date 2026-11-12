<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

final readonly class CredentialSummary
{
    public function __construct(
        public int $id,
        public string $label,
        public bool $enabled,
        public string $createdAt,
        public ?string $lastUsedAt,
    ) {
    }
}
