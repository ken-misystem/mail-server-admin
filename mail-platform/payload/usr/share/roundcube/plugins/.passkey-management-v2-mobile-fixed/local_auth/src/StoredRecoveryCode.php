<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

final readonly class StoredRecoveryCode
{
    public function __construct(
        public int $id,
        public string $hash,
    ) {
    }
}
