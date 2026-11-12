<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

interface CredentialManagementRepository
{
    /** @return list<CredentialSummary> */
    public function summaries(int $roundcubeUserId): array;

    public function enabledCount(int $roundcubeUserId): int;

    public function disableIfAlternativeFactor(int $roundcubeUserId, int $credentialRowId): void;
}
