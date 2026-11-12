<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

interface RecoveryCodeRepository
{
    /** @param list<NewRecoveryCode> $codes */
    public function replaceAll(int $roundcubeUserId, array $codes): void;

    /**
     * Start and hold one rate-limit/code-consumption transaction. A null
     * selector represents malformed input and must still count as an attempt.
     */
    public function beginAttempt(int $roundcubeUserId, ?string $selector): ?StoredRecoveryCode;

    public function rejectAttempt(int $roundcubeUserId): void;

    public function completeConsumption(int $roundcubeUserId, StoredRecoveryCode $code): void;

    public function rollbackAttempt(): void;
}
