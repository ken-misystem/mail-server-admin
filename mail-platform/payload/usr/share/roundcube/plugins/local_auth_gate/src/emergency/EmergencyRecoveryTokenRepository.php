<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

interface EmergencyRecoveryTokenRepository
{
    public function replacePending(int $roundcubeUserId, NewEmergencyRecoveryToken $token): int;

    public function activate(int $roundcubeUserId, int $tokenId): void;

    public function revokePending(int $roundcubeUserId, int $tokenId): void;

    /**
     * Start and hold a rate-limit/token transaction. Return only an active,
     * unexpired, unclaimed, unused, and unrevoked token. Malformed input
     * supplies a null selector and must still count as an attempt.
     */
    public function beginAttempt(
        int $roundcubeUserId,
        ?string $selector,
        int $now,
    ): ?StoredEmergencyRecoveryToken;

    public function rejectAttempt(int $roundcubeUserId, int $now): void;

    /** Commit a one-time claim bound to the hash of the restricted-session nonce. */
    public function completeClaim(
        int $roundcubeUserId,
        StoredEmergencyRecoveryToken $token,
        string $sessionNonceHash,
        int $now,
    ): void;

    public function rollbackAttempt(): void;
}
