<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

use Throwable;

final class EmergencyRecoveryTokenClaimService implements EmergencyRecoveryTokenClaim
{
    public function __construct(
        private readonly EmergencyRecoveryTokenRepository $repository,
        private readonly EmergencyRecoveryTokenHasher $hasher,
    ) {
    }

    public function claim(
        int $roundcubeUserId,
        string $accountIdentifier,
        string $presented,
        EmergencyRecoverySession $session,
        ?int $now = null,
    ): bool {
        $now ??= time();
        $account = strtolower($accountIdentifier);
        if ($roundcubeUserId <= 0
            || !\MailServer\RoundcubePasskeyGeneral\AccountIdentity::valid($account)
        ) {
            return false;
        }

        $selector = null;
        if (preg_match('/\Amisf_([0-9a-f]{32})_[0-9a-f]{32}\z/D', $presented, $matches) === 1) {
            $decoded = hex2bin($matches[1]);
            if (is_string($decoded) && strlen($decoded) === 16) {
                $selector = $decoded;
            }
        }

        try {
            $stored = $this->repository->beginAttempt($roundcubeUserId, $selector, $now);
            if ($selector === null
                || !$stored
                || $stored->expiresAt <= $now
                || !$this->hasher->verify($presented, $stored->hash)
            ) {
                $this->repository->rejectAttempt($roundcubeUserId, $now);
                return false;
            }

            $state = $session->start(
                $roundcubeUserId,
                $account,
                $stored->id,
                $stored->expiresAt,
                $now,
            );
            $this->repository->completeClaim(
                $roundcubeUserId,
                $stored,
                $state->nonceHash,
                $now,
            );
            return true;
        } catch (Throwable $e) {
            $session->clear();
            $this->repository->rollbackAttempt();
            throw $e;
        }
    }
}
