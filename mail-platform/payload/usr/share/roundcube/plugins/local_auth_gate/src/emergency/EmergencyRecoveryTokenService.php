<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

use Throwable;

final class EmergencyRecoveryTokenService
{
    public const TOKEN_TTL_SECONDS = 900;
    public const MAX_FAILURES = 5;
    public const RATE_WINDOW_SECONDS = 900;
    public const BLOCK_SECONDS = 900;
    private const PREFIX = 'misf_';

    public function __construct(
        private readonly EmergencyRecoveryTokenRepository $repository,
        private readonly EmergencyRecoveryTokenHasher $hasher,
        private readonly EmergencyRecoveryTokenDelivery $delivery,
    ) {
    }

    /** Issue only after the caller has completed administrator OOB verification. */
    public function issue(int $roundcubeUserId, bool $administratorVerified, ?int $now = null): void
    {
        if ($roundcubeUserId <= 0 || !$administratorVerified) {
            throw new EmergencyRecoveryException('Administrator verification is required.', 'authentication');
        }
        $now ??= time();
        $selector = random_bytes(16);
        $plaintext = self::PREFIX . bin2hex($selector) . '_' . bin2hex(random_bytes(16));
        $token = new NewEmergencyRecoveryToken(
            $selector,
            $this->hasher->hash($plaintext),
            $now,
            $now + self::TOKEN_TTL_SECONDS,
        );
        $tokenId = $this->repository->replacePending($roundcubeUserId, $token);
        try {
            if (!$this->delivery->deliver($roundcubeUserId, $plaintext)) {
                throw new EmergencyRecoveryException('Recovery token delivery failed.', 'delivery');
            }
            $this->repository->activate($roundcubeUserId, $tokenId);
        } catch (Throwable $e) {
            $this->repository->revokePending($roundcubeUserId, $tokenId);
            throw $e;
        } finally {
            unset($plaintext);
        }
    }

    public function claim(
        int $roundcubeUserId,
        string $accountIdentifier,
        string $presented,
        EmergencyRecoverySession $session,
        ?int $now = null,
    ): bool {
        return (new EmergencyRecoveryTokenClaimService($this->repository, $this->hasher))->claim(
            $roundcubeUserId,
            $accountIdentifier,
            $presented,
            $session,
            $now,
        );
    }
}
