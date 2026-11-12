<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

use Throwable;

final class EmergencyRecoveryCompletionService
{
    public const MAX_LABEL_CHARACTERS = 80;
    public const MAX_CREDENTIAL_ID_BYTES = 1024;

    public function __construct(
        private readonly EmergencyRecoveryCompletionRepository $repository,
        private readonly EmergencyRecoveryEpochInvalidator $epochInvalidator,
        private readonly EmergencyRecoverySession $session,
        private readonly EmergencyRecoveryAuthenticatedSessionDestroyer $sessionDestroyer,
        private readonly EmergencyRecoverySecurityNotifier $notifier,
    ) {
    }

    public function complete(
        int $roundcubeUserId,
        string $accountIdentifier,
        EmergencyRecoveryCredential $credential,
        string $label,
        ?int $now = null,
    ): EmergencyRecoveryCompletionResult {
        $now ??= time();
        $normalized = strtolower(trim($accountIdentifier));
        if (!\MailServer\RoundcubePasskeyGeneral\AccountIdentity::valid($normalized)) {
            throw new EmergencyRecoveryException('Recovery is unavailable.', 'authentication');
        }
        $state = $this->session->requirePending($roundcubeUserId, $normalized, $now);
        $label = trim($label);
        if (preg_match('/\A.{1,' . self::MAX_LABEL_CHARACTERS . '}\z/us', $label) !== 1
            || preg_match('/[\x00-\x1F\x7F]/u', $label)
            || strlen($credential->credentialId) < 1
            || strlen($credential->credentialId) > self::MAX_CREDENTIAL_ID_BYTES
            || strlen($credential->userHandle) !== 32
            || $credential->credentialRecordJson === ''
            || $credential->signCount < 0
        ) {
            throw new EmergencyRecoveryException('Replacement credential is invalid.', 'input');
        }

        // This cross-database order is intentionally fail closed.
        $this->epochInvalidator->bump($normalized);
        $this->repository->complete(
            $roundcubeUserId,
            $state->tokenId,
            $state->nonceHash,
            $credential,
            $label,
            $now,
        );
        $this->session->clear();
        try {
            $sessionDestroyed = $this->sessionDestroyer->destroy();
        } catch (Throwable $e) {
            $sessionDestroyed = false;
        }
        try {
            $notificationSent = $this->notifier->notify($normalized);
        } catch (Throwable $e) {
            $notificationSent = false;
        }
        return new EmergencyRecoveryCompletionResult($sessionDestroyed, $notificationSent);
    }
}
