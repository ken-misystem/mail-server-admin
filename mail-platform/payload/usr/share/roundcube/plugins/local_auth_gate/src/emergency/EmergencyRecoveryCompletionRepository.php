<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

interface EmergencyRecoveryCompletionRepository
{
    /**
     * In one transaction, revalidate the claimed token and nonce hash, insert
     * the new credential, disable older credentials, revoke unused Recovery
     * Codes and other tokens, keep MFA required, and mark the token used.
     */
    public function complete(
        int $roundcubeUserId,
        int $tokenId,
        string $sessionNonceHash,
        EmergencyRecoveryCredential $credential,
        string $label,
        int $now,
    ): void;
}
