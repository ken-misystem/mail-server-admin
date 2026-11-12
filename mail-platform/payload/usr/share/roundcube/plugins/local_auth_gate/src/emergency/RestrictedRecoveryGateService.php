<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

final class RestrictedRecoveryGateService
{
    public function __construct(
        private readonly EmergencyRecoverySession $session,
        private readonly EmergencyRecoveryRegistrationCeremony $ceremony,
        private readonly EmergencyRecoveryCompletionService $completion,
    ) {
    }

    /** @return array{ceremony_id: string, publicKey: array<string, mixed>} */
    public function begin(int $roundcubeUserId, string $accountIdentifier, ?int $now = null): array
    {
        $this->session->requirePending($roundcubeUserId, $accountIdentifier, $now);
        return $this->ceremony->begin($roundcubeUserId, $accountIdentifier);
    }

    public function finish(
        int $roundcubeUserId,
        string $accountIdentifier,
        string $ceremonyId,
        string $responseJson,
        string $label,
        ?int $now = null,
    ): EmergencyRecoveryCompletionResult {
        $this->session->requirePending($roundcubeUserId, $accountIdentifier, $now);
        $credential = $this->ceremony->finish($roundcubeUserId, $ceremonyId, $responseJson);
        return $this->completion->complete(
            $roundcubeUserId,
            $accountIdentifier,
            $credential,
            $label,
            $now,
        );
    }
}
