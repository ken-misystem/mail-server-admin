<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

final class CredentialManagementService
{
    public const MAX_CREDENTIALS = 10;

    public function __construct(
        private readonly CredentialManagementRepository $repository,
        private readonly RecentFactorSession $recentFactor,
    ) {
    }

    /** @return list<CredentialSummary> */
    public function list(int $roundcubeUserId): array
    {
        self::requireUser($roundcubeUserId);
        return $this->repository->summaries($roundcubeUserId);
    }

    public function requireRegistrationAuthorization(int $roundcubeUserId): void
    {
        self::requireUser($roundcubeUserId);
        $count = $this->repository->enabledCount($roundcubeUserId);
        if ($count >= self::MAX_CREDENTIALS) {
            throw new ManagementException('The Passkey limit has been reached.', 'limit');
        }
        if ($count > 0 && !$this->recentFactor->isRecent($roundcubeUserId)) {
            throw new ManagementException('Fresh factor verification is required.', 'authentication');
        }
    }

    public function completeRegistrationAuthorization(int $roundcubeUserId): void
    {
        self::requireUser($roundcubeUserId);
        $this->recentFactor->clear();
    }

    public function disable(int $roundcubeUserId, int $credentialRowId): void
    {
        $this->requireDisableAuthorization($roundcubeUserId, $credentialRowId);

        // The repository locks policy, credentials, and unused Recovery Codes
        // in one transaction. A final Passkey can be disabled only when an
        // independent Recovery Code remains available.
        $this->repository->disableIfAlternativeFactor($roundcubeUserId, $credentialRowId);
        $this->recentFactor->clear();
    }

    public function requireDisableAuthorization(int $roundcubeUserId, int $credentialRowId): void
    {
        self::requireUser($roundcubeUserId);
        if ($credentialRowId <= 0) {
            throw new ManagementException('The credential selection is invalid.', 'input');
        }
        if (!$this->recentFactor->isRecent($roundcubeUserId)) {
            throw new ManagementException('Fresh factor verification is required.', 'authentication');
        }
    }

    private static function requireUser(int $roundcubeUserId): void
    {
        if ($roundcubeUserId <= 0) {
            throw new ManagementException('Authentication is required.', 'authentication');
        }
    }
}
