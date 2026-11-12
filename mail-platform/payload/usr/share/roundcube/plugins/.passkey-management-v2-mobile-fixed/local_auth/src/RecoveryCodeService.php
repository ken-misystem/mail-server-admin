<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

use Throwable;

final class RecoveryCodeService
{
    public const CODE_COUNT = 10;
    public const MAX_FAILURES = 5;
    public const RATE_WINDOW_MINUTES = 15;
    public const BLOCK_MINUTES = 15;
    private const PREFIX = 'misr_';

    public function __construct(
        private readonly RecoveryCodeRepository $repository,
        private readonly RecoveryCodeHasher $hasher,
        private readonly RecentFactorSession $recentFactor,
    ) {
    }

    /** @return list<string> Plaintext values must be displayed once and never logged. */
    public function replace(int $roundcubeUserId): array
    {
        if ($roundcubeUserId <= 0 || !$this->recentFactor->isRecent($roundcubeUserId)) {
            throw new ManagementException('Fresh factor verification is required.', 'authentication');
        }

        $plain = [];
        $records = [];
        for ($index = 0; $index < self::CODE_COUNT; ++$index) {
            $selector = random_bytes(16);
            $code = self::PREFIX . bin2hex($selector) . '_' . bin2hex(random_bytes(16));
            $plain[] = $code;
            $records[] = new NewRecoveryCode($selector, $this->hasher->hash($code));
        }

        $this->repository->replaceAll($roundcubeUserId, $records);
        $this->recentFactor->clear();
        return $plain;
    }

    public function consume(int $roundcubeUserId, string $presented, ?int $now = null): bool
    {
        if ($roundcubeUserId <= 0) {
            return false;
        }

        $selector = null;
        if (preg_match('/\Amisr_([0-9a-f]{32})_[0-9a-f]{32}\z/D', $presented, $matches) === 1) {
            $decoded = hex2bin($matches[1]);
            if (is_string($decoded) && strlen($decoded) === 16) {
                $selector = $decoded;
            }
        }

        try {
            $stored = $this->repository->beginAttempt($roundcubeUserId, $selector);
            if ($selector === null
                || !$stored
                || !$this->hasher->verify($presented, $stored->hash)
            ) {
                $this->repository->rejectAttempt($roundcubeUserId);
                return false;
            }
            $this->repository->completeConsumption($roundcubeUserId, $stored);
            $this->recentFactor->mark($roundcubeUserId, 'recovery-code', $now);
            return true;
        } catch (Throwable $e) {
            $this->repository->rollbackAttempt();
            throw $e;
        }
    }
}
