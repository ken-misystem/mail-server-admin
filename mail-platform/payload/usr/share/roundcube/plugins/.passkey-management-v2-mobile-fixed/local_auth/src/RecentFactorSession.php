<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

final class RecentFactorSession
{
    public const SESSION_KEY = 'local_auth_recent_factor_v1';
    public const TTL_SECONDS = 300;

    /** @var array<string, mixed> */
    private array $session;

    /** @param array<string, mixed> $session */
    public function __construct(array &$session)
    {
        $this->session =& $session;
    }

    public function mark(int $roundcubeUserId, string $factor, ?int $now = null): void
    {
        if ($roundcubeUserId <= 0 || !in_array($factor, ['passkey', 'recovery-code'], true)) {
            throw new \InvalidArgumentException('A valid factor proof is required.');
        }

        $now ??= time();
        $this->session[self::SESSION_KEY] = [
            'version' => 1,
            'roundcube_user_id' => $roundcubeUserId,
            'factor' => $factor,
            'verified_at' => $now,
            'expires_at' => $now + self::TTL_SECONDS,
        ];
    }

    public function isRecent(int $roundcubeUserId, ?int $now = null): bool
    {
        $now ??= time();
        $state = $this->session[self::SESSION_KEY] ?? null;
        $valid = is_array($state)
            && ($state['version'] ?? null) === 1
            && ($state['roundcube_user_id'] ?? null) === $roundcubeUserId
            && in_array($state['factor'] ?? null, ['passkey', 'recovery-code'], true)
            && is_int($state['verified_at'] ?? null)
            && is_int($state['expires_at'] ?? null)
            && $state['verified_at'] <= $now
            && $state['expires_at'] === $state['verified_at'] + self::TTL_SECONDS
            && $state['expires_at'] >= $now;

        if (!$valid) {
            unset($this->session[self::SESSION_KEY]);
        }

        return $valid;
    }

    public function clear(): void
    {
        unset($this->session[self::SESSION_KEY]);
    }
}
