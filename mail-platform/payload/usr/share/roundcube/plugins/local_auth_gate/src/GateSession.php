<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthGate;

final class GateSession
{
    public const SESSION_KEY = 'local_auth_gate_pending_v1';
    public const STATUS_NONE = 'none';
    public const STATUS_PENDING = 'pending';
    public const STATUS_INVALID = 'invalid';

    private const VERSION = 1;
    private const TTL_SECONDS = 300;

    /** @var array<string, mixed> */
    private array $session;

    /** @param array<string, mixed> $session */
    public function __construct(array &$session)
    {
        $this->session =& $session;
    }

    public function hasState(): bool
    {
        return array_key_exists(self::SESSION_KEY, $this->session);
    }

    public function markPending(int $roundcubeUserId, ?int $now = null): void
    {
        if ($roundcubeUserId <= 0) {
            throw new \InvalidArgumentException('A valid Roundcube user ID is required.');
        }

        $now ??= time();
        $this->session[self::SESSION_KEY] = [
            'version' => self::VERSION,
            'roundcube_user_id' => $roundcubeUserId,
            'issued_at' => $now,
            'expires_at' => $now + self::TTL_SECONDS,
        ];
    }

    public function status(int $roundcubeUserId, ?int $now = null): string
    {
        if (!$this->hasState()) {
            return self::STATUS_NONE;
        }

        $now ??= time();
        $state = $this->session[self::SESSION_KEY];
        if (!is_array($state)
            || ($state['version'] ?? null) !== self::VERSION
            || ($state['roundcube_user_id'] ?? null) !== $roundcubeUserId
            || !is_int($state['issued_at'] ?? null)
            || !is_int($state['expires_at'] ?? null)
            || $roundcubeUserId <= 0
            || $state['issued_at'] > $now
            || $state['expires_at'] !== $state['issued_at'] + self::TTL_SECONDS
            || $state['expires_at'] < $now
        ) {
            return self::STATUS_INVALID;
        }

        return self::STATUS_PENDING;
    }

    public function clearPending(int $roundcubeUserId, ?int $now = null): bool
    {
        if ($this->status($roundcubeUserId, $now) !== self::STATUS_PENDING) {
            return false;
        }

        unset($this->session[self::SESSION_KEY]);
        return true;
    }
}
