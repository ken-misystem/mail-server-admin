<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

final class EmergencyRecoverySession
{
    public const SESSION_KEY = 'local_auth_emergency_recovery_v1';
    public const MAX_TTL_SECONDS = 900;

    /** @var array<string, mixed> */
    private array $session;

    /** @param array<string, mixed> $session */
    public function __construct(array &$session)
    {
        $this->session =& $session;
    }

    public function start(
        int $roundcubeUserId,
        string $accountIdentifier,
        int $tokenId,
        int $tokenExpiresAt,
        ?int $now = null,
    ): EmergencyRecoverySessionState {
        $now ??= time();
        $accountIdentifier = strtolower(trim($accountIdentifier));
        if ($roundcubeUserId <= 0 || $tokenId <= 0 || $accountIdentifier === '' || $tokenExpiresAt <= $now) {
            throw new EmergencyRecoveryException('Recovery session input is invalid.', 'state');
        }

        $nonce = random_bytes(32);
        $expiresAt = min($tokenExpiresAt, $now + self::MAX_TTL_SECONDS);
        $this->session[self::SESSION_KEY] = [
            'version' => 1,
            'roundcube_user_id' => $roundcubeUserId,
            'account_identifier' => $accountIdentifier,
            'token_id' => $tokenId,
            'nonce' => self::base64UrlEncode($nonce),
            'verified_at' => $now,
            'expires_at' => $expiresAt,
        ];

        return new EmergencyRecoverySessionState(
            $roundcubeUserId,
            $accountIdentifier,
            $tokenId,
            hash('sha256', $nonce, true),
            $now,
            $expiresAt,
        );
    }

    public function requirePending(
        int $roundcubeUserId,
        string $accountIdentifier,
        ?int $now = null,
    ): EmergencyRecoverySessionState {
        $now ??= time();
        $state = $this->session[self::SESSION_KEY] ?? null;
        $normalized = strtolower(trim($accountIdentifier));
        if (!is_array($state)
            || ($state['version'] ?? null) !== 1
            || ($state['roundcube_user_id'] ?? null) !== $roundcubeUserId
            || !is_string($state['account_identifier'] ?? null)
            || !hash_equals($state['account_identifier'], $normalized)
            || !is_int($state['token_id'] ?? null)
            || $state['token_id'] <= 0
            || !is_string($state['nonce'] ?? null)
            || !is_int($state['verified_at'] ?? null)
            || !is_int($state['expires_at'] ?? null)
            || $state['verified_at'] > $now
            || $state['expires_at'] <= $now
            || $state['expires_at'] > $state['verified_at'] + self::MAX_TTL_SECONDS
        ) {
            $this->clear();
            throw new EmergencyRecoveryException('Recovery session is unavailable.', 'state');
        }

        $nonce = self::base64UrlDecode($state['nonce']);
        if (strlen($nonce) !== 32) {
            $this->clear();
            throw new EmergencyRecoveryException('Recovery session is invalid.', 'state');
        }

        return new EmergencyRecoverySessionState(
            $roundcubeUserId,
            $normalized,
            $state['token_id'],
            hash('sha256', $nonce, true),
            $state['verified_at'],
            $state['expires_at'],
        );
    }

    public function hasState(): bool
    {
        return array_key_exists(self::SESSION_KEY, $this->session);
    }

    public function clear(): void
    {
        unset($this->session[self::SESSION_KEY]);
    }

    private static function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $value): string
    {
        $padding = (4 - strlen($value) % 4) % 4;
        $decoded = base64_decode(strtr($value . str_repeat('=', $padding), '-_', '+/'), true);
        return is_string($decoded) ? $decoded : '';
    }
}
