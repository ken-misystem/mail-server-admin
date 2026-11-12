<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

final class EmergencyRecoveryRegistrationChallengeStore
{
    private const SESSION_KEY = 'local_auth_emergency_registration_v1';
    private const TTL_SECONDS = 300;

    /** @var array<string, mixed> */
    private array $session;

    /** @param array<string, mixed> $session */
    public function __construct(array &$session)
    {
        $this->session =& $session;
    }

    public function issue(
        int $roundcubeUserId,
        string $userHandle,
        string $optionsJson,
        ?int $now = null,
    ): string {
        if ($roundcubeUserId <= 0 || strlen($userHandle) !== 32 || $optionsJson === '') {
            throw new EmergencyRecoveryException('Registration state is invalid.', 'state');
        }
        $now ??= time();
        $ceremonyId = self::base64UrlEncode(random_bytes(32));
        $this->session[self::SESSION_KEY] = [
            'version' => 1,
            'ceremony_id' => $ceremonyId,
            'roundcube_user_id' => $roundcubeUserId,
            'user_handle' => self::base64UrlEncode($userHandle),
            'options_json' => $optionsJson,
            'issued_at' => $now,
            'expires_at' => $now + self::TTL_SECONDS,
        ];
        return $ceremonyId;
    }

    /** @return array{user_handle: string, options_json: string} */
    public function consume(int $roundcubeUserId, string $ceremonyId, ?int $now = null): array
    {
        $now ??= time();
        $state = $this->session[self::SESSION_KEY] ?? null;

        // Consume before validation. A failed response must start a new ceremony.
        unset($this->session[self::SESSION_KEY]);

        if (!is_array($state)
            || ($state['version'] ?? null) !== 1
            || ($state['roundcube_user_id'] ?? null) !== $roundcubeUserId
            || !is_string($state['ceremony_id'] ?? null)
            || !hash_equals($state['ceremony_id'], $ceremonyId)
            || !is_int($state['issued_at'] ?? null)
            || !is_int($state['expires_at'] ?? null)
            || $state['issued_at'] > $now
            || $state['expires_at'] !== $state['issued_at'] + self::TTL_SECONDS
            || $state['expires_at'] < $now
            || !is_string($state['user_handle'] ?? null)
            || !is_string($state['options_json'] ?? null)
        ) {
            throw new EmergencyRecoveryException('Registration state is unavailable.', 'state');
        }

        $userHandle = self::base64UrlDecode($state['user_handle']);
        if (strlen($userHandle) !== 32 || $state['options_json'] === '') {
            throw new EmergencyRecoveryException('Registration state is invalid.', 'state');
        }
        return ['user_handle' => $userHandle, 'options_json' => $state['options_json']];
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
