<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuth;

final class AssertionChallengeStore
{
    private const SESSION_KEY = 'local_auth_assertion_v1';

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
        $now ??= time();
        $ceremonyId = self::base64UrlEncode(random_bytes(32));

        $this->session[self::SESSION_KEY] = [
            'ceremony_id' => $ceremonyId,
            'roundcube_user_id' => $roundcubeUserId,
            'user_handle' => self::base64UrlEncode($userHandle),
            'options_json' => $optionsJson,
            'expires_at' => $now + RegistrationConfig::CHALLENGE_TTL_SECONDS,
        ];

        return $ceremonyId;
    }

    /** @return array{user_handle: string, options_json: string} */
    public function consume(int $roundcubeUserId, string $ceremonyId, ?int $now = null): array
    {
        $now ??= time();
        $state = $this->session[self::SESSION_KEY] ?? null;
        unset($this->session[self::SESSION_KEY]);

        if (!is_array($state)) {
            throw new RegistrationException(
                'Assertion ceremony is missing or already used.',
                diagnosticCode: 'state',
            );
        }

        $storedId = $state['ceremony_id'] ?? null;
        if (!is_string($storedId) || !hash_equals($storedId, $ceremonyId)) {
            throw new RegistrationException(
                'Assertion ceremony does not match.',
                diagnosticCode: 'state',
            );
        }

        if (($state['roundcube_user_id'] ?? null) !== $roundcubeUserId) {
            throw new RegistrationException(
                'Assertion ceremony belongs to another user.',
                diagnosticCode: 'state',
            );
        }

        if (!is_int($state['expires_at'] ?? null) || $state['expires_at'] < $now) {
            throw new RegistrationException(
                'Assertion ceremony has expired.',
                diagnosticCode: 'state',
            );
        }

        $encodedHandle = $state['user_handle'] ?? null;
        $optionsJson = $state['options_json'] ?? null;
        if (!is_string($encodedHandle) || !is_string($optionsJson)) {
            throw new RegistrationException(
                'Assertion ceremony is invalid.',
                diagnosticCode: 'state',
            );
        }

        return [
            'user_handle' => self::base64UrlDecode($encodedHandle),
            'options_json' => $optionsJson,
        ];
    }

    private static function base64UrlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $value): string
    {
        $padding = (4 - strlen($value) % 4) % 4;
        $decoded = base64_decode(strtr($value . str_repeat('=', $padding), '-_', '+/'), true);
        if ($decoded === false) {
            throw new RegistrationException(
                'Assertion ceremony encoding is invalid.',
                diagnosticCode: 'state',
            );
        }

        return $decoded;
    }
}
