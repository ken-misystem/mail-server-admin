<?php

declare(strict_types=1);

namespace MailServer\Management;

use Symfony\Component\HttpFoundation\Session\SessionInterface;

final class AdminPasskeyCeremony
{
    public const PENDING = 'mail_admin_passkey_ceremony';
    public const PASSWORD_LOGIN = 'mail_admin_password_login';
    public function __construct(private readonly AdminPasskeyStore $store, private readonly AdminWebauthn $validator) {}

    public function start(AdminUser $user, SessionInterface $session, string $kind, string $label = '', ?int $now = null): array
    {
        $now ??= time();
        $session->remove(self::PENDING);
        if (!$user->active || !in_array($kind, ['register', 'assert'], true)) { throw new \DomainException('not_authorized'); }
        $snapshot = $this->store->snapshot($user);
        $first = !$snapshot['has_any'];
        if ($kind === 'register') {
            $label = self::label($label);
            $this->requireRegistration($user, $session, $first, $now);
            $options = $this->validator->registrationOptions($user, $snapshot['handle'], $snapshot['records']);
        } else {
            $session->remove(AdminFactorGate::SESSION_KEY);
            $options = $this->validator->assertionOptions($snapshot['records']);
        }
        $session->set(self::PENDING, ['admin_id' => $user->id, 'auth_epoch' => $user->epoch,
            'kind' => $kind, 'at' => $now, 'options' => $options, 'first' => $first, 'label' => $label]);
        return json_decode($options, true, 32, JSON_THROW_ON_ERROR);
    }

    public function finish(AdminUser $user, SessionInterface $session, string $kind, string $response, ?int $now = null): void
    {
        $now ??= time();
        $pending = $session->remove(self::PENDING); // Consume before parsing/validation, including failures.
        if (!$user->active || !is_array($pending) || ($pending['admin_id'] ?? null) !== $user->id
            || ($pending['auth_epoch'] ?? null) !== $user->epoch || ($pending['kind'] ?? null) !== $kind
            || !is_int($pending['at'] ?? null) || $pending['at'] > $now || $pending['at'] <= $now - AdminWebauthn::TTL
            || !is_string($pending['options'] ?? null) || strlen($response) > 131072) {
            throw new \DomainException('challenge_expired_or_used');
        }
        if ($kind === 'register') {
            $this->requireRegistration($user, $session, $pending['first'], $now);
            $record = $this->validator->registration($response, $pending['options']);
            $this->store->register($user, $record, $pending['label'], $pending['first']);
            $session->remove(AdminFactorGate::SESSION_KEY); // Registration does not itself grant management access.
        } elseif ($kind === 'assert') {
            $session->remove(AdminFactorGate::SESSION_KEY);
            $this->store->authenticate($user, $response, $pending['options'], $this->validator);
            // Only after upstream validation and the serialized DB commit succeed.
            $session->set(AdminFactorGate::SESSION_KEY, ['admin_id' => $user->id, 'auth_epoch' => $user->epoch,
                'factor' => 'webauthn_uv', 'verified_at' => $now]);
        } else { throw new \DomainException('not_authorized'); }
    }

    public static function label(string $label): string
    {
        $label = trim($label);
        if ($label === '' || mb_strlen($label, 'UTF-8') > 128 || !preg_match('//u', $label)
            || preg_match('/[\x00-\x1f\x7f]/', $label)) { throw new \DomainException('invalid_label'); }
        return $label;
    }

    private function requireRegistration(AdminUser $user, SessionInterface $session, bool $first, int $now): void
    {
        if (!$first) {
            if (!AdminFactorGate::verified($user, $session->get(AdminFactorGate::SESSION_KEY), $now)) {
                throw new \DomainException('recent_passkey_required');
            }
            return;
        }
        $login = $session->get(self::PASSWORD_LOGIN);
        if (!is_array($login) || ($login['admin_id'] ?? null) !== $user->id || ($login['auth_epoch'] ?? null) !== $user->epoch
            || !is_int($login['at'] ?? null) || $login['at'] > $now || $login['at'] <= $now - 600) {
            throw new \DomainException('recent_password_login_required');
        }
    }
}
