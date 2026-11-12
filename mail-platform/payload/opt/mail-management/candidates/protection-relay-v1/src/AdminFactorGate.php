<?php

declare(strict_types=1);

namespace MailServer\Management;

/** Factor evidence is server-session-only; no POST/GET parameter is accepted here. */
final class AdminFactorGate
{
    public const SESSION_KEY = 'mail_admin_verified_factor';
    public const MAX_AGE = 600;

    public static function permits(AdminUser $user, mixed $evidence, int $now): bool
    {
        return $user->systemAdmin && self::verified($user, $evidence, $now);
    }

    public static function verified(AdminUser $user, mixed $evidence, int $now): bool
    {
        return $user->active && is_array($evidence)
            && ($evidence['admin_id'] ?? null) === $user->id
            && ($evidence['auth_epoch'] ?? null) === $user->epoch
            && ($evidence['factor'] ?? null) === 'webauthn_uv'
            && is_int($evidence['verified_at'] ?? null)
            && $evidence['verified_at'] <= $now && $evidence['verified_at'] > $now - self::MAX_AGE;
    }
}
