<?php

declare(strict_types=1);

namespace MailServer\Management;

final class AdminMailPolicy
{
    public const PROTECTED_MIGRATION_ACCOUNT = 'ken@mi-sys.jp';

    public static function domain(string $value): string
    {
        $value = strtolower(trim($value));
        if (strlen($value) > 253 || !str_contains($value, '.') || filter_var($value, FILTER_VALIDATE_IP)) {
            throw new \DomainException('invalid_domain');
        }
        foreach (explode('.', $value) as $label) {
            if (!preg_match('/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/D', $label)) {
                throw new \DomainException('invalid_domain');
            }
        }
        return $value;
    }

    public static function localPart(string $value): string
    {
        $value = strtolower(trim($value));
        if (!preg_match('/^[a-z0-9][a-z0-9._-]{0,63}$/D', $value)
            || str_ends_with($value, '.') || str_contains($value, '..')) { throw new \DomainException('invalid_address'); }
        return $value;
    }

    public static function address(string $value): string
    {
        $parts = explode('@', trim($value));
        if (count($parts) !== 2) { throw new \DomainException('invalid_address'); }
        return self::localPart($parts[0]) . '@' . self::domain($parts[1]);
    }

    public static function confirmation(string $expected, string $entered): void
    {
        if (!hash_equals(strtolower($expected), strtolower(trim($entered)))) { throw new \DomainException('confirmation_required'); }
    }

    public static function protectMailbox(string $email): void
    {
        if (strtolower($email) === self::PROTECTED_MIGRATION_ACCOUNT) { throw new \DomainException('migration_protected'); }
    }

    public static function requireEpochAdvance(string $before, string $after): void
    {
        UserPolicyLimits::userId($before); UserPolicyLimits::userId($after);
        if (strlen($after) < strlen($before) || (strlen($after) === strlen($before) && strcmp($after, $before) <= 0)) {
            throw new \DomainException('epoch_update_unverified');
        }
    }
}
