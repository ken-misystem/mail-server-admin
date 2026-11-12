<?php

declare(strict_types=1);

namespace MailServer\Management;

/** Business rules only; authentication/CSRF and transaction locking are separate. */
final class AdminPolicy
{
    /** Administrator login identity does not require a locally hosted mail domain. */
    public static function identity(string $email): string
    {
        if (strlen($email) > 254 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            throw new \DomainException('invalid_admin_identity');
        }
        return strtolower($email);
    }

    /** Counts and roles must be loaded while the administrator-role registry is locked. */
    public static function requireRoleChange(
        bool $actorIsSystemAdmin,
        bool $targetIsActiveSystemAdmin,
        bool $targetWillBeActiveSystemAdmin,
        int $activeSystemAdminCount,
    ): void {
        if (!$actorIsSystemAdmin) {
            throw new \DomainException('not_authorized');
        }
        if ($activeSystemAdminCount < 1) {
            throw new \DomainException('invalid_admin_policy');
        }
        if ($targetIsActiveSystemAdmin && !$targetWillBeActiveSystemAdmin
            && $activeSystemAdminCount === 1) {
            throw new \DomainException('last_administrator');
        }
    }
}
