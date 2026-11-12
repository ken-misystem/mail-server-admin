<?php
declare(strict_types=1);

use MailServer\RoundcubeAuthManagement\ManagementException;

/** Single-use proof binding; never authorizes from a generic recent-factor flag. */
final class OwnerActionSession
{
    private const KEY = 'local_auth_owner_remove_v1';
    public static function issue(array &$session, int $userId, int $rowId, string $ceremony, ?int $now = null): void
    {
        if ($userId <= 0 || $rowId <= 0 || $ceremony === '') {
            throw new ManagementException('Invalid action.', 'input');
        }
        $session[self::KEY] = ['user' => $userId, 'target' => $rowId, 'ceremony' => $ceremony, 'expires' => ($now ?? time()) + 300];
    }
    public static function consume(array &$session, int $userId, string $ceremony, ?int $now = null): int
    {
        $state = $session[self::KEY] ?? null;
        unset($session[self::KEY]);
        $now ??= time();
        if (!is_array($state) || ($state['user'] ?? null) !== $userId || !is_int($state['target'] ?? null)
            || $state['target'] <= 0 || !is_string($state['ceremony'] ?? null) || !hash_equals($state['ceremony'], $ceremony)
            || !is_int($state['expires'] ?? null) || $state['expires'] < $now || $state['expires'] > $now + 300) {
            throw new ManagementException('Action proof is unavailable.', 'authentication');
        }
        return $state['target'];
    }
}
