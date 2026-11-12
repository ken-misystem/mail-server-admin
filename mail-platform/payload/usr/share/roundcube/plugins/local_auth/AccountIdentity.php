<?php
declare(strict_types=1);
namespace MailServer\RoundcubePasskeyGeneral;

/** Account identity comes from the authenticated session or exact DB lookup. */
final class AccountIdentity
{
    public const MAIL_HOST = 'mx.mi-sys.jp';

    public static function valid(string $account): bool
    {
        return strlen($account) >= 3 && strlen($account) <= 254
            && preg_match('/\A[\x21-\x7e]+\z/D', $account) === 1
            && substr_count($account, '@') === 1
            && !str_starts_with($account, '@') && !str_ends_with($account, '@');
    }

    public static function canonical(string $account): string
    {
        $account = strtolower($account);
        if (!self::valid($account)) {
            throw new \InvalidArgumentException('Invalid account identity.');
        }
        return $account;
    }

    /** Bind both halves; never infer an owner ID from an address or request. */
    public static function requireOwner(\rcube_db $db, int $owner, string $account): string
    {
        $account = self::canonical($account);
        if ($owner <= 0) throw new \InvalidArgumentException('Invalid owner.');
        $db->set_debug(false);
        $db->set_option('ignore_errors', true);
        $db->set_option('ignore_key_errors', true);
        $users = $db->table_name('users', true);
        $result = $db->query("SELECT `user_id`, `username`, `mail_host` FROM {$users} WHERE `user_id` = ?", $owner);
        if ($result === false || $db->is_error($result)) throw new \RuntimeException('Identity lookup failed.');
        $row = $db->fetch_assoc($result);
        $extra = $db->fetch_assoc($result);
        if (!is_array($row) || is_array($extra)
            || (string) ($row['user_id'] ?? '') !== (string) $owner
            || !is_string($row['username'] ?? null)
            || !hash_equals($account, self::canonical($row['username']))
            || ($row['mail_host'] ?? null) !== self::MAIL_HOST) {
            throw new \RuntimeException('Owner identity mismatch.');
        }
        return $account;
    }
}
