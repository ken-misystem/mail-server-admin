<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthGate;

use PDO;

/** Short-lived mail backend credentials, scoped by the Dovecot Webmail passdb. */
final class WebmailSessionCredential
{
    public const CONFIG = '/etc/roundcube/webmail-passkey.json';
    public const TTL = 3600;

    public static function configured(): bool
    {
        return is_readable(self::CONFIG);
    }

    private static function connect(): PDO
    {
        $info = lstat(self::CONFIG);
        if (!$info || is_link(self::CONFIG) || !is_file(self::CONFIG) || $info['uid'] !== 0
            || ($info['mode'] & 0777) !== 0640 || $info['nlink'] !== 1 || $info['size'] > 4096) {
            throw new \RuntimeException('webmail_passkey_configuration');
        }
        $config = json_decode(file_get_contents(self::CONFIG), true, 8, JSON_THROW_ON_ERROR);
        $name = 'roundcube_webmail_passkey';
        if (!is_array($config) || ($config['user'] ?? null) !== $name
            || !is_string($config['dsn'] ?? null) || !preg_match(
                '~\Amysql:unix_socket=/[a-zA-Z0-9/._-]+;dbname=mailserver;charset=utf8mb4\z~D', $config['dsn'])
            || !is_string($config['password'] ?? null) || !preg_match('/\A[A-Za-z0-9_-]{64}\z/D', $config['password'])) {
            throw new \RuntimeException('webmail_passkey_configuration');
        }
        $db = new PDO($config['dsn'], $name, $config['password'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        if ($db->query('SELECT CURRENT_USER()')->fetchColumn() !== $name . '@localhost') {
            throw new \RuntimeException('webmail_passkey_database_identity');
        }
        return $db;
    }

    public static function registerChallenge(string $ceremony): void
    {
        $db = self::connect();
        $db->exec('DELETE FROM webmail_passkey_challenges WHERE expires_at <= UTC_TIMESTAMP() ORDER BY expires_at LIMIT 64');
        $db->prepare('INSERT INTO webmail_passkey_challenges (challenge_hash, expires_at)
            VALUES (UNHEX(?), TIMESTAMPADD(SECOND, 120, UTC_TIMESTAMP()))')->execute([hash('sha256', $ceremony)]);
    }

    public static function consumeChallenge(string $ceremony): bool
    {
        $query = self::connect()->prepare('DELETE FROM webmail_passkey_challenges
            WHERE challenge_hash=UNHEX(?) AND expires_at > UTC_TIMESTAMP()');
        $query->execute([hash('sha256', $ceremony)]);
        return $query->rowCount() === 1;
    }

    public static function issue(string $email, string $epoch): array
    {
        if (!ctype_digit($epoch)) { throw new \DomainException('webmail_passkey_epoch'); }
        $selector = bin2hex(random_bytes(16));
        $secret = 'misw_' . $selector . '_' . rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $passwordHash = '{SHA256}' . base64_encode(hash('sha256', $secret, true));
        $db = self::connect();
        $db->exec('DELETE FROM webmail_passkey_sessions WHERE expires_at <= UTC_TIMESTAMP() ORDER BY expires_at LIMIT 64');
        $statement = $db->prepare('INSERT INTO webmail_passkey_sessions
            (selector, owner_id, auth_epoch, password_hash, expires_at)
            SELECT UNHEX(?), u.id, u.auth_epoch, ?, TIMESTAMPADD(SECOND, ?, UTC_TIMESTAMP())
            FROM virtual_users u JOIN virtual_domains d ON d.id=u.domain_id
            WHERE BINARY u.email=BINARY ? AND u.active=1 AND d.active=1 AND u.auth_epoch=?');
        $statement->execute([$selector, $passwordHash, self::TTL, $email, $epoch]);
        if ($statement->rowCount() !== 1) {
            self::revoke($selector);
            throw new \RuntimeException('webmail_passkey_owner_changed');
        }
        return [$selector, $secret];
    }

    public static function revoke(string $selector): void
    {
        if (!preg_match('/\A[0-9a-f]{32}\z/D', $selector)) {
            throw new \DomainException('webmail_passkey_selector');
        }
        self::connect()->prepare('DELETE FROM webmail_passkey_sessions WHERE selector=UNHEX(?)')->execute([$selector]);
    }
}
