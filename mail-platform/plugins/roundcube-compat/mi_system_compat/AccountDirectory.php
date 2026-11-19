<?php
declare(strict_types=1);

namespace MISystem\RoundcubeCompat;

use PDO;
use RuntimeException;
use Throwable;

final class AccountDirectory
{
    public const SETTINGS = '/etc/roundcube/account_recovery.inc.php';
    private ?PDO $connection = null;

    public function __construct(private array $settings) {}

    public static function settings(): ?array
    {
        if (!is_readable(self::SETTINGS)) {
            return null;
        }
        $value = require self::SETTINGS;
        return is_array($value) ? $value : null;
    }

    private function connection(): PDO
    {
        return $this->connection ??= new PDO($this->settings['db_dsn'], $this->settings['db_user'],
            $this->settings['db_pass'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_EMULATE_PREPARES => false, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
    }

    private function execute(string $sql, array $parameters): \PDOStatement
    {
        $query = $this->connection()->prepare($sql);
        $query->execute($parameters);
        return $query;
    }

    public function epoch(string $mailbox): ?string
    {
        $value = $this->execute('SELECT auth_epoch FROM virtual_users WHERE active = 1 AND email = ? LIMIT 1',
            [$mailbox])->fetchColumn();
        return (is_string($value) || is_int($value)) && ctype_digit((string) $value) ? (string) $value : null;
    }

    public function recovery(string $mailbox): array
    {
        return $this->execute('SELECT verified_at, recovery_email, pending_email, verify_expires_at
            FROM account_recovery WHERE email = ?', [$mailbox])->fetch() ?: [];
    }

    public static function token(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    public static function externalAddress(string $address, array $localDomains): bool
    {
        if (strlen($address) > 254 || !filter_var($address, FILTER_VALIDATE_EMAIL)) {
            return false;
        }
        $domain = strtolower(substr($address, strrpos($address, '@') + 1));
        return !in_array($domain, array_map('strtolower', $localDomains), true);
    }

    public function start(string $mailbox, string $address, string $hash, int $seconds): void
    {
        if ($this->epoch($mailbox) === null) {
            throw new RuntimeException('mailbox_inactive');
        }
        $this->execute('INSERT INTO account_recovery (email, pending_email, verify_token_hash, verify_expires_at)
            VALUES (?, ?, ?, TIMESTAMPADD(SECOND, ?, CURRENT_TIMESTAMP))
            ON DUPLICATE KEY UPDATE verify_expires_at = VALUES(verify_expires_at),
            verify_token_hash = VALUES(verify_token_hash), pending_email = VALUES(pending_email)',
            [$mailbox, $address, $hash, $seconds]);
    }

    public function cancel(string $mailbox, string $hash): void
    {
        $this->execute('UPDATE account_recovery SET verify_expires_at = NULL, verify_token_hash = NULL,
            pending_email = NULL WHERE email = ? AND verify_token_hash = ?', [$mailbox, $hash]);
    }

    public function confirm(string $token): bool
    {
        if (!preg_match('/\A[A-Za-z0-9_-]{40,60}\z/', $token)) {
            return false;
        }
        $hash = hash('sha256', $token);
        $pdo = $this->connection();
        $pdo->beginTransaction();
        try {
            // Serialize competing confirmations and keep ambiguous token matches unusable.
            $keys = $this->execute('SELECT email FROM account_recovery
                WHERE verify_token_hash = ? AND verify_expires_at > CURRENT_TIMESTAMP AND pending_email IS NOT NULL
                LIMIT 2 FOR UPDATE', [$hash])->fetchAll(PDO::FETCH_COLUMN);
            $updated = count($keys) === 1 && $this->execute('UPDATE account_recovery
                SET recovery_email = pending_email, verified_at = CURRENT_TIMESTAMP, verify_expires_at = NULL,
                    verify_token_hash = NULL, pending_email = NULL
                WHERE email = ? AND verify_token_hash = ? AND verify_expires_at > CURRENT_TIMESTAMP',
                [$keys[0], $hash])->rowCount() === 1;
            $pdo->commit();
            return $updated;
        } catch (Throwable $error) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $error;
        }
    }
}
