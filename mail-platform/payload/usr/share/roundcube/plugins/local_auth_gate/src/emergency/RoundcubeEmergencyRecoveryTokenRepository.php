<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

use rcube_db;
use Throwable;

final class RoundcubeEmergencyRecoveryTokenRepository implements EmergencyRecoveryTokenRepository
{
    private bool $transactionOpen = false;
    private ?int $currentFailureCount = null;
    private bool $resetFailureWindow = false;

    public function __construct(private readonly rcube_db $db)
    {
        $this->db->set_debug(false);
        $this->db->set_option('ignore_errors', true);
        $this->db->set_option('ignore_key_errors', true);
    }

    public function replacePending(int $roundcubeUserId, NewEmergencyRecoveryToken $token): int
    {
        if ($roundcubeUserId <= 0
            || strlen($token->selector) !== 16
            || $token->hash === ''
            || $token->expiresAt <= $token->issuedAt
            || $this->transactionOpen
            || $this->db->startTransaction() !== true
        ) {
            throw new EmergencyRecoveryException('Recovery token transaction is unavailable.', 'storage');
        }
        $this->transactionOpen = true;
        try {
            $table = $this->db->table_name('auth_factor_recovery_tokens', true);
            $this->query(
                "UPDATE {$table} SET `revoked_at` = FROM_UNIXTIME(?) WHERE `user_id` = ?"
                    . " AND `used_at` IS NULL AND `revoked_at` IS NULL",
                $token->issuedAt,
                $roundcubeUserId,
            );
            $this->query(
                "INSERT INTO {$table}"
                    . " (`user_id`, `selector`, `token_hash`, `issued_at`, `expires_at`)"
                    . " VALUES (?, ?, ?, FROM_UNIXTIME(?), FROM_UNIXTIME(?))",
                $roundcubeUserId,
                $token->selector,
                $token->hash,
                $token->issuedAt,
                $token->expiresAt,
            );
            $tokenId = $this->db->insert_id();
            if (preg_match('/\A[1-9][0-9]*\z/D', (string) $tokenId) !== 1
                || $this->db->endTransaction() !== true
            ) {
                throw new EmergencyRecoveryException('Recovery token creation failed.', 'storage');
            }
            $this->closeTransaction();
            return (int) $tokenId;
        } catch (Throwable $e) {
            $this->rollbackAttempt();
            throw self::safe($e);
        }
    }

    public function activate(int $roundcubeUserId, int $tokenId): void
    {
        $table = $this->db->table_name('auth_factor_recovery_tokens', true);
        $result = $this->query(
            "UPDATE {$table} SET `activated_at` = CURRENT_TIMESTAMP"
                . " WHERE `user_id` = ? AND `id` = ? AND `activated_at` IS NULL"
                . " AND `claimed_at` IS NULL AND `used_at` IS NULL AND `revoked_at` IS NULL"
                . " AND `expires_at` > CURRENT_TIMESTAMP",
            $roundcubeUserId,
            $tokenId,
        );
        if ($this->db->affected_rows($result) !== 1) {
            throw new EmergencyRecoveryException('Recovery token activation failed.', 'storage');
        }
    }

    public function revokePending(int $roundcubeUserId, int $tokenId): void
    {
        $table = $this->db->table_name('auth_factor_recovery_tokens', true);
        $this->query(
            "UPDATE {$table} SET `revoked_at` = CURRENT_TIMESTAMP"
                . " WHERE `user_id` = ? AND `id` = ? AND `used_at` IS NULL AND `revoked_at` IS NULL",
            $roundcubeUserId,
            $tokenId,
        );
    }

    public function beginAttempt(
        int $roundcubeUserId,
        ?string $selector,
        int $now,
    ): ?StoredEmergencyRecoveryToken {
        if ($roundcubeUserId <= 0
            || ($selector !== null && strlen($selector) !== 16)
            || $this->transactionOpen
            || $this->db->startTransaction() !== true
        ) {
            throw new EmergencyRecoveryException('Recovery token transaction is unavailable.', 'storage');
        }
        $this->transactionOpen = true;
        try {
            $rateTable = $this->db->table_name('auth_factor_recovery_rate_limits', true);
            $this->query(
                "INSERT IGNORE INTO {$rateTable} (`user_id`, `window_started_at`)"
                    . " VALUES (?, FROM_UNIXTIME(?))",
                $roundcubeUserId,
                $now,
            );
            $rateResult = $this->query(
                "SELECT `failed_attempts`,"
                    . " CASE WHEN UNIX_TIMESTAMP(`window_started_at`) < ? THEN 1 ELSE 0 END"
                    . " AS `window_expired`,"
                    . " CASE WHEN `blocked_until` IS NOT NULL"
                    . " AND UNIX_TIMESTAMP(`blocked_until`) > ? THEN 1 ELSE 0 END AS `blocked`"
                    . " FROM {$rateTable} WHERE `user_id` = ? FOR UPDATE",
                $now - EmergencyRecoveryTokenService::RATE_WINDOW_SECONDS,
                $now,
                $roundcubeUserId,
            );
            $rate = $this->db->fetch_assoc($rateResult);
            if (!is_array($rate)
                || preg_match('/\A[0-5]\z/D', (string) ($rate['failed_attempts'] ?? '')) !== 1
                || !in_array((string) ($rate['window_expired'] ?? ''), ['0', '1'], true)
                || !in_array((string) ($rate['blocked'] ?? ''), ['0', '1'], true)
            ) {
                throw new EmergencyRecoveryException('Recovery rate state is invalid.', 'storage');
            }
            $this->resetFailureWindow = (string) $rate['window_expired'] === '1';
            $this->currentFailureCount = $this->resetFailureWindow ? 0 : (int) $rate['failed_attempts'];
            if ((string) $rate['blocked'] === '1'
                || $this->currentFailureCount >= EmergencyRecoveryTokenService::MAX_FAILURES
            ) {
                throw new EmergencyRecoveryException('Recovery attempts are blocked.', 'rate-limit');
            }
            if ($selector === null) return null;

            $table = $this->db->table_name('auth_factor_recovery_tokens', true);
            $result = $this->query(
                "SELECT `id`, `token_hash`, UNIX_TIMESTAMP(`issued_at`) AS `issued_at_unix`,"
                    . " UNIX_TIMESTAMP(`expires_at`) AS `expires_at_unix` FROM {$table}"
                    . " WHERE `user_id` = ? AND `selector` = ? AND `activated_at` IS NOT NULL"
                    . " AND UNIX_TIMESTAMP(`activated_at`) <= ? AND `claimed_at` IS NULL"
                    . " AND `used_at` IS NULL AND `revoked_at` IS NULL"
                    . " AND UNIX_TIMESTAMP(`expires_at`) > ? LIMIT 1 FOR UPDATE",
                $roundcubeUserId,
                $selector,
                $now,
                $now,
            );
            $row = $this->db->fetch_assoc($result);
            if (!is_array($row)) return null;
            foreach (['id', 'issued_at_unix', 'expires_at_unix'] as $field) {
                if (preg_match('/\A[1-9][0-9]*\z/D', (string) ($row[$field] ?? '')) !== 1) {
                    throw new EmergencyRecoveryException('Recovery token state is invalid.', 'storage');
                }
            }
            if (!is_string($row['token_hash'] ?? null) || $row['token_hash'] === '') {
                throw new EmergencyRecoveryException('Recovery token state is invalid.', 'storage');
            }
            return new StoredEmergencyRecoveryToken(
                (int) $row['id'],
                $row['token_hash'],
                (int) $row['issued_at_unix'],
                (int) $row['expires_at_unix'],
            );
        } catch (Throwable $e) {
            if (!$e instanceof EmergencyRecoveryException || $e->diagnosticCode !== 'rate-limit') {
                $this->rollbackAttempt();
            }
            throw self::safe($e);
        }
    }

    public function rejectAttempt(int $roundcubeUserId, int $now): void
    {
        if (!$this->transactionOpen || $this->currentFailureCount === null) {
            throw new EmergencyRecoveryException('Recovery token transaction is unavailable.', 'storage');
        }
        try {
            $newCount = $this->currentFailureCount + 1;
            $table = $this->db->table_name('auth_factor_recovery_rate_limits', true);
            $result = $this->query(
                "UPDATE {$table} SET `window_started_at` = CASE WHEN ? = 1 THEN FROM_UNIXTIME(?)"
                    . " ELSE `window_started_at` END, `failed_attempts` = ?,"
                    . " `blocked_until` = CASE WHEN ? >= ? THEN FROM_UNIXTIME(?) ELSE NULL END"
                    . " WHERE `user_id` = ?",
                $this->resetFailureWindow ? 1 : 0,
                $now,
                $newCount,
                $newCount,
                EmergencyRecoveryTokenService::MAX_FAILURES,
                $now + EmergencyRecoveryTokenService::BLOCK_SECONDS,
                $roundcubeUserId,
            );
            if ($this->db->affected_rows($result) !== 1 || $this->db->endTransaction() !== true) {
                throw new EmergencyRecoveryException('Recovery rejection failed.', 'storage');
            }
            $this->closeTransaction();
        } catch (Throwable $e) {
            $this->rollbackAttempt();
            throw self::safe($e);
        }
    }

    public function completeClaim(
        int $roundcubeUserId,
        StoredEmergencyRecoveryToken $token,
        string $sessionNonceHash,
        int $now,
    ): void {
        if (!$this->transactionOpen || strlen($sessionNonceHash) !== 32) {
            throw new EmergencyRecoveryException('Recovery token transaction is unavailable.', 'storage');
        }
        try {
            $table = $this->db->table_name('auth_factor_recovery_tokens', true);
            $result = $this->query(
                "UPDATE {$table} SET `claimed_at` = FROM_UNIXTIME(?), `claim_nonce_hash` = ?"
                    . " WHERE `user_id` = ? AND `id` = ? AND `claimed_at` IS NULL"
                    . " AND `activated_at` IS NOT NULL AND `used_at` IS NULL"
                    . " AND `revoked_at` IS NULL AND UNIX_TIMESTAMP(`expires_at`) > ?",
                $now,
                $sessionNonceHash,
                $roundcubeUserId,
                $token->id,
                $now,
            );
            if ($this->db->affected_rows($result) !== 1) {
                throw new EmergencyRecoveryException('Recovery token claim failed.', 'storage');
            }
            $rateTable = $this->db->table_name('auth_factor_recovery_rate_limits', true);
            $this->query(
                "UPDATE {$rateTable} SET `window_started_at` = FROM_UNIXTIME(?),"
                    . " `failed_attempts` = 0, `blocked_until` = NULL WHERE `user_id` = ?",
                $now,
                $roundcubeUserId,
            );
            if ($this->db->endTransaction() !== true) {
                throw new EmergencyRecoveryException('Recovery token claim failed.', 'storage');
            }
            $this->closeTransaction();
        } catch (Throwable $e) {
            $this->rollbackAttempt();
            throw self::safe($e);
        }
    }

    public function rollbackAttempt(): void
    {
        if ($this->transactionOpen) $this->db->rollbackTransaction();
        $this->closeTransaction();
    }

    public function __destruct()
    {
        $this->rollbackAttempt();
    }

    private function closeTransaction(): void
    {
        $this->transactionOpen = false;
        $this->currentFailureCount = null;
        $this->resetFailureWindow = false;
    }

    private static function safe(Throwable $exception): EmergencyRecoveryException
    {
        return $exception instanceof EmergencyRecoveryException
            ? $exception
            : new EmergencyRecoveryException('Recovery storage failed.', 'storage');
    }

    private function query(string $sql, mixed ...$parameters): mixed
    {
        $result = $this->db->query($sql, ...$parameters);
        if ($result === false || $this->db->is_error($result)) {
            throw new EmergencyRecoveryException('Recovery storage failed.', 'storage');
        }
        return $result;
    }
}
