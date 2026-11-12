<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

use rcube_db;
use Throwable;

final class RoundcubeRecoveryCodeRepository implements RecoveryCodeRepository
{
    private bool $transactionOpen = false;
    private ?int $currentFailureCount = null;
    private bool $resetFailureWindow = false;

    public function __construct(private readonly rcube_db $db)
    {
        // Hash values are query parameters. Roundcube expands parameters before
        // debug/error logging, so suppress DB logging for these endpoints.
        $this->db->set_debug(false);
        $this->db->set_option('ignore_errors', true);
        $this->db->set_option('ignore_key_errors', true);
    }

    public function replaceAll(int $roundcubeUserId, array $codes): void
    {
        if (count($codes) !== RecoveryCodeService::CODE_COUNT
            || $this->transactionOpen
            || $this->db->startTransaction() !== true
        ) {
            throw new ManagementException('Recovery Code transaction is unavailable.', 'storage');
        }
        $this->transactionOpen = true;

        try {
            // Lock the durable policy first so factor disablement and Recovery
            // Code replacement use the same lock order. A missing pilot policy
            // is created as required=0 inside this transaction only; it becomes
            // required=1 after the complete replacement set has been stored.
            $policyTable = $this->db->table_name('auth_mfa_policy', true);
            $this->query(
                "INSERT INTO {$policyTable} (`user_id`, `required`) VALUES (?, 0)"
                    . " ON DUPLICATE KEY UPDATE `user_id` = VALUES(`user_id`)",
                $roundcubeUserId,
            );
            $policyResult = $this->query(
                "SELECT `required` FROM {$policyTable} WHERE `user_id` = ? FOR UPDATE",
                $roundcubeUserId,
            );
            $policy = $this->db->fetch_assoc($policyResult);
            if (!is_array($policy)
                || !in_array((string) ($policy['required'] ?? ''), ['0', '1'], true)
            ) {
                throw new ManagementException('MFA policy state is invalid.', 'storage');
            }

            $table = $this->db->table_name('auth_recovery_codes', true);
            $this->query(
                "UPDATE {$table} SET `revoked_at` = CURRENT_TIMESTAMP"
                . " WHERE `user_id` = ? AND `used_at` IS NULL AND `revoked_at` IS NULL",
                $roundcubeUserId,
            );
            foreach ($codes as $code) {
                if (!$code instanceof NewRecoveryCode
                    || strlen($code->selector) !== 16
                    || $code->hash === ''
                ) {
                    throw new ManagementException('Recovery Code record is invalid.', 'storage');
                }
                $this->query(
                    "INSERT INTO {$table} (`user_id`, `selector`, `code_hash`) VALUES (?, ?, ?)",
                    $roundcubeUserId,
                    $code->selector,
                    $code->hash,
                );
            }
            $this->query(
                "UPDATE {$policyTable} SET `required` = 1 WHERE `user_id` = ?",
                $roundcubeUserId,
            );
            if ($this->db->endTransaction() !== true) {
                throw new ManagementException('Recovery Code replacement failed.', 'storage');
            }
            $this->transactionOpen = false;
        } catch (Throwable $e) {
            $this->rollbackAttempt();
            throw $e;
        }
    }

    public function beginAttempt(int $roundcubeUserId, ?string $selector): ?StoredRecoveryCode
    {
        if (($selector !== null && strlen($selector) !== 16)
            || $this->transactionOpen
            || $this->db->startTransaction() !== true
        ) {
            throw new ManagementException('Recovery Code transaction is unavailable.', 'storage');
        }
        $this->transactionOpen = true;

        $rateTable = $this->db->table_name('auth_recovery_rate_limits', true);
        $this->query(
            "INSERT IGNORE INTO {$rateTable} (`user_id`) VALUES (?)",
            $roundcubeUserId,
        );
        $rateResult = $this->query(
            "SELECT `failed_attempts`,"
                . " CASE WHEN `window_started_at` < CURRENT_TIMESTAMP"
                . " - INTERVAL " . RecoveryCodeService::RATE_WINDOW_MINUTES . " MINUTE THEN 1 ELSE 0 END"
                . " AS `window_expired`,"
                . " CASE WHEN `blocked_until` IS NOT NULL AND `blocked_until` > CURRENT_TIMESTAMP"
                . " THEN 1 ELSE 0 END AS `blocked`"
                . " FROM {$rateTable} WHERE `user_id` = ? FOR UPDATE",
            $roundcubeUserId,
        );
        $rate = $this->db->fetch_assoc($rateResult);
        if (!is_array($rate)
            || preg_match('/\A[0-9]+\z/D', (string) ($rate['failed_attempts'] ?? '')) !== 1
            || !in_array((string) ($rate['window_expired'] ?? ''), ['0', '1'], true)
            || !in_array((string) ($rate['blocked'] ?? ''), ['0', '1'], true)
        ) {
            throw new ManagementException('Recovery Code rate state is invalid.', 'storage');
        }
        $this->resetFailureWindow = (string) $rate['window_expired'] === '1';
        $this->currentFailureCount = $this->resetFailureWindow
            ? 0
            : (int) $rate['failed_attempts'];
        if ((string) $rate['blocked'] === '1'
            || $this->currentFailureCount >= RecoveryCodeService::MAX_FAILURES
        ) {
            throw new ManagementException('Recovery Code attempts are temporarily blocked.', 'rate-limit');
        }

        if ($selector === null) {
            return null;
        }

        $table = $this->db->table_name('auth_recovery_codes', true);
        $result = $this->query(
            "SELECT `id`, `code_hash` FROM {$table}"
            . " WHERE `user_id` = ? AND `selector` = ?"
            . " AND `used_at` IS NULL AND `revoked_at` IS NULL LIMIT 1 FOR UPDATE",
            $roundcubeUserId,
            $selector,
        );
        $row = $this->db->fetch_assoc($result);
        if (!is_array($row)) {
            return null;
        }
        if (preg_match('/\A[1-9][0-9]*\z/D', (string) ($row['id'] ?? '')) !== 1
            || !is_string($row['code_hash'] ?? null)
            || $row['code_hash'] === ''
        ) {
            throw new ManagementException('Recovery Code record is invalid.', 'storage');
        }
        return new StoredRecoveryCode((int) $row['id'], $row['code_hash']);
    }

    public function rejectAttempt(int $roundcubeUserId): void
    {
        if (!$this->transactionOpen || $this->currentFailureCount === null) {
            throw new ManagementException('Recovery Code transaction is unavailable.', 'storage');
        }

        try {
            $newCount = $this->currentFailureCount + 1;
            $table = $this->db->table_name('auth_recovery_rate_limits', true);
            $updated = $this->query(
                "UPDATE {$table} SET"
                    . " `window_started_at` = CASE WHEN ? = 1 THEN CURRENT_TIMESTAMP"
                    . " ELSE `window_started_at` END,"
                    . " `failed_attempts` = ?,"
                    . " `blocked_until` = CASE WHEN ? >= " . RecoveryCodeService::MAX_FAILURES
                    . " THEN CURRENT_TIMESTAMP + INTERVAL " . RecoveryCodeService::BLOCK_MINUTES
                    . " MINUTE ELSE NULL END"
                    . " WHERE `user_id` = ?",
                $this->resetFailureWindow ? 1 : 0,
                $newCount,
                $newCount,
                $roundcubeUserId,
            );
            if ($this->db->affected_rows($updated) !== 1 || $this->db->endTransaction() !== true) {
                throw new ManagementException('Recovery Code rejection failed.', 'storage');
            }
            $this->closeTransaction();
        } catch (Throwable $e) {
            $this->rollbackAttempt();
            throw $e;
        }
    }

    public function completeConsumption(int $roundcubeUserId, StoredRecoveryCode $code): void
    {
        if (!$this->transactionOpen) {
            throw new ManagementException('Recovery Code transaction is unavailable.', 'storage');
        }

        try {
            $table = $this->db->table_name('auth_recovery_codes', true);
            $updated = $this->query(
                "UPDATE {$table} SET `used_at` = CURRENT_TIMESTAMP"
                . " WHERE `user_id` = ? AND `id` = ?"
                . " AND `used_at` IS NULL AND `revoked_at` IS NULL",
                $roundcubeUserId,
                $code->id,
            );
            if ($this->db->affected_rows($updated) !== 1) {
                throw new ManagementException('Recovery Code consumption failed.', 'storage');
            }
            $rateTable = $this->db->table_name('auth_recovery_rate_limits', true);
            $rateUpdated = $this->query(
                "UPDATE {$rateTable} SET `window_started_at` = CURRENT_TIMESTAMP,"
                    . " `failed_attempts` = 0, `blocked_until` = NULL WHERE `user_id` = ?",
                $roundcubeUserId,
            );
            // The row was locked by beginAttempt(). MySQL may report zero
            // changed rows when a newly-created limiter row is reset within
            // the same second, so query success and commit are the safe checks.
            if ($this->db->endTransaction() !== true) {
                throw new ManagementException('Recovery Code consumption failed.', 'storage');
            }
            $this->closeTransaction();
        } catch (Throwable $e) {
            $this->rollbackAttempt();
            throw $e;
        }
    }

    public function rollbackAttempt(): void
    {
        if ($this->transactionOpen) {
            $this->db->rollbackTransaction();
        }
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

    private function query(string $sql, mixed ...$parameters): mixed
    {
        $result = $this->db->query($sql, ...$parameters);
        if ($result === false || $this->db->is_error($result)) {
            throw new ManagementException('Recovery Code storage operation failed.', 'storage');
        }
        return $result;
    }
}
