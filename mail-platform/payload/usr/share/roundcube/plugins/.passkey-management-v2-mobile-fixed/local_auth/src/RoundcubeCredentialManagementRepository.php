<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

use rcube_db;
use Throwable;

final class RoundcubeCredentialManagementRepository implements CredentialManagementRepository
{
    private bool $transactionOpen = false;

    public function __construct(private readonly rcube_db $db)
    {
        $this->db->set_debug(false);
        $this->db->set_option('ignore_errors', true);
        $this->db->set_option('ignore_key_errors', true);
    }

    public function summaries(int $roundcubeUserId): array
    {
        $table = $this->db->table_name('auth_webauthn_credentials', true);
        $result = $this->query(
            "SELECT `id`, `label`, `enabled`, `created_at`, `last_used_at` FROM {$table}"
            . " WHERE `user_id` = ? ORDER BY `id`",
            $roundcubeUserId,
        );
        $rows = [];
        while ($row = $this->db->fetch_assoc($result)) {
            if (!is_array($row)
                || preg_match('/\A[1-9][0-9]*\z/D', (string) ($row['id'] ?? '')) !== 1
                || !is_string($row['label'] ?? null)
                || !in_array((string) ($row['enabled'] ?? ''), ['0', '1'], true)
                || !is_string($row['created_at'] ?? null)
                || (!is_null($row['last_used_at'] ?? null)
                    && !is_string($row['last_used_at'] ?? null))
            ) {
                throw new ManagementException('Credential metadata is invalid.', 'storage');
            }
            $rows[] = new CredentialSummary(
                (int) $row['id'],
                $row['label'],
                (string) $row['enabled'] === '1',
                $row['created_at'],
                $row['last_used_at'] ?? null,
            );
        }
        return $rows;
    }

    public function enabledCount(int $roundcubeUserId): int
    {
        $table = $this->db->table_name('auth_webauthn_credentials', true);
        $result = $this->query(
            "SELECT COUNT(*) AS `credential_count` FROM {$table}"
            . " WHERE `user_id` = ? AND `enabled` = 1",
            $roundcubeUserId,
        );
        $row = $this->db->fetch_assoc($result);
        $count = is_array($row) ? ($row['credential_count'] ?? null) : null;
        if (preg_match('/\A[0-9]+\z/D', (string) $count) !== 1) {
            throw new ManagementException('Credential count is invalid.', 'storage');
        }
        return (int) $count;
    }

    public function disableIfAlternativeFactor(int $roundcubeUserId, int $credentialRowId): void
    {
        if ($this->transactionOpen || $this->db->startTransaction() !== true) {
            throw new ManagementException('Credential transaction is unavailable.', 'storage');
        }
        $this->transactionOpen = true;

        try {
            $policyTable = $this->db->table_name('auth_mfa_policy', true);
            $policyResult = $this->query(
                "SELECT `required` FROM {$policyTable} WHERE `user_id` = ? FOR UPDATE",
                $roundcubeUserId,
            );
            $policy = $this->db->fetch_assoc($policyResult);
            if (!is_array($policy)
                || !in_array((string) ($policy['required'] ?? ''), ['0', '1'], true)
            ) {
                throw new ManagementException('MFA policy is unavailable.', 'storage');
            }

            $table = $this->db->table_name('auth_webauthn_credentials', true);
            $result = $this->query(
                "SELECT `id`, `enabled` FROM {$table} WHERE `user_id` = ? ORDER BY `id` FOR UPDATE",
                $roundcubeUserId,
            );
            $enabledCount = 0;
            $targetEnabled = false;
            while ($row = $this->db->fetch_assoc($result)) {
                $id = (string) ($row['id'] ?? '');
                $enabled = (string) ($row['enabled'] ?? '');
                if (preg_match('/\A[1-9][0-9]*\z/D', $id) !== 1
                    || !in_array($enabled, ['0', '1'], true)
                ) {
                    throw new ManagementException('Credential state is invalid.', 'storage');
                }
                if ($enabled === '1') {
                    ++$enabledCount;
                    $targetEnabled = $targetEnabled || (int) $id === $credentialRowId;
                }
            }

            if (!$targetEnabled) {
                throw new ManagementException('The credential is unavailable.', 'input');
            }
            if ($enabledCount <= 1) {
                $recoveryTable = $this->db->table_name('auth_recovery_codes', true);
                $recoveryResult = $this->query(
                    "SELECT `id` FROM {$recoveryTable} WHERE `user_id` = ?"
                        . " AND `used_at` IS NULL AND `revoked_at` IS NULL FOR UPDATE",
                    $roundcubeUserId,
                );
                $availableRecoveryCodes = 0;
                while ($recovery = $this->db->fetch_assoc($recoveryResult)) {
                    if (preg_match('/\A[1-9][0-9]*\z/D', (string) ($recovery['id'] ?? '')) !== 1) {
                        throw new ManagementException('Recovery Code state is invalid.', 'storage');
                    }
                    ++$availableRecoveryCodes;
                }
                if ($availableRecoveryCodes < 1) {
                    throw new ManagementException('The final factor cannot be disabled.', 'last-factor');
                }
            }

            $updated = $this->query(
                "UPDATE {$table} SET `enabled` = 0"
                . " WHERE `user_id` = ? AND `id` = ? AND `enabled` = 1",
                $roundcubeUserId,
                $credentialRowId,
            );
            if ($this->db->affected_rows($updated) !== 1 || $this->db->endTransaction() !== true) {
                throw new ManagementException('Credential disablement failed.', 'storage');
            }
            $this->transactionOpen = false;
        } catch (Throwable $e) {
            $this->rollback();
            throw $e;
        }
    }

    public function __destruct()
    {
        $this->rollback();
    }

    private function rollback(): void
    {
        if ($this->transactionOpen) {
            $this->db->rollbackTransaction();
            $this->transactionOpen = false;
        }
    }

    private function query(string $sql, mixed ...$parameters): mixed
    {
        $result = $this->db->query($sql, ...$parameters);
        if ($result === false || $this->db->is_error($result)) {
            throw new ManagementException('Credential storage operation failed.', 'storage');
        }
        return $result;
    }
}
