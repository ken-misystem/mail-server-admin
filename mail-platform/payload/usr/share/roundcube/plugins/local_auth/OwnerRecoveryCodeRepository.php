<?php
declare(strict_types=1);

use MailServer\RoundcubeAuthManagement\ManagementException;
use MailServer\RoundcubeAuthManagement\NewRecoveryCode;
use MailServer\RoundcubeAuthManagement\RecoveryCodeRepository;
use MailServer\RoundcubeAuthManagement\RecoveryCodeService;
use MailServer\RoundcubeAuthManagement\RoundcubeRecoveryCodeRepository;
use MailServer\RoundcubeAuthManagement\StoredRecoveryCode;

/** Replacement preserves required=0, required=1, and missing policy alike. */
final class OwnerRecoveryCodeRepository implements RecoveryCodeRepository
{
    private readonly RoundcubeRecoveryCodeRepository $consumer;
    public bool $commitAttempted = false;
    public bool $committed = false;

    public function __construct(private readonly rcube_db $db)
    {
        // Only consume methods are delegated. Its legacy replaceAll() changes
        // MFA policy and MUST NOT be called by owner management.
        $this->consumer = new RoundcubeRecoveryCodeRepository($db);
    }

    public function replaceAll(int $owner, array $codes): void
    {
        if ($owner <= 0 || count($codes) !== RecoveryCodeService::CODE_COUNT) {
            throw new ManagementException('Invalid replacement.', 'input');
        }
        $selectors = [];
        foreach ($codes as $code) {
            if (!$code instanceof NewRecoveryCode || strlen($code->selector) !== 16
                || $code->hash === '' || isset($selectors[bin2hex($code->selector)])) {
                throw new ManagementException('Invalid replacement record.', 'input');
            }
            $selectors[bin2hex($code->selector)] = true;
        }
        if ($this->db->startTransaction() !== true) {
            throw new ManagementException('Transaction unavailable.', 'storage');
        }
        try {
            // Same policy -> credentials order as legacy factor management.
            // Never INSERT/UPDATE a policy, including when the row is absent.
            $policy = $this->db->table_name('auth_mfa_policy', true);
            $result = $this->query("SELECT `required` FROM {$policy} WHERE `user_id` = ? FOR UPDATE", $owner);
            $row = $this->db->fetch_assoc($result);
            if ($row !== false && $row !== null
                && (!is_array($row) || !in_array((string) ($row['required'] ?? ''), ['0', '1'], true))) {
                throw new ManagementException('Invalid policy state.', 'storage');
            }
            $credentials = $this->db->table_name('auth_webauthn_credentials', true);
            $rows = $this->query("SELECT `id`, `enabled` FROM {$credentials} WHERE `user_id` = ? ORDER BY `id` FOR UPDATE", $owner);
            $enabled = 0;
            while ($row = $this->db->fetch_assoc($rows)) {
                if (!is_array($row) || !in_array((string) ($row['enabled'] ?? ''), ['0', '1'], true)) {
                    throw new ManagementException('Invalid credential state.', 'storage');
                }
                $enabled += (int) $row['enabled'];
            }
            if ($enabled === 0) {
                throw new ManagementException('An enabled Passkey is required.', 'last-factor');
            }
            $table = $this->db->table_name('auth_recovery_codes', true);
            $this->query("UPDATE {$table} SET `revoked_at` = CURRENT_TIMESTAMP WHERE `user_id` = ? AND `used_at` IS NULL AND `revoked_at` IS NULL", $owner);
            foreach ($codes as $code) {
                $this->query("INSERT INTO {$table} (`user_id`, `selector`, `code_hash`) VALUES (?, ?, ?)", $owner, $code->selector, $code->hash);
            }
            $this->commitAttempted = true;
            if ($this->db->endTransaction() !== true) {
                throw new ManagementException('Commit outcome unavailable.', 'storage');
            }
            $this->committed = true;
        } catch (Throwable $error) {
            try { $this->db->rollbackTransaction(); } catch (Throwable $ignored) {}
            throw $error;
        }
    }

    public function beginAttempt(int $owner, ?string $selector): ?StoredRecoveryCode
    { return $this->consumer->beginAttempt($owner, $selector); }
    public function rejectAttempt(int $owner): void
    { $this->consumer->rejectAttempt($owner); }
    public function completeConsumption(int $owner, StoredRecoveryCode $code): void
    { $this->consumer->completeConsumption($owner, $code); }
    public function rollbackAttempt(): void
    { $this->consumer->rollbackAttempt(); }

    private function query(string $sql, mixed ...$parameters): mixed
    {
        $result = $this->db->query($sql, ...$parameters);
        if ($result === false || $this->db->is_error($result)) {
            throw new ManagementException('Storage operation failed.', 'storage');
        }
        return $result;
    }
}
