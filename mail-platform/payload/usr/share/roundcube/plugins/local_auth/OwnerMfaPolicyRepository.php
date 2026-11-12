<?php
declare(strict_types=1);
namespace MailServer\RoundcubePasskeyGeneral;

use MailServer\RoundcubeAuthManagement\ManagementException;
use MailServer\RoundcubeAuthManagement\MfaRequirement;

/** Existing explicit rows are authoritative; unconfigured users are opt-in. */
final class OwnerMfaPolicyRepository
{
    public bool $commitAttempted = false;
    public bool $committed = false;

    public function __construct(private readonly \rcube_db $db)
    {
        $db->set_debug(false);
        $db->set_option('ignore_errors', true);
        $db->set_option('ignore_key_errors', true);
    }

    public function status(int $owner): array
    {
        if ($owner <= 0) throw new ManagementException('Authentication required.', 'authentication');
        $policy = $this->db->table_name('auth_mfa_policy', true);
        $keys = $this->db->table_name('auth_webauthn_credentials', true);
        $codes = $this->db->table_name('auth_recovery_codes', true);
        $result = $this->query("SELECT COALESCE((SELECT `required` FROM {$policy} WHERE `user_id` = ?), 0) AS `required`,"
            . " EXISTS(SELECT 1 FROM {$policy} WHERE `user_id` = ?) AS `configured`,"
            . " EXISTS(SELECT 1 FROM {$keys} WHERE `user_id` = ? AND `enabled` = 1) AS `passkey_available`,"
            . " EXISTS(SELECT 1 FROM {$codes} WHERE `user_id` = ? AND `used_at` IS NULL AND `revoked_at` IS NULL) AS `recovery_available`",
            $owner, $owner, $owner, $owner);
        $row = $this->db->fetch_assoc($result);
        $state = [];
        foreach (['required', 'configured', 'passkey_available', 'recovery_available'] as $key) {
            if (!is_array($row) || !in_array((string) ($row[$key] ?? ''), ['0','1'], true)) {
                throw new ManagementException('Invalid policy metadata.', 'storage');
            }
            $state[$key] = (string) $row[$key] === '1';
        }
        return $state;
    }

    public function requirement(int $owner): MfaRequirement
    {
        $state = $this->status($owner);
        return new MfaRequirement($state['required'], $state['passkey_available'], $state['recovery_available']);
    }

    /** Called only after fresh owner proof and CSRF validation in the plugin. */
    public function save(int $owner, bool $required, callable $invalidate): void
    {
        if ($owner <= 0) throw new ManagementException('Invalid owner.', 'authentication');
        if ($this->db->startTransaction() !== true) throw new ManagementException('Transaction unavailable.', 'storage');
        try {
            $policy = $this->db->table_name('auth_mfa_policy', true);
            $result = $this->query("SELECT `required` FROM {$policy} WHERE `user_id` = ? FOR UPDATE", $owner);
            $row = $this->db->fetch_assoc($result);
            if (is_array($row) && !in_array((string) ($row['required'] ?? ''), ['0','1'], true)) {
                throw new ManagementException('Invalid policy state.', 'storage');
            }
            $users = $this->db->table_name('auth_webauthn_users', true);
            $binding = $this->query("SELECT `user_id` FROM {$users} WHERE `user_id` = ? FOR UPDATE", $owner);
            $bound = $this->db->fetch_assoc($binding);
            if (!is_array($bound) || (string) ($bound['user_id'] ?? '') !== (string) $owner) {
                throw new ManagementException('Owner binding missing.', 'storage');
            }
            $keys = $this->db->table_name('auth_webauthn_credentials', true);
            $result = $this->query("SELECT `enabled` FROM {$keys} WHERE `user_id` = ? ORDER BY `id` FOR UPDATE", $owner);
            $keyAvailable = false;
            while ($row = $this->db->fetch_assoc($result)) {
                if (!is_array($row) || !in_array((string) ($row['enabled'] ?? ''), ['0','1'], true)) {
                    throw new ManagementException('Invalid credential state.', 'storage');
                }
                $keyAvailable = $keyAvailable || (string) $row['enabled'] === '1';
            }
            $codes = $this->db->table_name('auth_recovery_codes', true);
            $result = $this->query("SELECT `id` FROM {$codes} WHERE `user_id` = ? AND `used_at` IS NULL AND `revoked_at` IS NULL ORDER BY `id` FOR UPDATE", $owner);
            $codeAvailable = is_array($this->db->fetch_assoc($result));
            if ($required && (!$keyAvailable || !$codeAvailable)) {
                throw new ManagementException('Save an enabled Passkey and Recovery Codes first.', 'last-factor');
            }
            // Existing reviewed cross-DB epoch invalidator runs before policy
            // mutation; a later failure never leaves other sessions trusted.
            $invalidate();
            $this->query("INSERT INTO {$policy} (`user_id`, `required`) VALUES (?, ?) ON DUPLICATE KEY UPDATE `required` = VALUES(`required`)", $owner, $required ? 1 : 0);
            $this->commitAttempted = true;
            if ($this->db->endTransaction() !== true) throw new ManagementException('Commit unavailable.', 'storage');
            $this->committed = true;
        } catch (\Throwable $error) {
            try { $this->db->rollbackTransaction(); } catch (\Throwable $ignored) {}
            throw $error;
        }
    }

    private function query(string $sql, mixed ...$parameters): mixed
    {
        $result = $this->db->query($sql, ...$parameters);
        if ($result === false || $this->db->is_error($result)) throw new ManagementException('Policy storage failed.', 'storage');
        return $result;
    }
}
