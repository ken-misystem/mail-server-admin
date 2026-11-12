<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

use rcube_db;

final class RoundcubeMfaPolicyRepository implements MfaPolicyRepository
{
    public function __construct(private readonly rcube_db $db)
    {
        $this->db->set_debug(false);
        $this->db->set_option('ignore_errors', true);
        $this->db->set_option('ignore_key_errors', true);
    }

    public function requirement(int $roundcubeUserId): MfaRequirement
    {
        if ($roundcubeUserId <= 0) {
            throw new ManagementException('Authentication is required.', 'authentication');
        }
        $policy = $this->db->table_name('auth_mfa_policy', true);
        $credentials = $this->db->table_name('auth_webauthn_credentials', true);
        $codes = $this->db->table_name('auth_recovery_codes', true);
        $result = $this->db->query(
            "SELECT COALESCE((SELECT `required` FROM {$policy}"
                . " WHERE `user_id` = ? LIMIT 1), 1) AS `required`,"
                . " EXISTS(SELECT 1 FROM {$credentials} WHERE `user_id` = ? AND `enabled` = 1)"
                . " AS `passkey_available`,"
                . " EXISTS(SELECT 1 FROM {$codes} WHERE `user_id` = ?"
                . " AND `used_at` IS NULL AND `revoked_at` IS NULL) AS `recovery_available`",
            $roundcubeUserId,
            $roundcubeUserId,
            $roundcubeUserId,
        );
        if ($result === false || $this->db->is_error($result)) {
            throw new ManagementException('MFA policy lookup failed.', 'storage');
        }
        $row = $this->db->fetch_assoc($result);
        if (!is_array($row)) {
            throw new ManagementException('MFA policy is unavailable.', 'storage');
        }
        foreach (['required', 'passkey_available', 'recovery_available'] as $field) {
            if (!in_array((string) ($row[$field] ?? ''), ['0', '1'], true)) {
                throw new ManagementException('MFA policy state is invalid.', 'storage');
            }
        }
        return new MfaRequirement(
            (string) $row['required'] === '1',
            (string) $row['passkey_available'] === '1',
            (string) $row['recovery_available'] === '1',
        );
    }
}
