<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

use rcube_db;
use Throwable;

final class RoundcubeEmergencyRecoveryWebauthnSource implements EmergencyRecoveryWebauthnSource
{
    public function __construct(private readonly rcube_db $db)
    {
        // Parameters include credential IDs and user handles. Keep them out of
        // Roundcube database debug/error output for the lifetime of this request.
        $this->db->set_debug(false);
        $this->db->set_option('ignore_errors', true);
        $this->db->set_option('ignore_key_errors', true);
    }

    public function userHandle(int $roundcubeUserId): string
    {
        $table = $this->db->table_name('auth_webauthn_users', true);
        $result = $this->query(
            "SELECT `user_handle` FROM {$table} WHERE `user_id` = ? LIMIT 1",
            $roundcubeUserId,
        );
        $row = $this->db->fetch_assoc($result);
        $handle = is_array($row) ? ($row['user_handle'] ?? null) : null;
        if (!is_string($handle) || strlen($handle) !== 32) {
            throw new EmergencyRecoveryException('WebAuthn identity is unavailable.', 'storage');
        }
        return $handle;
    }

    public function allCredentialDescriptors(int $roundcubeUserId): array
    {
        $table = $this->db->table_name('auth_webauthn_credentials', true);
        $result = $this->query(
            "SELECT `credential_id`, `transports_json` FROM {$table}"
                . " WHERE `user_id` = ? ORDER BY `id`",
            $roundcubeUserId,
        );
        $descriptors = [];
        while ($row = $this->db->fetch_assoc($result)) {
            if (!is_array($row)
                || !is_string($row['credential_id'] ?? null)
                || strlen($row['credential_id']) < 1
                || strlen($row['credential_id']) > 1023
                || !is_string($row['transports_json'] ?? null)
            ) {
                throw new EmergencyRecoveryException('Credential metadata is invalid.', 'storage');
            }
            try {
                $transports = json_decode($row['transports_json'], true, 8, JSON_THROW_ON_ERROR);
            } catch (Throwable $e) {
                throw new EmergencyRecoveryException('Credential metadata is invalid.', 'storage');
            }
            if (!is_array($transports) || array_filter($transports, 'is_string') !== $transports) {
                throw new EmergencyRecoveryException('Credential metadata is invalid.', 'storage');
            }
            $descriptors[] = [
                'id' => $row['credential_id'],
                'transports' => array_values($transports),
            ];
        }
        return $descriptors;
    }

    public function credentialExists(string $credentialId): bool
    {
        $table = $this->db->table_name('auth_webauthn_credentials', true);
        $result = $this->query(
            "SELECT `id` FROM {$table} WHERE `credential_id` = ? LIMIT 1",
            $credentialId,
        );
        return is_array($this->db->fetch_assoc($result));
    }

    private function query(string $sql, mixed ...$parameters): mixed
    {
        $result = $this->db->query($sql, ...$parameters);
        if ($result === false || $this->db->is_error($result)) {
            throw new EmergencyRecoveryException('Credential storage is unavailable.', 'storage');
        }
        return $result;
    }
}
