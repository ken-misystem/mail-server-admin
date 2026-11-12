<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuth;

use rcube_db;

final class RoundcubeCredentialRepository implements CredentialRepository, AssertionCredentialRepository
{
    private bool $assertionTransactionOpen = false;

    public function __construct(private readonly rcube_db $db)
    {
        // rcube_db expands parameters before debug/error logging. Credential
        // IDs and serialized public-key records must never reach those logs.
        // This repository is instantiated only in endpoints that exit after
        // their response, so suppressing DB logging is scoped to that request.
        $this->db->set_debug(false);
        $this->db->set_option('ignore_errors', true);
        $this->db->set_option('ignore_key_errors', true);
    }

    public function getOrCreateUserHandle(int $roundcubeUserId): string
    {
        $handle = $this->getUserHandle($roundcubeUserId);
        if (is_string($handle)) {
            return $handle;
        }

        $users = $this->db->table_name('auth_webauthn_users', true);
        $candidate = random_bytes(32);
        // INSERT IGNORE plus re-read is race-safe for one row per user and does
        // not expose the handle in an error message.
        $this->query(
            "INSERT IGNORE INTO {$users} (`user_id`, `user_handle`) VALUES (?, ?)",
            $roundcubeUserId,
            $candidate,
        );

        $handle = $this->getUserHandle($roundcubeUserId);

        if (!is_string($handle) || strlen($handle) !== 32) {
            throw new RegistrationException('Unable to obtain a WebAuthn user handle.');
        }

        return $handle;
    }

    public function getUserHandle(int $roundcubeUserId): ?string
    {
        $users = $this->db->table_name('auth_webauthn_users', true);
        $result = $this->query(
            "SELECT `user_handle` FROM {$users} WHERE `user_id` = ?",
            $roundcubeUserId,
        );
        $row = $this->db->fetch_assoc($result);
        $handle = is_array($row) ? ($row['user_handle'] ?? null) : null;

        return is_string($handle) ? $handle : null;
    }

    public function enabledCredentialDescriptors(int $roundcubeUserId): array
    {
        $table = $this->db->table_name('auth_webauthn_credentials', true);
        $result = $this->query(
            "SELECT `credential_id`, `transports_json` FROM {$table}"
            . " WHERE `user_id` = ? AND `enabled` = 1 ORDER BY `id`",
            $roundcubeUserId,
        );
        $rows = [];

        while ($row = $this->db->fetch_assoc($result)) {
            $transports = json_decode((string) $row['transports_json'], true);
            $rows[] = [
                'id' => (string) $row['credential_id'],
                'transports' => is_array($transports)
                    ? array_values(array_filter($transports, 'is_string'))
                    : [],
            ];
        }

        return $rows;
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

    public function saveNewCredential(
        int $roundcubeUserId,
        ValidatedCredential $credential,
        string $label,
    ): void {
        if ($this->credentialExists($credential->credentialId)) {
            throw new RegistrationException(
                'This credential is already registered.',
                diagnosticCode: 'credential',
            );
        }

        $table = $this->db->table_name('auth_webauthn_credentials', true);
        $this->query(
            "INSERT INTO {$table}"
            . " (`user_id`, `credential_id`, `user_handle`, `credential_record_json`,"
            . " `sign_count`, `transports_json`, `label`, `enabled`)"
            . " VALUES (?, ?, ?, ?, ?, ?, ?, 1)",
            $roundcubeUserId,
            $credential->credentialId,
            $credential->userHandle,
            $credential->credentialRecordJson,
            $credential->signCount,
            json_encode($credential->transports, JSON_THROW_ON_ERROR),
            $label,
        );
    }

    public function lockEnabledCredential(
        int $roundcubeUserId,
        string $credentialId,
    ): StoredCredential {
        if ($this->assertionTransactionOpen || $this->db->startTransaction() !== true) {
            throw new RegistrationException(
                'Unable to start credential transaction.',
                diagnosticCode: 'storage',
            );
        }
        $this->assertionTransactionOpen = true;

        try {
            $table = $this->db->table_name('auth_webauthn_credentials', true);
            $result = $this->query(
                "SELECT `credential_id`, `user_handle`, `credential_record_json` FROM {$table}"
                . " WHERE `user_id` = ? AND `credential_id` = ? AND `enabled` = 1"
                . " LIMIT 1 FOR UPDATE",
                $roundcubeUserId,
                $credentialId,
            );
            $row = $this->db->fetch_assoc($result);
            if (!is_array($row)
                || !is_string($row['credential_id'] ?? null)
                || !is_string($row['user_handle'] ?? null)
                || !is_string($row['credential_record_json'] ?? null)
            ) {
                throw new RegistrationException(
                    'Enabled credential is unavailable.',
                    diagnosticCode: 'credential',
                );
            }

            return new StoredCredential(
                $row['credential_id'],
                $row['user_handle'],
                $row['credential_record_json'],
            );
        } catch (\Throwable $e) {
            $this->rollbackAssertion();
            throw $e;
        }
    }

    public function completeAssertion(
        int $roundcubeUserId,
        StoredCredential $stored,
        ValidatedAssertion $validated,
    ): void {
        if (!$this->assertionTransactionOpen) {
            throw new RegistrationException(
                'Credential transaction is unavailable.',
                diagnosticCode: 'storage',
            );
        }

        try {
            $table = $this->db->table_name('auth_webauthn_credentials', true);
            $result = $this->query(
                "UPDATE {$table} SET `credential_record_json` = ?, `sign_count` = ?,"
                . " `last_used_at` = CURRENT_TIMESTAMP"
                . " WHERE `user_id` = ? AND `credential_id` = ? AND `enabled` = 1"
                . " AND `credential_record_json` = ?",
                $validated->credentialRecordJson,
                $validated->signCount,
                $roundcubeUserId,
                $stored->credentialId,
                $stored->credentialRecordJson,
            );
            if ($this->db->affected_rows($result) !== 1 || $this->db->endTransaction() !== true) {
                throw new RegistrationException(
                    'Credential assertion update failed.',
                    diagnosticCode: 'storage',
                );
            }
            $this->assertionTransactionOpen = false;
        } catch (\Throwable $e) {
            $this->rollbackAssertion();
            throw $e;
        }
    }

    public function rollbackAssertion(): void
    {
        if ($this->assertionTransactionOpen) {
            $this->db->rollbackTransaction();
            $this->assertionTransactionOpen = false;
        }
    }

    public function __destruct()
    {
        $this->rollbackAssertion();
    }

    private function query(string $sql, mixed ...$parameters): mixed
    {
        $result = $this->db->query($sql, ...$parameters);
        if ($result === false || $this->db->is_error($result)) {
            // The unique credential_id key is the final duplicate/race guard.
            // Never include the SQL or database error: parameters can contain
            // credential IDs, user handles, and serialized public-key records.
            throw new RegistrationException(
                'Credential storage operation failed.',
                diagnosticCode: 'storage',
            );
        }

        return $result;
    }
}
