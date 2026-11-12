<?php

declare(strict_types=1);

namespace MailServer\RoundcubeEmergencyRecovery;

use rcube_db;
use Throwable;

final class RoundcubeEmergencyRecoveryCompletionRepository implements EmergencyRecoveryCompletionRepository
{
    private bool $transactionOpen = false;

    public function __construct(private readonly rcube_db $db)
    {
        $this->db->set_debug(false);
        $this->db->set_option('ignore_errors', true);
        $this->db->set_option('ignore_key_errors', true);
    }

    public function complete(
        int $roundcubeUserId,
        int $tokenId,
        string $sessionNonceHash,
        EmergencyRecoveryCredential $credential,
        string $label,
        int $now,
    ): void {
        if ($roundcubeUserId <= 0
            || $tokenId <= 0
            || strlen($sessionNonceHash) !== 32
            || $this->transactionOpen
            || $this->db->startTransaction() !== true
        ) {
            throw new EmergencyRecoveryException('Recovery completion is unavailable.', 'storage');
        }
        $this->transactionOpen = true;
        try {
            $policyTable = $this->db->table_name('auth_mfa_policy', true);
            $policyResult = $this->query(
                "SELECT `required` FROM {$policyTable} WHERE `user_id` = ? FOR UPDATE",
                $roundcubeUserId,
            );
            $policy = $this->db->fetch_assoc($policyResult);
            if (!is_array($policy) || (string) ($policy['required'] ?? '') !== '1') {
                throw new EmergencyRecoveryException('Required MFA policy is unavailable.', 'storage');
            }

            $usersTable = $this->db->table_name('auth_webauthn_users', true);
            $userResult = $this->query(
                "SELECT `user_handle` FROM {$usersTable} WHERE `user_id` = ? FOR UPDATE",
                $roundcubeUserId,
            );
            $user = $this->db->fetch_assoc($userResult);
            if (!is_array($user)
                || !is_string($user['user_handle'] ?? null)
                || !hash_equals($user['user_handle'], $credential->userHandle)
            ) {
                throw new EmergencyRecoveryException('WebAuthn identity changed.', 'storage');
            }

            $credentialsTable = $this->db->table_name('auth_webauthn_credentials', true);
            $credentialRows = $this->query(
                "SELECT `id`, `credential_id`, `enabled` FROM {$credentialsTable}"
                    . " WHERE `user_id` = ? ORDER BY `id` FOR UPDATE",
                $roundcubeUserId,
            );
            while ($row = $this->db->fetch_assoc($credentialRows)) {
                if (!is_array($row)
                    || preg_match('/\A[1-9][0-9]*\z/D', (string) ($row['id'] ?? '')) !== 1
                    || !is_string($row['credential_id'] ?? null)
                    || !in_array((string) ($row['enabled'] ?? ''), ['0', '1'], true)
                ) {
                    throw new EmergencyRecoveryException('Credential state is invalid.', 'storage');
                }
                if (hash_equals($row['credential_id'], $credential->credentialId)) {
                    throw new EmergencyRecoveryException('Credential is already registered.', 'input');
                }
            }
            $globalDuplicate = $this->query(
                "SELECT `id` FROM {$credentialsTable} WHERE `credential_id` = ? LIMIT 1 FOR UPDATE",
                $credential->credentialId,
            );
            if (is_array($this->db->fetch_assoc($globalDuplicate))) {
                throw new EmergencyRecoveryException('Credential is already registered.', 'input');
            }

            $codesTable = $this->db->table_name('auth_recovery_codes', true);
            $codes = $this->query(
                "SELECT `id` FROM {$codesTable} WHERE `user_id` = ?"
                    . " AND `used_at` IS NULL AND `revoked_at` IS NULL ORDER BY `id` FOR UPDATE",
                $roundcubeUserId,
            );
            while ($row = $this->db->fetch_assoc($codes)) {
                if (preg_match('/\A[1-9][0-9]*\z/D', (string) ($row['id'] ?? '')) !== 1) {
                    throw new EmergencyRecoveryException('Recovery Code state is invalid.', 'storage');
                }
            }

            $tokensTable = $this->db->table_name('auth_factor_recovery_tokens', true);
            $tokenResult = $this->query(
                "SELECT `claim_nonce_hash`, UNIX_TIMESTAMP(`expires_at`) AS `expires_at_unix`"
                    . " FROM {$tokensTable} WHERE `user_id` = ? AND `id` = ?"
                    . " AND `activated_at` IS NOT NULL AND `claimed_at` IS NOT NULL"
                    . " AND `used_at` IS NULL AND `revoked_at` IS NULL LIMIT 1 FOR UPDATE",
                $roundcubeUserId,
                $tokenId,
            );
            $token = $this->db->fetch_assoc($tokenResult);
            if (!is_array($token)
                || !is_string($token['claim_nonce_hash'] ?? null)
                || strlen($token['claim_nonce_hash']) !== 32
                || !hash_equals($token['claim_nonce_hash'], $sessionNonceHash)
                || preg_match('/\A[1-9][0-9]*\z/D', (string) ($token['expires_at_unix'] ?? '')) !== 1
                || (int) $token['expires_at_unix'] <= $now
            ) {
                throw new EmergencyRecoveryException('Recovery token is unavailable.', 'state');
            }

            $rateTable = $this->db->table_name('auth_factor_recovery_rate_limits', true);
            $this->query(
                "INSERT IGNORE INTO {$rateTable} (`user_id`, `window_started_at`)"
                    . " VALUES (?, FROM_UNIXTIME(?))",
                $roundcubeUserId,
                $now,
            );
            $rateResult = $this->query(
                "SELECT `failed_attempts` FROM {$rateTable} WHERE `user_id` = ? FOR UPDATE",
                $roundcubeUserId,
            );
            $rate = $this->db->fetch_assoc($rateResult);
            if (!is_array($rate)
                || preg_match('/\A[0-5]\z/D', (string) ($rate['failed_attempts'] ?? '')) !== 1
            ) {
                throw new EmergencyRecoveryException('Recovery rate state is invalid.', 'storage');
            }

            $this->query(
                "INSERT INTO {$credentialsTable}"
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
            $this->query(
                "UPDATE {$credentialsTable} SET `enabled` = 0"
                    . " WHERE `user_id` = ? AND `credential_id` <> ? AND `enabled` = 1",
                $roundcubeUserId,
                $credential->credentialId,
            );
            $this->query(
                "UPDATE {$codesTable} SET `revoked_at` = FROM_UNIXTIME(?) WHERE `user_id` = ?"
                    . " AND `used_at` IS NULL AND `revoked_at` IS NULL",
                $now,
                $roundcubeUserId,
            );
            $this->query(
                "UPDATE {$tokensTable} SET `revoked_at` = FROM_UNIXTIME(?)"
                    . " WHERE `user_id` = ? AND `id` <> ?"
                    . " AND `used_at` IS NULL AND `revoked_at` IS NULL",
                $now,
                $roundcubeUserId,
                $tokenId,
            );
            $this->query(
                "UPDATE {$policyTable} SET `required` = 1 WHERE `user_id` = ?",
                $roundcubeUserId,
            );
            $used = $this->query(
                "UPDATE {$tokensTable} SET `used_at` = FROM_UNIXTIME(?)"
                    . " WHERE `user_id` = ? AND `id` = ?"
                    . " AND `used_at` IS NULL AND `revoked_at` IS NULL"
                    . " AND `claim_nonce_hash` = ? AND UNIX_TIMESTAMP(`expires_at`) > ?",
                $now,
                $roundcubeUserId,
                $tokenId,
                $sessionNonceHash,
                $now,
            );
            if ($this->db->affected_rows($used) !== 1) {
                throw new EmergencyRecoveryException('Recovery token consumption failed.', 'storage');
            }
            $this->query(
                "UPDATE {$rateTable} SET `window_started_at` = FROM_UNIXTIME(?),"
                    . " `failed_attempts` = 0, `blocked_until` = NULL WHERE `user_id` = ?",
                $now,
                $roundcubeUserId,
            );
            if ($this->db->endTransaction() !== true) {
                throw new EmergencyRecoveryException('Recovery completion failed.', 'storage');
            }
            $this->transactionOpen = false;
        } catch (Throwable $e) {
            $this->rollback();
            if ($e instanceof EmergencyRecoveryException) throw $e;
            throw new EmergencyRecoveryException('Recovery completion failed.', 'storage');
        }
    }

    public function __destruct()
    {
        $this->rollback();
    }

    private function rollback(): void
    {
        if ($this->transactionOpen) $this->db->rollbackTransaction();
        $this->transactionOpen = false;
    }

    private function query(string $sql, mixed ...$parameters): mixed
    {
        $result = $this->db->query($sql, ...$parameters);
        if ($result === false || $this->db->is_error($result)) {
            throw new EmergencyRecoveryException('Recovery completion failed.', 'storage');
        }
        return $result;
    }
}
