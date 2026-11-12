<?php
declare(strict_types=1);

use MailServer\RoundcubeAuthManagement\ManagementException;

/** Serializes this owner's registration finishes, including the limit check. */
final class OwnerRegistrationTransaction
{
    public bool $commitAttempted = false;
    public bool $committed = false;

    public function __construct(private readonly rcube_db $db) {}

    public function run(int $owner, callable $operation): void
    {
        if ($owner <= 0) {
            throw new ManagementException('Invalid owner.', 'authentication');
        }
        $this->db->set_debug(false);
        $this->db->set_option('ignore_errors', true);
        $this->db->set_option('ignore_key_errors', true);
        if ($this->db->startTransaction() !== true) {
            throw new ManagementException('Transaction unavailable.', 'storage');
        }
        try {
            // begin() has already created this stable per-owner row. Do not
            // create it here or lock a request-supplied credential identifier.
            $users = $this->db->table_name('auth_webauthn_users', true);
            $result = $this->query("SELECT `user_id` FROM {$users} WHERE `user_id` = ? FOR UPDATE", $owner);
            $row = $this->db->fetch_assoc($result);
            if (!is_array($row) || (string) ($row['user_id'] ?? '') !== (string) $owner) {
                throw new ManagementException('Owner binding unavailable.', 'storage');
            }
            $table = $this->db->table_name('auth_webauthn_credentials', true);
            $rows = $this->query("SELECT `id`, `enabled` FROM {$table} WHERE `user_id` = ? ORDER BY `id` FOR UPDATE", $owner);
            $enabled = 0;
            while ($row = $this->db->fetch_assoc($rows)) {
                if (!is_array($row) || !in_array((string) ($row['enabled'] ?? ''), ['0', '1'], true)) {
                    throw new ManagementException('Invalid credential state.', 'storage');
                }
                $enabled += (int) $row['enabled'];
            }
            if ($enabled >= 10) {
                throw new ManagementException('Credential limit reached.', 'limit');
            }
            // Authorization and the unchanged validator/INSERT are inside the
            // same transaction as both locks. No nested assertion transaction.
            $operation();
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

    private function query(string $sql, mixed ...$parameters): mixed
    {
        $result = $this->db->query($sql, ...$parameters);
        if ($result === false || $this->db->is_error($result)) {
            throw new ManagementException('Storage operation failed.', 'storage');
        }
        return $result;
    }
}
