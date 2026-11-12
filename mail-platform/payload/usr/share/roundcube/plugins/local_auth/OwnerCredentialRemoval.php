<?php
declare(strict_types=1);

use MailServer\RoundcubeAuthManagement\ManagementException;

/** Owner-only soft removal; keeps at least one active Passkey, no policy-row seed. */
final class OwnerCredentialRemoval
{
    public bool $mutationAttempted = false;
    public function __construct(private readonly rcube_db $db) {}
    public function remove(int $userId, int $rowId, callable $invalidateOtherSessions): void
    {
        if ($userId <= 0 || $rowId <= 0) {
            throw new ManagementException('Invalid owner or target.', 'input');
        }
        $this->db->set_debug(false);
        $this->db->set_option('ignore_errors', true);
        $this->db->set_option('ignore_key_errors', true);
        if ($this->db->startTransaction() !== true) {
            throw new ManagementException('Transaction unavailable.', 'storage');
        }
        try {
            $table = $this->db->table_name('auth_webauthn_credentials', true);
            $rows = $this->query("SELECT `id`, `enabled` FROM {$table} WHERE `user_id` = ? ORDER BY `id` FOR UPDATE", $userId);
            $enabled = 0; $target = false;
            while ($row = $this->db->fetch_assoc($rows)) {
                if (!is_array($row) || preg_match('/\A[1-9][0-9]*\z/D', (string) ($row['id'] ?? '')) !== 1
                    || !in_array((string) ($row['enabled'] ?? ''), ['0', '1'], true)) {
                    throw new ManagementException('Invalid credential state.', 'storage');
                }
                if ((string) $row['enabled'] === '1') {
                    ++$enabled;
                    $target = $target || (int) $row['id'] === $rowId;
                }
            }
            if (!$target) { throw new ManagementException('Target unavailable.', 'input'); }
            if ($enabled <= 1) { throw new ManagementException('Keep one Passkey.', 'last-factor'); }
            // Same existing epoch helper as pilot removal, before credential mutation.
            $invalidateOtherSessions();
            $this->mutationAttempted = true;
            $changed = $this->query("UPDATE {$table} SET `enabled` = 0 WHERE `user_id` = ? AND `id` = ? AND `enabled` = 1", $userId, $rowId);
            if ($this->db->affected_rows($changed) !== 1 || $this->db->endTransaction() !== true) {
                throw new ManagementException('Removal incomplete.', 'storage');
            }
        } catch (Throwable $error) {
            $this->db->rollbackTransaction();
            throw $error;
        }
    }
    private function query(string $sql, mixed ...$values): mixed
    {
        $result = $this->db->query($sql, ...$values);
        if ($result === false || $this->db->is_error($result)) {
            throw new ManagementException('Storage operation failed.', 'storage');
        }
        return $result;
    }
}
