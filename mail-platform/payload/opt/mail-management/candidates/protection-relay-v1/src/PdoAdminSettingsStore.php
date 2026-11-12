<?php

declare(strict_types=1);

namespace MailServer\Management;

use PDO;

final class PdoAdminSettingsStore implements AdminSettingsStore, AdminInventoryStore
{
    public function __construct(private readonly PDO $db)
    {
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $db->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
    }

    public function overview(AdminUser $actor): array
    {
        if ($this->db->inTransaction()) { throw new \DomainException('nested_transaction'); }
        try {
            $this->db->exec('START TRANSACTION READ ONLY');
            $this->actor($actor, false);
            // No password hashes, user handles, credentials, POP usernames, secrets or recovery data.
            $queries = [
                'domains' => 'SELECT id,name,active FROM mailserver.virtual_domains ORDER BY name LIMIT 201',
                'users' => 'SELECT u.id,u.email,u.active,d.name AS domain_name,d.active AS domain_active,'
                    . 'COALESCE(s.alias_limit,1) AS alias_limit,COALESCE(s.pop_account_limit,0) AS pop_account_limit,'
                    . 'COALESCE(s.pop_poll_seconds,300) AS pop_poll_seconds,'
                    . '(SELECT COUNT(*) FROM mail_owned_aliases m WHERE m.user_id=u.id) AS owned_alias_count '
                    . 'FROM mailserver.virtual_users u JOIN mailserver.virtual_domains d ON d.id=u.domain_id '
                    . 'LEFT JOIN mail_user_settings s ON s.user_id=u.id ORDER BY u.email LIMIT 201',
                'aliases' => 'SELECT id,source,destination,active FROM mailserver.virtual_aliases ORDER BY source,id LIMIT 201',
                'admins' => 'SELECT id,email,active,is_system_admin FROM mail_admin_users ORDER BY email LIMIT 201',
            ];
            $result = [];
            foreach ($queries as $name => $sql) {
                $rows = $this->db->query($sql)->fetchAll(PDO::FETCH_ASSOC);
                foreach ($rows as &$row) { $row['id'] = (string) $row['id']; }
                unset($row);
                $result[$name] = ['rows' => array_slice($rows, 0, 200), 'truncated' => count($rows) > 200];
            }
            $this->db->rollBack();
            return $result;
        } catch (\Throwable $error) {
            try { if ($this->db->inTransaction()) { $this->db->rollBack(); } }
            catch (\Throwable) { throw new \DomainException('settings_storage_unavailable'); }
            if ($error instanceof \DomainException) { throw $error; }
            throw new \DomainException('settings_storage_unavailable');
        }
    }

    public function browse(AdminUser $actor, AdminInventoryFilter $filter): array
    {
        if ($this->db->inTransaction()) { throw new \DomainException('nested_transaction'); }
        try {
            $this->db->exec('START TRANSACTION READ ONLY');
            $this->actor($actor, false);
            $result = AdminInventoryQuery::read($this->db, $filter);
            $this->db->rollBack();
            return $result;
        } catch (\Throwable $error) {
            try { if ($this->db->inTransaction()) { $this->db->rollBack(); } }
            catch (\Throwable) { throw new \DomainException('settings_storage_unavailable'); }
            throw new \DomainException('settings_storage_unavailable');
        }
    }

    public function setUserPolicy(AdminUser $actor, string $userId, UserPolicyLimits $limits): void
    {
        UserPolicyLimits::userId($userId);
        if ($this->db->inTransaction()) { throw new \DomainException('nested_transaction'); }
        $committing = false;
        try {
            if (!$this->db->beginTransaction()) { throw new \DomainException('transaction_unavailable'); }
            // Same order as self-service alias mutations: namespace -> actor/target -> policy.
            $lock = $this->db->query("SELECT name FROM mail_management_locks WHERE name='alias_namespace' FOR UPDATE");
            if ($lock->fetchColumn() !== 'alias_namespace') { throw new \DomainException('schema_not_ready'); }
            $this->actor($actor, true);
            $target = $this->db->prepare('SELECT id FROM mailserver.virtual_users WHERE id=? FOR UPDATE');
            $target->execute([$userId]);
            if ((string) $target->fetchColumn() !== $userId) { throw new \DomainException('unknown_user'); }
            $policy = $this->db->prepare('SELECT user_id FROM mail_user_settings WHERE user_id=? FOR UPDATE');
            $policy->execute([$userId]);
            $exists = $policy->fetchColumn() !== false;
            $sql = $exists
                ? 'UPDATE mail_user_settings SET alias_limit=?,pop_account_limit=? WHERE user_id=?'
                : 'INSERT INTO mail_user_settings(alias_limit,pop_account_limit,user_id) VALUES(?,?,?)';
            $this->db->prepare($sql)->execute([$limits->aliasLimit, $limits->popLimit, $userId]);
            // Existing polling interval is preserved; new rows retain the schema's 300-second default.
            // Lower limits never delete existing aliases/POP accounts or enable a retrieval process.
            $audit = $this->db->prepare('INSERT INTO mail_admin_audit(admin_id,action,target_type,target_id) VALUES(?,?,?,?)');
            $audit->execute([$actor->id, 'user_policy_updated', 'mail_user', $userId]);
            $committing = true;
            if (!$this->db->commit()) { throw new \DomainException('result_unverified'); }
        } catch (\Throwable $error) {
            try { if ($this->db->inTransaction()) { $this->db->rollBack(); } }
            catch (\Throwable) { throw new \DomainException('result_unverified'); }
            if ($committing) { throw new \DomainException('result_unverified'); }
            if ($error instanceof \DomainException) { throw $error; }
            throw new \DomainException('settings_write_failed');
        }
    }

    private function actor(AdminUser $actor, bool $locked): void
    {
        if (!$actor->active || !$actor->systemAdmin) { throw new \DomainException('not_authorized'); }
        $query = $this->db->prepare('SELECT email,active,is_system_admin,auth_epoch FROM mail_admin_users WHERE id=?'
            . ($locked ? ' FOR UPDATE' : ''));
        $query->execute([$actor->id]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!$row || (string) $row['active'] !== '1' || (string) $row['is_system_admin'] !== '1'
            || (string) $row['auth_epoch'] !== $actor->epoch || $row['email'] !== $actor->getUserIdentifier()) {
            throw new \DomainException('admin_session_changed');
        }
    }
}
