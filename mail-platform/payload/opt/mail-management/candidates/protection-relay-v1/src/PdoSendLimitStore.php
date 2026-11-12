<?php
declare(strict_types=1);
namespace MailServer\Management;

use PDO;

final class PdoSendLimitStore implements SendLimitStore
{
    private const COLUMNS = 'profile,minute_messages,minute_recipients,hour_messages,hour_recipients,revision,updated_at';

    public function __construct(private readonly PDO $db)
    {
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $db->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
    }

    private function actor(AdminUser $actor, bool $lock): void
    {
        if (!$actor->active || !$actor->systemAdmin) { throw new \DomainException('not_authorized'); }
        $query = $this->db->prepare('SELECT email,active,is_system_admin,auth_epoch FROM mail_admin_users WHERE id=?'
            . ($lock ? ' FOR UPDATE' : ''));
        $query->execute([$actor->id]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!$row || (string)$row['active'] !== '1' || (string)$row['is_system_admin'] !== '1'
            || (string)$row['auth_epoch'] !== $actor->epoch || $row['email'] !== $actor->getUserIdentifier()) {
            throw new \DomainException('admin_session_changed');
        }
    }

    public function overview(AdminUser $actor): array
    {
        if ($this->db->inTransaction()) { throw new \DomainException('nested_transaction'); }
        $stage = 'read_begin';
        try {
            $this->db->exec('START TRANSACTION READ ONLY');
            $stage = 'read_actor';
            $this->actor($actor, false);
            $stage = 'read_profiles';
            $rows = $this->db->query('SET STATEMENT max_statement_time=2 FOR SELECT ' . self::COLUMNS
                . ' FROM mail_send_limit_profiles ORDER BY profile LIMIT 3')->fetchAll(PDO::FETCH_ASSOC);
            if (array_column($rows, 'profile') !== ['legacy','mailbox']) { throw new \DomainException('profile_inventory'); }
            foreach ($rows as $row) { SendLimitChange::limits($row); SendLimitChange::revision($row['revision']); }
            $stage = 'read_history';
            $history = $this->db->query('SET STATEMENT max_statement_time=2 FOR SELECT id,admin_id,profile,revision,'
                . 'before_json,after_json,reason,created_at FROM mail_send_limit_history ORDER BY id DESC LIMIT 50')->fetchAll(PDO::FETCH_ASSOC);
            $stage = 'read_close';
            if (!$this->db->rollBack()) { throw new \RuntimeException('read_close_failed'); }
            return ['profiles'=>$rows, 'history'=>$history];
        } catch (\Throwable $error) { $this->failed($error, $stage, false); }
    }

    public function save(AdminUser $actor, SendLimitChange $change): void
    {
        if ($this->db->inTransaction()) { throw new \DomainException('nested_transaction'); }
        $stage = 'begin';
        $committing = false;
        try {
            if (!$this->db->beginTransaction()) { throw new \RuntimeException('transaction_unavailable'); }
            $stage = 'actor_lock';
            $this->actor($actor, true);
            $stage = 'profile_lock';
            $query = $this->db->prepare('SELECT ' . self::COLUMNS . ' FROM mail_send_limit_profiles WHERE profile=? FOR UPDATE');
            $query->execute([$change->profile]);
            $before = $query->fetch(PDO::FETCH_ASSOC);
            if (!$before || SendLimitChange::revision($before['revision']) !== $change->revision
                || $change->revision >= 999999999999999) { throw new \DomainException('revision_changed'); }
            $oldLimits = SendLimitChange::limits($before);
            $stage = 'update';
            $query = $this->db->prepare('UPDATE mail_send_limit_profiles SET minute_messages=?,minute_recipients=?,'
                . 'hour_messages=?,hour_recipients=?,revision=revision+1 WHERE profile=? AND revision=?');
            $query->execute([...array_values($change->limits), $change->profile, $change->revision]);
            if ($query->rowCount() !== 1) { throw new \DomainException('revision_changed'); }
            $stage = 'history';
            $query = $this->db->prepare('INSERT INTO mail_send_limit_history(admin_id,profile,revision,before_json,after_json,reason) VALUES(?,?,?,?,?,?)');
            $query->execute([$actor->id, $change->profile, $change->revision+1,
                json_encode($oldLimits, JSON_THROW_ON_ERROR), json_encode($change->limits, JSON_THROW_ON_ERROR), $change->reason]);
            if ($query->rowCount() !== 1) { throw new \RuntimeException('history_row_count'); }
            $stage = 'audit';
            $query = $this->db->prepare('INSERT INTO mail_admin_audit(admin_id,action,target_type,target_id) VALUES(?,?,?,?)');
            $query->execute([$actor->id, 'send_limit_profile_updated', 'send_limit_profile', $change->profile]);
            if ($query->rowCount() !== 1) { throw new \RuntimeException('audit_row_count'); }
            $stage = 'commit';
            $committing = true;
            if (!$this->db->commit()) { throw new \RuntimeException('commit_unverified'); }
        } catch (\Throwable $error) { $this->failed($error, $stage, $committing); }
    }

    private function failed(\Throwable $error, string $stage, bool $committing): never
    {
        $cleanup = null;
        try {
            if ($this->db->inTransaction() && !$this->db->rollBack()) { throw new \RuntimeException('rollback_failed'); }
        } catch (\Throwable $failure) { $cleanup = $failure; }
        if (!$committing && !$cleanup && $error instanceof \DomainException
            && in_array($error->getMessage(), ['not_authorized','admin_session_changed','revision_changed'], true)) {
            throw $error;
        }
        throw new SendLimitFailure($stage, $error, $cleanup, $committing);
    }
}
