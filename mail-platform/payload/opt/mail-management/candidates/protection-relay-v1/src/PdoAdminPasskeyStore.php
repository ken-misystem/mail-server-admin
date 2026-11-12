<?php

declare(strict_types=1);

namespace MailServer\Management;

use PDO;
use Webauthn\CredentialRecord;

final class PdoAdminPasskeyStore implements AdminPasskeyStore
{
    public function __construct(private readonly PDO $db, private readonly AdminWebauthn $validator)
    {
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $db->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
    }

    public function snapshot(AdminUser $user): array
    {
        try {
            $admin = $this->admin($user, false);
            $query = $this->db->prepare('SELECT credential_id,credential_json,enabled FROM mail_admin_credentials WHERE admin_id=? ORDER BY id');
            $query->execute([$user->id]);
            $rows = $query->fetchAll(PDO::FETCH_ASSOC);
            $records = [];
            foreach ($rows as $row) {
                if ((string) $row['enabled'] !== '1') { continue; }
                $record = $this->validator->decode($row['credential_json']);
                if (!hash_equals($admin['user_handle'], $record->userHandle)
                    || !hash_equals($row['credential_id'], $record->publicKeyCredentialId)) { throw new \DomainException('invalid_credential_record'); }
                $records[] = $record;
            }
            return ['handle' => $admin['user_handle'], 'records' => $records, 'has_any' => count($rows) > 0];
        } catch (\DomainException $e) { throw $e; }
        catch (\Throwable) { throw new \DomainException('passkey_storage_unavailable'); }
    }

    public function register(AdminUser $user, CredentialRecord $record, string $label, bool $first): void
    {
        $this->transaction(function () use ($user, $record, $label, $first): void {
            $admin = $this->admin($user, true);
            $count = $this->db->prepare('SELECT COUNT(*) FROM mail_admin_credentials WHERE admin_id=?');
            $count->execute([$user->id]);
            $existing = (int) $count->fetchColumn();
            if (($first && $existing !== 0) || $existing >= 20) { throw new \DomainException('registration_not_allowed'); }
            if (!hash_equals($admin['user_handle'], $record->userHandle)
                || strlen($record->publicKeyCredentialId) < 1 || strlen($record->publicKeyCredentialId) > 1024) {
                throw new \DomainException('invalid_credential_record');
            }
            AdminPasskeyCeremony::label($label);
            $duplicate = $this->db->prepare('SELECT id FROM mail_admin_credentials WHERE credential_id=?');
            $duplicate->execute([$record->publicKeyCredentialId]);
            if ($duplicate->fetchColumn() !== false) { throw new \DomainException('duplicate_credential'); }
            $query = $this->db->prepare('INSERT INTO mail_admin_credentials(admin_id,credential_id,credential_json,label,enabled) VALUES(?,?,?,?,1)');
            $query->execute([$user->id, $record->publicKeyCredentialId, $this->validator->encode($record), $label]);
            $this->audit($user, 'passkey_registered', (string) $this->db->lastInsertId());
        });
    }

    public function authenticate(AdminUser $user, string $response, string $options, AdminWebauthn $validator): void
    {
        $id = $validator->credentialId($response);
        $this->transaction(function () use ($user, $response, $options, $validator, $id): void {
            $admin = $this->admin($user, true);
            $query = $this->db->prepare('SELECT id,credential_json FROM mail_admin_credentials WHERE admin_id=? AND credential_id=? AND enabled=1 FOR UPDATE');
            $query->execute([$user->id, $id]);
            $row = $query->fetch(PDO::FETCH_ASSOC);
            if (!$row) { throw new \DomainException('passkey_validation_failed'); }
            // Sign-counter validation and update are serialized against this newest row.
            $record = $validator->assertion($response, $options, $row['credential_json'], $admin['user_handle']);
            $update = $this->db->prepare('UPDATE mail_admin_credentials SET credential_json=?,last_used_at=CURRENT_TIMESTAMP WHERE id=? AND admin_id=? AND enabled=1');
            $update->execute([$validator->encode($record), $row['id'], $user->id]);
        });
    }

    private function admin(AdminUser $user, bool $locked): array
    {
        $query = $this->db->prepare('SELECT email,active,is_system_admin,auth_epoch,user_handle FROM mail_admin_users WHERE id=?'
            . ($locked ? ' FOR UPDATE' : ''));
        $query->execute([$user->id]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!$row || !$user->active || (string) $row['active'] !== '1'
            || (string) $row['auth_epoch'] !== $user->epoch || $row['email'] !== $user->getUserIdentifier()
            || ((string) $row['is_system_admin'] === '1') !== $user->systemAdmin) {
            throw new \DomainException('admin_session_changed');
        }
        return $row;
    }

    private function audit(AdminUser $user, string $action, string $target): void
    {
        $query = $this->db->prepare('INSERT INTO mail_admin_audit(admin_id,action,target_type,target_id) VALUES(?,?,?,?)');
        $query->execute([$user->id, $action, 'admin_passkey', $target]);
    }

    private function transaction(callable $operation): void
    {
        if ($this->db->inTransaction()) { throw new \DomainException('nested_transaction'); }
        $commitAttempted = false;
        try {
            if (!$this->db->beginTransaction()) { throw new \DomainException('transaction_unavailable'); }
            $operation();
            $commitAttempted = true;
            if (!$this->db->commit()) { throw new \DomainException('result_unverified'); }
        } catch (\Throwable $error) {
            try { if ($this->db->inTransaction()) { $this->db->rollBack(); } }
            catch (\Throwable) { throw new \DomainException('result_unverified'); }
            if ($commitAttempted) { throw new \DomainException('result_unverified'); }
            if ($error instanceof \DomainException) { throw $error; }
            if ($error instanceof \PDOException && $error->getCode() === '23000') { throw new \DomainException('duplicate_or_invalid_credential'); }
            throw new \DomainException('passkey_storage_unavailable');
        }
    }
}
