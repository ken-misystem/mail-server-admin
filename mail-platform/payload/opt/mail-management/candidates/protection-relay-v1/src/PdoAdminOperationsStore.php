<?php

declare(strict_types=1);

namespace MailServer\Management;

use PDO;

/** Controlled metadata/routing writes only. No mailbox filesystem, DNS or service operations. */
final class PdoAdminOperationsStore implements AdminOperationsStore
{
    public function __construct(private readonly PDO $db)
    { $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); $db->setAttribute(PDO::ATTR_EMULATE_PREPARES, false); }

    public function apply(AdminUser $actor, AdminMutation $mutation): void
    {
        if (!$actor->active || !$actor->systemAdmin || $this->db->inTransaction()) { throw new \DomainException('not_authorized'); }
        $committing = false;
        try {
            if (!$this->db->beginTransaction()) { throw new \DomainException('transaction_unavailable'); }
            foreach (['alias_namespace', 'admin_roles'] as $name) {
                $lock = $this->db->prepare('SELECT name FROM mail_management_locks WHERE name=? FOR UPDATE');
                $lock->execute([$name]); if ($lock->fetchColumn() !== $name) { throw new \DomainException('schema_not_ready'); }
            }
            $current = $this->row('mail_admin_users', $actor->id);
            if ((string) $current['active'] !== '1' || (string) $current['is_system_admin'] !== '1'
                || (string) $current['auth_epoch'] !== $actor->epoch || $current['email'] !== $actor->getUserIdentifier()) {
                throw new \DomainException('admin_session_changed');
            }
            $target = match ($mutation->action) {
                'domain_create', 'domain_state' => $this->domain($mutation),
                'mailbox_create', 'mailbox_state', 'mailbox_password' => $this->mailbox($mutation),
                'alias_create', 'alias_state', 'alias_destination', 'alias_remove' => $this->alias($mutation),
                'admin_create', 'admin_state', 'admin_password', 'admin_identity' => $this->administrator($mutation),
            };
            $audit = $this->db->prepare('INSERT INTO mail_admin_audit(admin_id,action,target_type,target_id) VALUES(?,?,?,?)');
            $audit->execute([$actor->id, $mutation->action,
                explode('_', $mutation->action)[0], $target]);
            $committing = true;
            if (!$this->db->commit()) { throw new \DomainException('result_unverified'); }
        } catch (\Throwable $error) {
            try { if ($this->db->inTransaction()) { $this->db->rollBack(); } }
            catch (\Throwable) { throw new \DomainException('result_unverified'); }
            if ($committing) { throw new \DomainException('result_unverified'); }
            if ($error instanceof \DomainException) { throw $error; }
            throw new \DomainException('operation_failed'); // No chained/raw PDO/credential errors.
        }
    }

    private function domain(AdminMutation $m): string
    {
        if ($m->action === 'domain_create') {
            foreach ([['virtual_domains', 'name'], ['virtual_domain_aliases', 'alias_domain']] as [$table, $column]) {
                $q = $this->db->prepare("SELECT 1 FROM mailserver.$table WHERE $column=? LIMIT 1");
                $q->execute([$m->value('name')]); if ($q->fetchColumn() !== false) { throw new \DomainException('namespace_unavailable'); }
            }
            $this->db->prepare('INSERT INTO mailserver.virtual_domains(name,active,created_at) VALUES(?,0,CURRENT_TIMESTAMP)')->execute([$m->value('name')]);
            return $this->db->lastInsertId();
        }
        $row = $this->row('mailserver.virtual_domains', $m->value('id'));
        AdminMailPolicy::confirmation($row['name'], $m->value('confirm'));
        if ((string) $row['active'] === ($m->value('enabled') ? '1' : '0')) { return (string) $row['id']; }
        $q = $this->db->prepare('SELECT id,email,auth_epoch FROM mailserver.virtual_users WHERE domain_id=? ORDER BY id FOR UPDATE');
        $q->execute([$row['id']]); $users = $q->fetchAll(PDO::FETCH_ASSOC);
        foreach ($users as $user) { AdminMailPolicy::protectMailbox($user['email']); }
        $this->db->prepare('UPDATE mailserver.virtual_domains SET active=? WHERE id=?')->execute([$m->value('enabled') ? 1 : 0, $row['id']]);
        foreach ($users as $user) { $this->advanceMailboxEpoch($user, null, null); }
        return (string) $row['id'];
    }

    private function mailbox(AdminMutation $m): string
    {
        if ($m->action === 'mailbox_create') {
            $domain = $this->row('mailserver.virtual_domains', $m->value('domain_id'));
            $email = AliasPolicy::registrationAddress($m->value('local'), $domain['name']);
            $this->available($m->value('local'), $domain);
            $q = $this->db->prepare('INSERT INTO mailserver.virtual_users(domain_id,email,password,active,quota_bytes,auth_epoch,created_at) VALUES(?,?,?,0,0,1,CURRENT_TIMESTAMP)');
            $q->execute([$domain['id'], $email, $m->value('hash')]); return $this->db->lastInsertId();
        }
        $row = $this->row('mailserver.virtual_users', $m->value('id'));
        AdminMailPolicy::confirmation($row['email'], $m->value('confirm')); AdminMailPolicy::protectMailbox($row['email']);
        if ($m->action === 'mailbox_state' && (string) $row['active'] === ($m->value('enabled') ? '1' : '0')) { return (string) $row['id']; }
        if ($m->action === 'mailbox_state' && $m->value('enabled')) {
            $domain = $this->row('mailserver.virtual_domains', (string) $row['domain_id']);
            if ((string) $domain['active'] !== '1') { throw new \DomainException('inactive_domain'); }
        }
        $this->advanceMailboxEpoch($row, $m->action === 'mailbox_state' ? $m->value('enabled') : null,
            $m->action === 'mailbox_password' ? $m->value('hash') : null);
        return (string) $row['id'];
    }

    private function advanceMailboxEpoch(array $row, ?bool $active, ?string $hash): void
    {
        if ((string) $row['auth_epoch'] === '18446744073709551615') { throw new \DomainException('epoch_exhausted'); }
        $sets = ['auth_epoch=auth_epoch+1']; $values = [];
        if ($active !== null) { $sets[] = 'active=?'; $values[] = $active ? 1 : 0; }
        if ($hash !== null) { $sets[] = 'password=?'; $values[] = $hash; }
        $values[] = (string) $row['id'];
        $this->db->prepare('UPDATE mailserver.virtual_users SET ' . implode(',', $sets) . ' WHERE id=?')->execute($values);
        $q = $this->db->prepare('SELECT auth_epoch FROM mailserver.virtual_users WHERE id=?'); $q->execute([$row['id']]);
        AdminMailPolicy::requireEpochAdvance((string) $row['auth_epoch'], (string) $q->fetchColumn());
    }

    private function alias(AdminMutation $m): string
    {
        if ($m->action === 'alias_create') {
            $domain = $this->row('mailserver.virtual_domains', $m->value('domain_id'));
            $source = AliasPolicy::registrationAddress($m->value('local'), $domain['name']);
            $target = $this->localDestination($m->value('destination_id'));
            $this->available($m->value('local'), $domain);
            $q = $this->db->prepare('INSERT INTO mailserver.virtual_aliases(domain_id,source,destination,active,created_at) VALUES(?,?,?,0,CURRENT_TIMESTAMP)');
            $q->execute([$domain['id'], $source, $target['email']]); return $this->db->lastInsertId();
        }
        $row = $this->row('mailserver.virtual_aliases', $m->value('id'));
        AdminMailPolicy::confirmation($row['source'], $m->value('confirm'));
        AdminMailPolicy::address($row['source']); // Legacy catch-all/bare-local-part routes are not rewritten here.
        $owned = $this->db->prepare('SELECT user_id FROM mail_owned_aliases WHERE virtual_alias_id=? FOR UPDATE');
        $owned->execute([$row['id']]); $owner = $owned->fetchColumn();
        if ($m->action === 'alias_destination') {
            if ($owner !== false) { throw new \DomainException('owned_alias_binding'); }
            $target = $this->localDestination($m->value('destination_id'));
            $this->db->prepare('UPDATE mailserver.virtual_aliases SET destination=? WHERE id=?')->execute([$target['email'], $row['id']]);
        } elseif ($m->action === 'alias_state') {
            if ($m->value('enabled')) {
                $domain = $this->row('mailserver.virtual_domains', (string) $row['domain_id']);
                if ((string) $domain['active'] !== '1') { throw new \DomainException('inactive_domain'); }
                $q = $this->db->prepare('SELECT id FROM mailserver.virtual_users WHERE email=?'); $q->execute([$row['destination']]);
                $id = $q->fetchColumn(); if ($id === false) { throw new \DomainException('local_destination_required'); }
                $this->localDestination((string) $id);
            }
            $this->db->prepare('UPDATE mailserver.virtual_aliases SET active=? WHERE id=?')->execute([$m->value('enabled') ? 1 : 0, $row['id']]);
        } else {
            if ($owner !== false) { $this->db->prepare('DELETE FROM mail_owned_aliases WHERE virtual_alias_id=?')->execute([$row['id']]); }
            $this->db->prepare('DELETE FROM mailserver.virtual_aliases WHERE id=?')->execute([$row['id']]);
        }
        return (string) $row['id'];
    }

    private function administrator(AdminMutation $m): string
    {
        if ($m->action === 'admin_create') {
            $q = $this->db->prepare('SELECT 1 FROM mail_admin_users WHERE email=? LIMIT 1'); $q->execute([$m->value('email')]);
            if ($q->fetchColumn() !== false) { throw new \DomainException('admin_identity_unavailable'); }
            $q = $this->db->prepare('INSERT INTO mail_admin_users(email,password_hash,user_handle,active,is_system_admin,auth_epoch) VALUES(?,?,?,0,0,1)');
            $q->execute([$m->value('email'), $m->value('hash'), random_bytes(32)]); return $this->db->lastInsertId();
        }
        $row = $this->row('mail_admin_users', $m->value('id'));
        AdminMailPolicy::confirmation($row['email'], $m->value('confirm'));
        if ((string) $row['auth_epoch'] === '18446744073709551615') { throw new \DomainException('epoch_exhausted'); }
        if ($m->action === 'admin_state') {
            $was = (string) $row['active'] === '1' && (string) $row['is_system_admin'] === '1';
            $will = $m->value('enabled') && $m->value('system_admin');
            $count = (int) $this->db->query('SELECT COUNT(*) FROM mail_admin_users WHERE active=1 AND is_system_admin=1')->fetchColumn();
            AdminPolicy::requireRoleChange(true, $was, $will, $count);
            if ($was && !$will) {
                $q = $this->db->prepare('SELECT 1 FROM mail_admin_credentials WHERE admin_id=? AND enabled=1 LIMIT 1'); $q->execute([$row['id']]);
                if ($q->fetchColumn() !== false && (int) $this->db->query('SELECT COUNT(*) FROM mail_admin_users a WHERE a.active=1 AND a.is_system_admin=1 AND EXISTS(SELECT 1 FROM mail_admin_credentials c WHERE c.admin_id=a.id AND c.enabled=1)')->fetchColumn() <= 1) {
                    throw new \DomainException('last_usable_administrator');
                }
            }
            $this->db->prepare('UPDATE mail_admin_users SET active=?,is_system_admin=?,auth_epoch=auth_epoch+1 WHERE id=?')
                ->execute([$m->value('enabled') ? 1 : 0, $m->value('system_admin') ? 1 : 0, $row['id']]);
        } elseif ($m->action === 'admin_identity') {
            $q = $this->db->prepare('SELECT 1 FROM mail_admin_users WHERE email=? AND id<>? LIMIT 1');
            $q->execute([$m->value('email'), $row['id']]); if ($q->fetchColumn() !== false) { throw new \DomainException('admin_identity_unavailable'); }
            $this->db->prepare('UPDATE mail_admin_users SET email=?,auth_epoch=auth_epoch+1 WHERE id=?')->execute([$m->value('email'), $row['id']]);
        } else {
            $this->db->prepare('UPDATE mail_admin_users SET password_hash=?,auth_epoch=auth_epoch+1 WHERE id=?')->execute([$m->value('hash'), $row['id']]);
        }
        return (string) $row['id'];
    }

    private function row(string $table, string $id): array
    {
        // Projection/table literals only; never load old password hashes or recovery data.
        $columns = match ($table) {
            'mail_admin_users' => 'id,email,active,is_system_admin,auth_epoch',
            'mailserver.virtual_domains' => 'id,name,active',
            'mailserver.virtual_users' => 'id,domain_id,email,active,auth_epoch',
            'mailserver.virtual_aliases' => 'id,domain_id,source,destination,active',
        };
        $q = $this->db->prepare("SELECT $columns FROM $table WHERE id=? FOR UPDATE"); $q->execute([$id]);
        $row = $q->fetch(PDO::FETCH_ASSOC); if (!$row) { throw new \DomainException('unknown_target'); }
        return $row;
    }

    private function localDestination(string $id): array
    {
        $user = $this->row('mailserver.virtual_users', $id);
        $domain = $this->row('mailserver.virtual_domains', (string) $user['domain_id']);
        if ((string) $user['active'] !== '1' || (string) $domain['active'] !== '1') { throw new \DomainException('inactive_destination'); }
        if (strcasecmp(explode('@', $user['email'], 2)[1] ?? '', $domain['name']) !== 0) { throw new \DomainException('invalid_binding'); }
        return $user;
    }

    private function available(string $local, array $domain): void
    {
        $q = $this->db->prepare('SELECT alias_domain FROM mailserver.virtual_domain_aliases WHERE target_domain_id=?'); $q->execute([$domain['id']]);
        $names = array_unique([$domain['name'], ...$q->fetchAll(PDO::FETCH_COLUMN)]);
        $addresses = []; $sources = [$local];
        foreach ($names as $name) { $addresses[] = $local . '@' . $name; $sources[] = $local . '@' . $name; $sources[] = '@' . $name; }
        foreach ([['mailserver.virtual_users', 'email', $addresses], ['mailserver.virtual_aliases', 'source', $sources],
            ['mail_owned_aliases', 'source', $addresses]] as [$table, $column, $values]) {
            $key = AliasPolicy::namespaceSql($column);
            $q = $this->db->prepare("SELECT 1 FROM $table WHERE ($key) IN (" . implode(',', array_fill(0, count($values), '?')) . ') LIMIT 1');
            $q->execute($values); if ($q->fetchColumn() !== false) { throw new \DomainException('namespace_unavailable'); }
        }
    }
}
