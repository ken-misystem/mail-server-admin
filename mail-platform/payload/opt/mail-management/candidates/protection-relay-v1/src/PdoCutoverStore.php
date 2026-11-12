<?php
declare(strict_types=1);
namespace MailServer\Management;

use PDO;
use MailServer\Management\Preparation\{DomainAliasChange, MailboxQuotaChange};

// Production's flat class loader does not load sub-namespaces. Bind these two
// unchanged reviewed policies explicitly; no public application entry is executed.
require_once __DIR__.'/DomainAliasChange.php';
require_once __DIR__.'/MailboxQuotaChange.php';

/** Candidate. All mutations and audit are one transaction. No mail, DNS, native process or service operations. */
final class PdoCutoverStore implements CutoverStore
{
    public function __construct(private readonly PDO $db, private readonly QuotaUsageProvider $usage)
    { $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); $db->setAttribute(PDO::ATTR_EMULATE_PREPARES, false); }

    public static function bytes(mixed $v): int
    {
        if (is_int($v) && $v >= 0) { return $v; }
        if (!is_string($v) || !preg_match('/^(?:0|[1-9][0-9]*)$/D', $v)
            || strlen($v) > strlen((string)PHP_INT_MAX)
            || (strlen($v) === strlen((string)PHP_INT_MAX) && strcmp($v, (string)PHP_INT_MAX) > 0)) {
            throw new \DomainException('quota_integer_range');
        }
        return (int)$v;
    }

    private function query(string $sql, array $args = []): \PDOStatement
    { $q = $this->db->prepare($sql); $q->execute($args); return $q; }

    private function actor(AdminUser $actor, bool $lock): void
    {
        if (!$actor->active || !$actor->systemAdmin) { throw new \DomainException('not_authorized'); }
        $r = $this->query('SELECT email,active,is_system_admin,auth_epoch FROM mail_admin_users WHERE id=?'
            .($lock ? ' FOR UPDATE' : ''), [$actor->id])->fetch(PDO::FETCH_ASSOC);
        if (!$r || $r['email'] !== $actor->getUserIdentifier() || (string)$r['active'] !== '1'
            || (string)$r['is_system_admin'] !== '1' || (string)$r['auth_epoch'] !== $actor->epoch) {
            throw new \DomainException('admin_session_changed');
        }
    }

    public function overview(AdminUser $actor, string $section, string $after = '0', array $filters = []): array
    {
        if (!in_array($section, ['domain-aliases', 'mailbox-quota'], true)) { throw new \DomainException('invalid_section'); }
        if ($after !== '0') { UserPolicyLimits::userId($after); }
        if ($this->db->inTransaction()) { throw new \DomainException('nested_transaction'); }
        $phase = 'overview_begin';
        try {
            $this->db->exec('START TRANSACTION READ ONLY'); $this->actor($actor, false);
            $phase = 'overview_rows';
            if ($section === 'mailbox-quota') {
                $data = QuotaListQuery::read($this->db, QuotaListFilter::fromArray($filters));
                foreach ($data['rows'] as &$row) {
                    UserPolicyLimits::userId((string)$row['id']);
                    $row['usage'] = null; $row['usage_reason'] = 'quota_backend_unverified';
                    try {
                        $row['usage'] = $this->usage->lookup((string)$row['id'], $row['email'], self::bytes($row['quota_bytes']), time());
                        $row['usage_reason'] = null;
                    } catch (\DomainException $e) { $row['usage_reason'] = self::usageReason($e); }
                }
                unset($row);
                if (!$this->db->rollBack()) { throw new \RuntimeException('read_close'); }
                return $data;
            }
            $sql = $section === 'domain-aliases'
                ? 'SELECT a.id,a.alias_domain,a.target_domain_id,a.active,d.name AS target_name,d.active AS target_active '
                  .'FROM mailserver.virtual_domain_aliases a JOIN mailserver.virtual_domains d ON d.id=a.target_domain_id '
                  .'WHERE a.id>CAST(? AS UNSIGNED) ORDER BY a.id LIMIT 51'
                : 'SELECT u.id,u.email,u.quota_bytes,u.active,d.active AS domain_active FROM mailserver.virtual_users u '
                  .'JOIN mailserver.virtual_domains d ON d.id=u.domain_id WHERE u.id>CAST(? AS UNSIGNED) ORDER BY u.id LIMIT 51';
            $rows = $this->query('SET STATEMENT max_statement_time=2 FOR '.$sql, [$after])->fetchAll(PDO::FETCH_ASSOC);
            if (count($rows) > 51) { throw new \DomainException('row_bound'); }
            $more = count($rows) === 51; if ($more) { array_pop($rows); }
            foreach ($rows as &$row) {
                UserPolicyLimits::userId((string)$row['id']);
                if ($section === 'mailbox-quota') {
                    $row['usage'] = null; $row['usage_reason'] = 'quota_backend_unverified';
                    try {
                        $row['usage'] = $this->usage->lookup((string)$row['id'], $row['email'], self::bytes($row['quota_bytes']), time());
                        $row['usage_reason'] = null;
                    } catch (\DomainException $e) { $row['usage_reason'] = self::usageReason($e); }
                }
            }
            unset($row);
            $phase = 'overview_close';
            if (!$this->db->rollBack()) { throw new \RuntimeException('read_close'); }
            return ['rows'=>$rows, 'next_after'=>$more ? (string)$rows[count($rows)-1]['id'] : null];
        } catch (\Throwable $e) { $this->fail($e, $phase, false); }
    }

    public static function usageReason(\DomainException $e): string
    {
        return in_array($e->getMessage(), ['quota_usage_stale','quota_binding_changed','quota_snapshot_invalid',
            'quota_backend_unverified','quota_integer_range'], true) ? $e->getMessage() : 'quota_backend_unverified';
    }

    public function save(AdminUser $actor, string $section, array $input): void
    {
        if (!in_array($section, ['domain-aliases', 'mailbox-quota'], true)) { throw new \DomainException('invalid_section'); }
        if ($this->db->inTransaction()) { throw new \DomainException('nested_transaction'); }
        $phase = 'begin'; $committing = false;
        try {
            if (!$this->db->beginTransaction()) { throw new \RuntimeException('transaction_unavailable'); }
            $phase = 'locks';
            foreach (['alias_namespace','admin_roles'] as $name) {
                if ($this->query('SELECT name FROM mail_management_locks WHERE name=? FOR UPDATE', [$name])->fetchColumn() !== $name) {
                    throw new \DomainException('schema_not_ready');
                }
            }
            $phase = 'actor'; $this->actor($actor, true);
            $phase = $section === 'domain-aliases' ? 'alias_snapshot_and_write' : 'quota_observation_and_write';
            [$target, $action, $type] = $section === 'domain-aliases' ? $this->alias($input) : $this->quota($input);
            if ($action === null) { if (!$this->db->rollBack()) { throw new \RuntimeException('noop_close'); } return; }
            $phase = 'audit';
            $q = $this->query('INSERT INTO mail_admin_audit(admin_id,action,target_type,target_id) VALUES(?,?,?,?)',
                [$actor->id, $action, $type, $target]);
            if ($q->rowCount() !== 1) { throw new \DomainException('audit_row_count'); }
            $phase = 'commit'; $committing = true;
            if (!$this->db->commit()) { throw new \RuntimeException('commit_unverified'); }
        } catch (\Throwable $e) { $this->fail($e, $phase, $committing); }
    }

    private function alias(array $input): array
    {
        // Complete namespace only, capped with explicit failure. Never feed the paginated display to the policy.
        $domains = $this->query('SET STATEMENT max_statement_time=2 FOR SELECT id,name,active FROM mailserver.virtual_domains ORDER BY id LIMIT 10001 FOR UPDATE')->fetchAll(PDO::FETCH_ASSOC);
        $aliases = $this->query('SET STATEMENT max_statement_time=2 FOR SELECT id,alias_domain,target_domain_id,active FROM mailserver.virtual_domain_aliases ORDER BY id LIMIT 10001 FOR UPDATE')->fetchAll(PDO::FETCH_ASSOC);
        if (count($domains) > 10000 || count($aliases) > 10000) { throw new \DomainException('snapshot_incomplete'); }
        // Native PDO returns integer columns as integers; the reused policy explicitly consumes strings.
        foreach ($domains as &$r) { foreach (['id','active'] as $k) { $r[$k] = (string)$r[$k]; } } unset($r);
        foreach ($aliases as &$r) { foreach (['id','target_domain_id','active'] as $k) { $r[$k] = (string)$r[$k]; } } unset($r);
        if (!is_string($input['target_name'] ?? null)) { throw new \DomainException('primary_domain_required'); }
        $name = AdminMailPolicy::domain($input['target_name']); $input['target_domain_id'] = null;
        foreach ($domains as $d) { if ($d['name'] === $name) { $input['target_domain_id'] = $d['id']; } }
        if ($input['target_domain_id'] === null) { throw new \DomainException('primary_domain_required'); }
        $plan = DomainAliasChange::plan($input, ['complete'=>true, 'domains'=>$domains, 'aliases'=>$aliases]);
        $id = null; $current = null;
        foreach ($aliases as $a) { if ($a['alias_domain'] === $plan['alias_domain']) { $id = $a['id']; $current = $a; } }
        if ($plan['operation'] === 'create') {
            $q = $this->query('INSERT INTO mailserver.virtual_domain_aliases(alias_domain,target_domain_id,active) VALUES(?,?,0)',
                [$plan['alias_domain'], $plan['target_domain_id']]);
            $id = UserPolicyLimits::userId($this->db->lastInsertId());
        } else {
            if (!is_string($input['id'] ?? null) || $id !== $input['id']) { throw new \DomainException('stale_form'); }
            if ($current['target_domain_id'] === $plan['target_domain_id'] && $current['active'] === ($plan['active'] ? '1' : '0')) {
                return [$id, null, 'domain_alias'];
            }
            $q = $this->query('UPDATE mailserver.virtual_domain_aliases SET target_domain_id=?,active=? WHERE id=? AND target_domain_id=? AND active=?',
                [$plan['target_domain_id'], $plan['active'] ? 1 : 0, $id, $input['expected_target_domain_id'], $input['expected_enabled']]);
        }
        if ($q->rowCount() !== 1) { throw new \DomainException('write_row_count'); }
        return [$id, 'domain_alias_'.$plan['operation'], 'domain_alias'];
    }

    private function quota(array $input): array
    {
        if (!is_string($input['id'] ?? null)) { throw new \DomainException('invalid_input'); }
        $id = UserPolicyLimits::userId($input['id']);
        $r = $this->query('SELECT u.email,u.quota_bytes,u.active,d.active AS domain_active FROM mailserver.virtual_users u '
            .'JOIN mailserver.virtual_domains d ON d.id=u.domain_id WHERE u.id=? FOR UPDATE', [$id])->fetch(PDO::FETCH_ASSOC);
        if (!$r || (string)$r['active'] !== '1' || (string)$r['domain_active'] !== '1') { throw new \DomainException('inactive_mailbox'); }
        AdminMailPolicy::confirmation($r['email'], is_string($input['confirm'] ?? null) ? $input['confirm'] : '');
        $current = self::bytes($r['quota_bytes']);
        $usage = $this->usage->lookup($id, $r['email'], $current, time());
        // No caller-supplied used_bytes/enforcement booleans. Provider validates trusted current observation.
        if (!is_int($usage['used_bytes_upper_bound'] ?? null) || $usage['used_bytes_upper_bound'] < 0
            || ($usage['enforcement_verified'] ?? null) !== true) { throw new \DomainException('quota_backend_unverified'); }
        $value = MailboxQuotaChange::plan($input, $current, $usage['used_bytes_upper_bound'], true);
        if ($value === $current) { return [$id, null, 'mailbox']; }
        $q = $this->query('UPDATE mailserver.virtual_users SET quota_bytes=? WHERE id=? AND quota_bytes=?', [$value,$id,$current]);
        if ($q->rowCount() !== 1) { throw new \DomainException('write_row_count'); }
        return [$id, $value === 0 ? 'mailbox_quota_unlimited' : 'mailbox_quota_limited', 'mailbox'];
    }

    private function fail(\Throwable $e, string $phase, bool $uncertain): never
    {
        try { if ($this->db->inTransaction() && !$this->db->rollBack()) { throw new \RuntimeException('rollback_unverified'); } }
        catch (\Throwable $rollback) { throw new CutoverFailure($phase, $e, true, $rollback); }
        if (!$uncertain && $e instanceof \DomainException) { throw $e; }
        throw new CutoverFailure($phase, $e, $uncertain);
    }
}
