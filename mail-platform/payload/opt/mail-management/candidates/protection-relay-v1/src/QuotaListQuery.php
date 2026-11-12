<?php
declare(strict_types=1);
namespace MailServer\Management;

use PDO;

/** Three bounded SELECTs inside the caller's existing read-only transaction. */
final class QuotaListQuery
{
    public static function read(PDO $db, QuotaListFilter $filter): array
    {
        $run = static function (string $sql, array $args = []) use ($db): \PDOStatement {
            // MariaDB native timeout, identical to the active quota repository.
            $q = $db->prepare('SET STATEMENT max_statement_time=2 FOR '.$sql);
            $q->execute($args); return $q;
        };
        [$where, $args] = $filter->predicates();
        $from = ' FROM mailserver.virtual_users u JOIN mailserver.virtual_domains d ON d.id=u.domain_id';
        $total = PdoCutoverStore::bytes($run('SELECT COUNT(*)'.$from.$where, $args)->fetchColumn());
        $p = $filter->window($total);
        // Only validated integer calculations enter LIMIT/OFFSET; all search values are bound parameters.
        $rows = $run('SELECT u.id,u.email,u.quota_bytes,u.active,d.active AS domain_active'.$from.$where
            .' ORDER BY u.id LIMIT '.$p['per_page'].' OFFSET '.$p['offset'], $args)->fetchAll(PDO::FETCH_ASSOC);
        if (count($rows) > $p['per_page']) { throw new \DomainException('row_bound'); }
        $domains = $run('SELECT name FROM mailserver.virtual_domains ORDER BY name LIMIT 201')->fetchAll(PDO::FETCH_ASSOC);
        $truncated = count($domains) === 201;
        if ($truncated) { array_pop($domains); }
        return ['rows'=>$rows,'pagination'=>$p,'domains'=>$domains,'domains_truncated'=>$truncated,'next_after'=>null];
    }
}
