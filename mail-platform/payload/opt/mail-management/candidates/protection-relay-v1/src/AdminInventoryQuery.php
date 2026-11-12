<?php
declare(strict_types=1);
namespace MailServer\Management;

use PDO;

/** Run only inside the authenticated caller's existing read-only transaction. */
final class AdminInventoryQuery
{
    public static function read(PDO $db, AdminInventoryFilter $filter): array
    {
        $run = static function (string $sql, array $args = []) use ($db): \PDOStatement {
            $query = $db->prepare('SET STATEMENT max_statement_time=2 FOR ' . $sql);
            $query->execute($args);
            return $query;
        };
        [$from, $columns] = match ($filter->section) {
            'users' => ['mailserver.virtual_users u JOIN mailserver.virtual_domains d ON d.id=u.domain_id '
                . 'LEFT JOIN mail_user_settings s ON s.user_id=u.id',
                'u.id,u.email,u.active,d.name AS domain_name,d.active AS domain_active,'
                . 'COALESCE(s.alias_limit,1) AS alias_limit,COALESCE(s.pop_account_limit,0) AS pop_account_limit,'
                . 'COALESCE(s.pop_poll_seconds,300) AS pop_poll_seconds,'
                . '(SELECT COUNT(*) FROM mail_owned_aliases m WHERE m.user_id=u.id) AS owned_alias_count'],
            'domains' => ['mailserver.virtual_domains u', 'u.id,u.name,u.active'],
            'aliases' => ['mailserver.virtual_aliases u LEFT JOIN mailserver.virtual_domains d ON d.id=u.domain_id',
                'u.id,u.source,u.destination,u.active'],
            'admins' => ['mail_admin_users u', 'u.id,u.email,u.active,u.is_system_admin'],
        };
        [$where, $args] = $filter->predicates();
        $total = PdoCutoverStore::bytes($run('SELECT COUNT(*) FROM ' . $from . $where, $args)->fetchColumn());
        $window = $filter->search->window($total);
        $rows = $run('SELECT ' . $columns . ' FROM ' . $from . $where
            . ' ORDER BY u.id LIMIT ' . $window['per_page'] . ' OFFSET ' . $window['offset'], $args)->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as &$row) { $row['id'] = (string)$row['id']; }
        unset($row);
        // Exact selectors keep every domain and destination reachable with bounded output.
        $domains = $run('SELECT id,name,active FROM mailserver.virtual_domains'
            . ($filter->domainChoice !== '' ? ' WHERE name=?' : '') . ' ORDER BY name,id LIMIT 26',
            $filter->domainChoice !== '' ? [$filter->domainChoice] : [])->fetchAll(PDO::FETCH_ASSOC);
        $users = $run('SELECT u.id,u.email,u.active FROM mailserver.virtual_users u '
            . 'JOIN mailserver.virtual_domains d ON d.id=u.domain_id WHERE u.active=1 AND d.active=1'
            . ($filter->destinationChoice !== '' ? ' AND u.email=?' : '') . ' ORDER BY u.email,u.id LIMIT 26',
            $filter->destinationChoice !== '' ? [$filter->destinationChoice] : [])->fetchAll(PDO::FETCH_ASSOC);
        return ['rows'=>$rows, 'pagination'=>$window, 'choices'=>[
            'domains'=>['rows'=>array_slice($domains, 0, 25), 'truncated'=>count($domains)>25],
            'users'=>['rows'=>array_slice($users, 0, 25), 'truncated'=>count($users)>25],
        ]];
    }
}
