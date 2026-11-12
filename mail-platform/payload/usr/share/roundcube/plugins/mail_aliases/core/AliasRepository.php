<?php

declare(strict_types=1);

namespace MailServer\Management;

use PDO;
use Throwable;

/** PDO default DB is mail_management; actor email comes from the session, never POST. */
final class AliasRepository
{
    public const DEFAULT_ALIAS_LIMIT = 1;

    /** Missing policy uses the default; an explicit zero remains a prohibition. */
    public static function effectiveAliasLimit(false|int|string $stored): int
    {
        return $stored === false ? self::DEFAULT_ALIAS_LIMIT : (int) $stored;
    }

    public function __construct(private readonly PDO $db)
    {
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $db->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
    }

    public function listOwned(string $authenticatedMailbox): array
    {
        try {
            $account = $this->account($authenticatedMailbox, false);
            $query = $this->db->prepare(
                'SELECT m.virtual_alias_id AS id,m.source,v.active FROM mail_owned_aliases m '
                . 'JOIN mailserver.virtual_aliases v ON v.id=m.virtual_alias_id '
                . 'WHERE m.user_id=? AND m.domain_id=? AND v.domain_id=m.domain_id '
                . 'AND v.source=m.source AND v.destination=? ORDER BY m.source'
            );
            $query->execute([$account['id'], $account['domain_id'], $account['email']]);
            $rows = $query->fetchAll(PDO::FETCH_ASSOC);
            foreach ($rows as &$row) {
                $row['id'] = (string) $row['id']; // Never round BIGINT through a JavaScript number.
                $row['active'] = (int) $row['active'] === 1;
            }
            unset($row);
            return $rows;
        } catch (\DomainException $error) {
            throw $error;
        } catch (Throwable $ignored) {
            throw new \DomainException('read_unavailable');
        }
    }

    /** Display the same ownership count/default limit used by create, including disabled reservations. */
    public function aliasUsage(string $authenticatedMailbox): array
    {
        try {
            $account = $this->account($authenticatedMailbox, false);
            $settings = $this->db->prepare('SELECT alias_limit FROM mail_user_settings WHERE user_id=?');
            $settings->execute([$account['id']]);
            $limit = self::effectiveAliasLimit($settings->fetchColumn());
            $count = $this->db->prepare('SELECT COUNT(*) FROM mail_owned_aliases WHERE user_id=?');
            $count->execute([$account['id']]);
            return ['count' => (int) $count->fetchColumn(), 'limit' => $limit];
        } catch (\DomainException $error) {
            throw $error;
        } catch (Throwable $ignored) {
            throw new \DomainException('read_unavailable');
        }
    }

    /** No row means both optional receiving variants are OFF. Identity is session-derived. */
    public function addressPreferences(string $authenticatedMailbox): array
    {
        try {
            $account = $this->account($authenticatedMailbox, false);
            $query = $this->db->prepare('SELECT ignore_dots,allow_plus FROM mail_address_preferences WHERE user_id=?');
            $query->execute([$account['id']]);
            $row = $query->fetch(PDO::FETCH_ASSOC);
            return ['ignore_dots' => $row !== false && (int) $row['ignore_dots'] === 1,
                'allow_plus' => $row !== false && (int) $row['allow_plus'] === 1];
        } catch (\DomainException $error) {
            throw $error;
        } catch (Throwable $ignored) {
            // A failed read is not a saved OFF value.
            throw new \DomainException('read_unavailable');
        }
    }

    public function saveAddressPreferences(string $authenticatedMailbox, bool $ignoreDots, bool $allowPlus): void
    {
        $this->mutate(function () use ($authenticatedMailbox, $ignoreDots, $allowPlus): void {
            $account = $this->account($authenticatedMailbox, true);
            // The namespace/account locks serialize creation; user_id is never updated.
            $exists = $this->db->prepare('SELECT user_id FROM mail_address_preferences WHERE user_id=?');
            $exists->execute([$account['id']]);
            if ($exists->fetchColumn() === false) {
                $query = $this->db->prepare('INSERT INTO mail_address_preferences(user_id,ignore_dots,allow_plus) VALUES(?,?,?)');
                $query->execute([$account['id'], (int) $ignoreDots, (int) $allowPlus]);
            } else {
                $query = $this->db->prepare('UPDATE mail_address_preferences SET ignore_dots=?,allow_plus=? WHERE user_id=?');
                $query->execute([(int) $ignoreDots, (int) $allowPlus, $account['id']]);
            }
        });
    }

    public function create(string $authenticatedMailbox, string $localPart): string
    {
        return $this->mutate(function () use ($authenticatedMailbox, $localPart): string {
            $account = $this->account($authenticatedMailbox, true);
            $settings = $this->db->prepare('SELECT alias_limit FROM mail_user_settings WHERE user_id=? FOR UPDATE');
            $settings->execute([$account['id']]);
            $limit = $settings->fetchColumn();
            $count = $this->db->prepare('SELECT COUNT(*) FROM mail_owned_aliases WHERE user_id=?');
            $count->execute([$account['id']]);
            $address = AliasPolicy::newAddress(
                $localPart, $account['domain_name'], self::effectiveAliasLimit($limit),
                (int) $count->fetchColumn(), true,
            );
            if (!$this->available($address, $account['domain_id'])) {
                throw new \DomainException('alias_unavailable');
            }
            $insert = $this->db->prepare(
                'INSERT INTO mailserver.virtual_aliases(domain_id,source,destination,active) VALUES(?,?,?,1)'
            );
            $insert->execute([$account['domain_id'], $address, $account['email']]);
            $id = $this->db->lastInsertId(); // Preserve unsigned BIGINT as a decimal string.
            $owner = $this->db->prepare(
                'INSERT INTO mail_owned_aliases(virtual_alias_id,user_id,domain_id,source) VALUES(?,?,?,?)'
            );
            $owner->execute([$id, $account['id'], $account['domain_id'], $address]);
            return $id;
        });
    }

    public function setEnabled(string $authenticatedMailbox, string $aliasId, bool $enabled): void
    {
        $this->mutate(function () use ($authenticatedMailbox, $aliasId, $enabled): void {
            $account = $this->account($authenticatedMailbox, true);
            $this->owned($account, $aliasId);
            $query = $this->db->prepare('UPDATE mailserver.virtual_aliases SET active=? WHERE id=?');
            $query->execute([$enabled ? 1 : 0, $aliasId]);
        });
    }

    /** Removes only the receiving route/ownership, never stored mail or mailbox data. */
    public function remove(string $authenticatedMailbox, string $aliasId): void
    {
        $this->mutate(function () use ($authenticatedMailbox, $aliasId): void {
            $account = $this->account($authenticatedMailbox, true);
            $this->owned($account, $aliasId);
            $owner = $this->db->prepare('DELETE FROM mail_owned_aliases WHERE virtual_alias_id=? AND user_id=?');
            $owner->execute([$aliasId, $account['id']]);
            if ($owner->rowCount() !== 1) { throw new \DomainException('alias_binding'); }
            $route = $this->db->prepare('DELETE FROM mailserver.virtual_aliases WHERE id=?');
            $route->execute([$aliasId]);
            if ($route->rowCount() !== 1) { throw new \DomainException('alias_binding'); }
        });
    }

    private function account(string $mailbox, bool $locked): array
    {
        $login = explode('@', $mailbox);
        if (count($login) !== 2 || $login[0] === '' || $login[1] === '') {
            throw new \DomainException('not_authorized');
        }
        $query = $this->db->prepare(
            'SELECT u.id,u.domain_id,u.email,d.name AS domain_name FROM mailserver.virtual_users u '
            . 'JOIN mailserver.virtual_domains d ON d.id=u.domain_id '
            . 'WHERE u.active=1 AND d.active=1 AND (u.email=? OR '
            . '(u.email=CONCAT(?,\'@\',d.name) AND EXISTS(SELECT 1 FROM mailserver.virtual_domain_aliases a '
            . 'WHERE a.alias_domain=? AND a.target_domain_id=d.id AND a.active=1)))'
            . ($locked ? ' FOR UPDATE' : '')
        );
        $query->execute([$mailbox, $login[0], $login[1]]);
        $rows = $query->fetchAll(PDO::FETCH_ASSOC);
        if (count($rows) !== 1) { throw new \DomainException('not_authorized'); }
        $account = $rows[0];
        $parts = explode('@', $account['email']);
        if (count($parts) !== 2 || strcasecmp($parts[1], $account['domain_name']) !== 0) {
            throw new \DomainException('account_binding');
        }
        return $account;
    }

    private function available(string $address, string|int $domainId): bool
    {
        [$localPart, $domain] = explode('@', $address, 2);
        $query = $this->db->prepare('SELECT alias_domain FROM mailserver.virtual_domain_aliases WHERE target_domain_id=?');
        $query->execute([$domainId]);
        $domains = array_unique([$domain, ...$query->fetchAll(PDO::FETCH_COLUMN)]);
        $addresses = [];
        $sources = [$localPart];
        foreach ($domains as $name) {
            $addresses[] = $localPart . '@' . $name;
            $sources[] = $localPart . '@' . $name;
            $sources[] = '@' . $name;
        }
        foreach ([['mailserver.virtual_users', 'email', $addresses], ['mailserver.virtual_aliases', 'source', $sources]] as [$table, $column, $values]) {
            // Table/column names are fixed literals above; only values become placeholders.
            $placeholders = implode(',', array_fill(0, count($values), '?'));
            $key = AliasPolicy::namespaceSql($column);
            $check = $this->db->prepare("SELECT 1 FROM $table WHERE ($key) IN ($placeholders) LIMIT 1");
            $check->execute($values);
            if ($check->fetchColumn() !== false) { return false; }
        }
        $key = AliasPolicy::namespaceSql('source');
        $registry = $this->db->prepare("SELECT 1 FROM mail_owned_aliases WHERE ($key) IN ("
            . implode(',', array_fill(0, count($addresses), '?')) . ') LIMIT 1');
        $registry->execute($addresses);
        return $registry->fetchColumn() === false;
    }

    private function owned(array $account, string $aliasId): void
    {
        if (!preg_match('/\A[1-9][0-9]{0,19}\z/D', $aliasId)) {
            throw new \DomainException('not_authorized');
        }
        $query = $this->db->prepare(
            'SELECT m.user_id,m.domain_id,m.source,v.domain_id AS route_domain,v.source AS route_source,'
            . 'v.destination FROM mail_owned_aliases m JOIN mailserver.virtual_aliases v ON v.id=m.virtual_alias_id '
            . 'WHERE m.virtual_alias_id=? FOR UPDATE'
        );
        $query->execute([$aliasId]);
        $row = $query->fetch(PDO::FETCH_ASSOC);
        if (!$row) { throw new \DomainException('not_authorized'); }
        AliasPolicy::requireOwner((string) $account['id'], (string) $row['user_id']);
        if ((string) $row['domain_id'] !== (string) $account['domain_id']
            || (string) $row['route_domain'] !== (string) $account['domain_id']
            || $row['source'] !== $row['route_source'] || $row['destination'] !== $account['email']
            || AliasPolicy::isReserved(explode('@', $row['source'], 2)[0])) {
            throw new \DomainException('alias_binding');
        }
    }

    private function mutate(callable $action): mixed
    {
        if ($this->db->inTransaction()) { throw new \DomainException('nested_transaction'); }
        try {
            if (!$this->db->beginTransaction()) { throw new \DomainException('result_unverified'); }
            $lock = $this->db->query("SELECT name FROM mail_management_locks WHERE name='alias_namespace' FOR UPDATE");
            if ($lock->fetchColumn() !== 'alias_namespace') { throw new \DomainException('schema_not_ready'); }
            $result = $action();
            if (!$this->db->commit()) { throw new \DomainException('result_unverified'); }
            return $result;
        } catch (Throwable $error) {
            try {
                if ($this->db->inTransaction()) { $this->db->rollBack(); }
            } catch (Throwable $ignored) {
                throw new \DomainException('result_unverified');
            }
            // No raw PDO exception, account data or connection credentials in the UI/log.
            if ($error instanceof \DomainException) { throw $error; }
            throw new \DomainException('result_unverified');
        }
    }
}
