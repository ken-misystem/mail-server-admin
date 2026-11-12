<?php

declare(strict_types=1);

namespace MailServer\Management;

use PDO;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;

/** Read-only authentication adapter. PDO connects to the separate management DB. */
final class PdoAdminDirectory implements AdminDirectory
{
    public function __construct(private readonly PDO $db)
    {
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $db->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
    }

    public function byEmail(string $email): ?AdminUser
    {
        try { $email = AdminPolicy::identity($email); }
        catch (\DomainException) { return null; }
        return $this->lookup('email', $email);
    }

    public function byId(string $id): ?AdminUser
    {
        if (!preg_match('/^[1-9][0-9]{0,19}$/D', $id)) { return null; }
        return $this->lookup('id', $id);
    }

    private function lookup(string $column, string $value): ?AdminUser
    {
        try {
            // $column is selected only by the two fixed methods, never request input.
            $query = $this->db->prepare('SELECT id,email,password_hash,active,is_system_admin,auth_epoch '
                . 'FROM mail_admin_users WHERE ' . $column . '=? LIMIT 2');
            $query->execute([$value]);
            $rows = $query->fetchAll(PDO::FETCH_ASSOC);
            if (count($rows) === 0) { return null; }
            if (count($rows) !== 1 || !in_array((string) $rows[0]['active'], ['0', '1'], true)
                || !in_array((string) $rows[0]['is_system_admin'], ['0', '1'], true)) {
                throw new \DomainException('invalid_admin_record');
            }
            $row = $rows[0];
            return new AdminUser((string) $row['id'], $row['email'], $row['password_hash'],
                (string) $row['active'] === '1', (string) $row['is_system_admin'] === '1',
                (string) $row['auth_epoch']);
        } catch (\Throwable) {
            // Do not chain/log raw PDO errors, SQL, DSNs, hashes or credentials.
            throw new AuthenticationServiceException('admin_auth_unavailable');
        }
    }
}
