<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

use PDO;
use Throwable;

final class MailAuthSessionEpochInvalidator implements SessionEpochInvalidator
{
    private const CONFIG_PATH = '/etc/roundcube/account_recovery.inc.php';

    public function bump(string $username): int
    {
        $username = strtolower(trim($username));
        if (strlen($username) < 3
            || strlen($username) > 320
            || filter_var($username, FILTER_VALIDATE_EMAIL) === false
        ) {
            throw new ManagementException('Account identity is invalid.', 'authentication');
        }

        $pdo = null;
        try {
            $config = require self::CONFIG_PATH;
            if (!is_array($config)) {
                throw new ManagementException('Session invalidation is unavailable.', 'storage');
            }
            foreach (['db_dsn', 'db_user', 'db_pass'] as $key) {
                if (!isset($config[$key]) || !is_string($config[$key]) || $config[$key] === '') {
                    throw new ManagementException('Session invalidation is unavailable.', 'storage');
                }
            }
            $pdo = new PDO(
                $config['db_dsn'],
                $config['db_user'],
                $config['db_pass'],
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_EMULATE_PREPARES => false,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                ],
            );
            unset($config);
            $pdo->beginTransaction();
            $select = $pdo->prepare(
                'SELECT `auth_epoch` FROM `virtual_users`'
                    . ' WHERE `email` = ? AND `active` = 1 LIMIT 1 FOR UPDATE'
            );
            $select->execute([$username]);
            $row = $select->fetch();
            $current = is_array($row) ? ($row['auth_epoch'] ?? null) : null;
            if (preg_match('/\A[0-9]{1,18}\z/D', (string) $current) !== 1) {
                throw new ManagementException('Session epoch is invalid.', 'storage');
            }
            $next = (int) $current + 1;
            if ($next <= 0) {
                throw new ManagementException('Session epoch is exhausted.', 'storage');
            }
            $update = $pdo->prepare(
                'UPDATE `virtual_users` SET `auth_epoch` = ?'
                    . ' WHERE `email` = ? AND `active` = 1 AND `auth_epoch` = ?'
            );
            $update->execute([$next, $username, $current]);
            if ($update->rowCount() !== 1 || !$pdo->commit()) {
                throw new ManagementException('Session invalidation failed.', 'storage');
            }
            return $next;
        } catch (Throwable $e) {
            if ($pdo instanceof PDO && $pdo->inTransaction()) {
                $pdo->rollBack();
            }
            if ($e instanceof ManagementException) {
                throw $e;
            }
            throw new ManagementException('Session invalidation failed.', 'storage');
        }
    }
}
