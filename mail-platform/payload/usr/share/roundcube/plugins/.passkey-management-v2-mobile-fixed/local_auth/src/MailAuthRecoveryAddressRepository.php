<?php

declare(strict_types=1);

namespace MailServer\RoundcubeAuthManagement;

use PDO;
use Throwable;

final class MailAuthRecoveryAddressRepository implements RecoveryAddressRepository
{
    private const CONFIG_PATH = '/etc/roundcube/account_recovery.inc.php';

    public function verifiedAddress(string $account): string
    {
        $account = self::validatedAddress($account, 'Account identity is invalid.');

        try {
            $config = require self::CONFIG_PATH;
            if (!is_array($config)) {
                throw new ManagementException('Recovery notification is unavailable.', 'storage');
            }
            foreach (['db_dsn', 'db_user', 'db_pass'] as $key) {
                if (!isset($config[$key]) || !is_string($config[$key]) || $config[$key] === '') {
                    throw new ManagementException('Recovery notification is unavailable.', 'storage');
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
            $statement = $pdo->prepare(
                'SELECT `recovery_email` FROM `account_recovery`'
                    . ' WHERE `email` = ? AND `recovery_email` IS NOT NULL'
                    . ' AND `verified_at` IS NOT NULL LIMIT 1'
            );
            $statement->execute([$account]);
            $row = $statement->fetch();
            $address = is_array($row) ? ($row['recovery_email'] ?? null) : null;
            if (!is_string($address)) {
                throw new ManagementException('Verified recovery address is unavailable.', 'storage');
            }
            return self::validatedAddress($address, 'Verified recovery address is invalid.');
        } catch (Throwable $e) {
            if ($e instanceof ManagementException) {
                throw $e;
            }
            throw new ManagementException('Recovery notification lookup failed.', 'storage');
        }
    }

    private static function validatedAddress(string $value, string $failure): string
    {
        $value = trim($value);
        if (strlen($value) < 3
            || strlen($value) > 320
            || strpbrk($value, "\r\n") !== false
            || filter_var($value, FILTER_VALIDATE_EMAIL) === false
        ) {
            throw new ManagementException($failure, 'storage');
        }
        return $value;
    }
}
